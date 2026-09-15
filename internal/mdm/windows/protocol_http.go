package windows

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/windows/protocol"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

const protocolRequestLimit = 32

// ProtocolOptions describes immutable enrollment identity configuration. A
// change after enrollment requires an explicit device migration, because issued
// devices are cryptographically bound to their original EnrollmentOptions.
type ProtocolOptions struct {
	PublicOrigin string
	ProviderID   string
	DisplayName  string
}

func (o ProtocolOptions) EnrollmentOptions() (EnrollmentOptions, error) {
	u, err := url.Parse(o.PublicOrigin)
	if err != nil || (o.PublicOrigin != "https://"+u.Host && o.PublicOrigin != "https://"+u.Host+"/") {
		return EnrollmentOptions{}, ErrEndpoint
	}
	u.Path = protocol.ManagementPath
	// Do not silently normalize credentials, queries, fragments or escaped paths.
	if _, err := enrollmentEndpoint(u.String()); err != nil {
		return EnrollmentOptions{}, err
	}
	options := EnrollmentOptions{ManagementURL: u.String(), ProviderID: o.ProviderID, DisplayName: o.DisplayName}
	if err := options.validate(); err != nil {
		return EnrollmentOptions{}, err
	}
	return options, nil
}

// ProtocolHandler owns bounded admission and trusted transport for all four
// native Windows endpoints. Credential, device and CSP authorization remain in
// their individual database transactions.
type ProtocolHandler struct {
	options  ProtocolOptions
	identity clientidentity.Policy
	routes   map[string]http.Handler
	slots    chan struct{}
}

func NewProtocolHandler(store *Store, options ProtocolOptions, identity clientidentity.Policy) (*ProtocolHandler, error) {
	enrollment, err := options.EnrollmentOptions()
	if err != nil {
		return nil, err
	}
	u, _ := enrollmentEndpoint(enrollment.ManagementURL)
	u.Path = ""
	origin := u.String()
	discovery, err := NewDiscoveryHandler(origin+protocol.DiscoveryPath, DiscoveryOptions{AuthPolicy: "OnPremise", EnrollmentVersion: 3, EnrollmentPolicyURL: origin + protocol.PolicyPath, EnrollmentURL: origin + protocol.EnrollmentPath})
	if err != nil {
		return nil, err
	}
	policy, err := NewPolicyHandler(store, origin+protocol.PolicyPath)
	if err != nil {
		return nil, err
	}
	wstep, err := newWSTEPHandlerWithIdentity(store, origin+protocol.EnrollmentPath, enrollment, identity)
	if err != nil {
		return nil, err
	}
	syncml, err := newSyncMLHandlerWithIdentity(store, enrollment, identity)
	if err != nil {
		return nil, err
	}
	options.PublicOrigin = origin
	return &ProtocolHandler{options: options, identity: identity, slots: make(chan struct{}, protocolRequestLimit), routes: map[string]http.Handler{
		protocol.DiscoveryPath: discovery, protocol.PolicyPath: policy, protocol.EnrollmentPath: wstep, protocol.ManagementPath: syncml,
	}}, nil
}

func (h *ProtocolHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.TLS == nil || !r.TLS.HandshakeComplete || (r.TLS.Version != tls.VersionTLS12 && r.TLS.Version != tls.VersionTLS13) {
		writeEnrollmentHTTP(w, r, http.StatusBadRequest, "", nil)
		return
	}
	if h.identity.Enabled() && !h.identity.IsGateway(r) {
		writeEnrollmentHTTP(w, r, http.StatusForbidden, "", nil)
		return
	}
	path := protocol.Path(r)
	if path == "" || !sameEnrollmentEndpoint("https://"+r.Host+path, h.options.PublicOrigin+path) {
		writeEnrollmentHTTP(w, r, http.StatusNotFound, "", nil)
		return
	}
	if !protocol.Public(r) {
		allow := "POST"
		if path == protocol.DiscoveryPath {
			allow = "GET, HEAD, POST"
		}
		w.Header().Set("Allow", allow)
		writeEnrollmentHTTP(w, r, http.StatusMethodNotAllowed, "", nil)
		return
	}
	if r.Context().Err() != nil {
		writeEnrollmentHTTP(w, r, http.StatusServiceUnavailable, "", nil)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "5")
		writeEnrollmentHTTP(w, r, http.StatusTooManyRequests, "", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	h.routes[path].ServeHTTP(w, r.WithContext(ctx))
}

func (h *ProtocolHandler) Server(address string) *http.Server {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	h.identity.ConfigureTLS(config)
	return &http.Server{Addr: address, Handler: h, TLSConfig: config,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 45 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10,
		// TLS/parser errors can contain peer-controlled material. Operational
		// listener failures are reported by the lifecycle owner without raw data.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}
