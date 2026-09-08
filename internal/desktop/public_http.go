package desktop

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"golang.org/x/time/rate"
)

const maxClaimBody = 16 << 10

// PublicHandler exposes only read-only installation metadata, approved packages
// and endpoint key-proof claims. It contains no console authentication or routes.
type PublicHandler struct {
	store                       *Store
	catalog                     *Catalog
	origin, host                string
	identity                    clientidentity.Policy
	claims, downloads, metadata chan struct{}
	mu                          sync.Mutex
	clients                     map[netip.Addr]publicBucket
	global                      *rate.Limiter
	closed                      bool
	requests                    sync.WaitGroup
	lifetime                    context.Context
	cancel                      context.CancelFunc
}

type publicBucket struct {
	limiter *rate.Limiter
	last    time.Time
}

func NewPublicHandler(store *Store, catalog *Catalog, publicOrigin string, identity clientidentity.Policy) (*PublicHandler, error) {
	if store == nil || catalog == nil || catalog.db != store.db || !canonicalEnrollmentOrigin(publicOrigin) {
		return nil, errors.New("desktop enrollment requires a store, approved catalog and canonical HTTPS origin")
	}
	u, _ := gateway.ParseOrigin(publicOrigin)
	lifetime, cancel := context.WithCancel(context.Background())
	return &PublicHandler{store: store, catalog: catalog, origin: publicOrigin, host: u.Host, identity: identity,
		claims: make(chan struct{}, 4), downloads: make(chan struct{}, 8), metadata: make(chan struct{}, 32),
		clients: make(map[netip.Addr]publicBucket), global: rate.NewLimiter(100, 200), lifetime: lifetime, cancel: cancel}, nil
}

// Close stops admission, cancels requests and joins all handlers before their
// shared catalog/database can be closed. The owning server must also be closed.
func (h *PublicHandler) Close() {
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.requests.Wait()
}

// Server has bounded headers, bodies, idle connections and ordinary responses.
// Only an admitted package download extends its write deadline to 15 minutes.
func (h *PublicHandler) Server(address string) *http.Server {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	h.identity.ConfigureTLS(config)
	return &http.Server{Addr: address, Handler: h, TLSConfig: config,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10,
		// net/http panic and transport diagnostics may contain request data.
		ErrorLog: log.New(io.Discard, "", 0)}
}

func (h *PublicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	h.requests.Add(1)
	h.mu.Unlock()
	defer h.requests.Done()
	if h.identity.Enabled() && !h.identity.IsGateway(r) {
		http.Error(w, "trusted gateway required", http.StatusForbidden)
		return
	}
	if r.TLS == nil || !r.TLS.HandshakeComplete || !strings.EqualFold(r.Host, h.host) {
		http.Error(w, "invalid request origin", http.StatusBadRequest)
		return
	}
	route, ok := protocol.Parse(r)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// A native client has no Origin. Browser requests must be same-origin; the
	// claim additionally requires an explicit JSON body and both key proofs.
	if values := r.Header.Values("Origin"); len(values) > 1 || (len(values) == 1 && values[0] != h.origin) {
		http.Error(w, "request origin is not allowed", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "none" && site != "same-origin" {
		http.Error(w, "request origin is not allowed", http.StatusForbidden)
		return
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Content-Encoding") != "" || (route.Kind != "claim" && (r.ContentLength != 0 || len(r.TransferEncoding) != 0)) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !h.allow(r) {
		publicBusy(w)
		return
	}
	slots, timeout := h.metadata, 20*time.Second
	if route.Kind == "claim" {
		slots = h.claims
	} else if route.Kind == "download" {
		slots, timeout = h.downloads, protocol.DownloadTimeout
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		publicBusy(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	stop := context.AfterFunc(h.lifetime, cancel)
	defer stop()
	r = r.WithContext(ctx)
	if route.Kind == "download" {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		h.download(w, r, route)
		return
	}
	if route.Kind == "metadata" {
		metadata, err := h.store.InstallerMetadata(ctx, h.catalog, route.Token, h.origin)
		if err != nil {
			publicFailure(w, err)
			return
		}
		publicJSON(w, r, metadata)
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(r.Header.Values("Content-Type")) != 1 || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		http.Error(w, "an application/json request is required", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > maxClaimBody {
		http.Error(w, "request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxClaimBody))
	defer clear(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request is too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		}
		return
	}
	// The body is complete. HTTP/2 read deadlines are stream deadlines; keeping
	// this timer armed could reset a valid claim while it waits for its DB lock.
	if err = http.NewResponseController(w).SetReadDeadline(time.Time{}); err != nil {
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	request, err := decodeClaim(body)
	if err != nil || request.Invitation != route.Token {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	response, err := h.store.ClaimInstaller(ctx, h.catalog, request, h.origin)
	if err != nil {
		publicFailure(w, err)
		return
	}
	publicJSON(w, r, response)
}

func decodeClaim(body []byte) (enrollment.Request, error) {
	var result enrollment.Request
	if len(body) > maxClaimBody || !utf8.Valid(body) {
		return result, enrollment.ErrInvalidProof
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return result, enrollment.ErrInvalidProof
	}
	fields := map[string]any{"version": &result.Version, "invitation": &result.Invitation, "platform": &result.Platform, "architecture": &result.Architecture, "device_name": &result.DeviceName, "csr": &result.CSR, "broker_key": &result.BrokerKey, "proof": &result.Proof}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return result, enrollment.ErrInvalidProof
		}
		name, ok := key.(string)
		target := fields[name]
		if !ok || target == nil {
			return result, enrollment.ErrInvalidProof
		}
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return result, enrollment.ErrInvalidProof
		}
		if err = json.Unmarshal(raw, target); err != nil {
			return result, enrollment.ErrInvalidProof
		}
		delete(fields, name)
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(fields) != 0 {
		return result, enrollment.ErrInvalidProof
	}
	if _, err = d.Token(); err != io.EOF {
		return result, enrollment.ErrInvalidProof
	}
	return result, nil
}

func (h *PublicHandler) download(w http.ResponseWriter, r *http.Request, route protocol.Route) {
	// Accept at most one bounded byte range; multipart responses are unnecessary
	// for installer resume and can amplify a small public request.
	values := r.Header.Values("Range")
	if len(values) > 1 || (len(values) == 1 && (len(values[0]) > 96 || strings.Contains(values[0], ","))) {
		http.Error(w, "only one byte range is supported", http.StatusBadRequest)
		return
	}
	file, artifact, err := h.catalog.OpenPackage(r.Context(), route.Digest, route.Platform, route.Architecture)
	if err != nil {
		publicFailure(w, err)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+artifact.Filename+`"`)
	w.Header().Set("ETag", `"`+artifact.SHA256+`"`)
	// Preserve security headers on ServeContent errors as well as 200/206/304.
	http.ServeContent(securityHeaderWriter{w}, r, artifact.Filename, time.Time{}, contextReadSeeker{r.Context(), file})
}

type securityHeaderWriter struct{ http.ResponseWriter }

func (w securityHeaderWriter) WriteHeader(code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(code)
}

type contextReadSeeker struct {
	ctx context.Context
	io.ReadSeeker
}

func (r contextReadSeeker) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.ReadSeeker.Read(p)
}

func publicJSON(w http.ResponseWriter, r *http.Request, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func publicFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, enrollment.ErrInvalidProof) || errors.Is(err, registry.ErrInvalid) {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
	} else if errors.Is(err, registry.ErrNotFound) || errors.Is(err, registry.ErrDenied) || errors.Is(err, ErrNoRelease) || errors.Is(err, ErrWithdrawn) || errors.Is(err, artifacts.ErrExpired) || errors.Is(err, artifacts.ErrTarget) {
		http.Error(w, "installation is unavailable", http.StatusNotFound)
	} else {
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
	}
}

func publicBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	http.Error(w, "please retry later", http.StatusTooManyRequests)
}

func (h *PublicHandler) allow(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if h.identity.IsGateway(r) {
		values := r.Header.Values("X-Forwarded-For")
		if len(values) != 1 {
			return false
		}
		host = values[0]
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	if !h.global.Allow() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	bucket, exists := h.clients[ip]
	if !exists {
		if len(h.clients) >= 4096 {
			for key, value := range h.clients {
				if now.Sub(value.last) > 5*time.Minute {
					delete(h.clients, key)
				}
			}
			if len(h.clients) >= 4096 {
				return false
			}
		}
		bucket.limiter = rate.NewLimiter(2, 30)
	}
	bucket.last = now
	h.clients[ip] = bucket
	return bucket.limiter.Allow()
}
