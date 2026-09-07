// Package gateway exposes explicitly implemented device routes while restricting
// all administrator routes to configured source networks on the same HTTPS port.
package gateway

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

type Config struct {
	PublicOrigin  string
	AppleURL      string
	ConsoleURL    string
	AuthURL       string
	AdminNetworks []netip.Prefix
	BackendTLS    *tls.Config
}

func ParseOrigin(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("an HTTPS origin without credentials, path, query or fragment is required")
	}
	u.Path = ""
	return u, nil
}

func New(config Config) (http.Handler, error) {
	origin, err := ParseOrigin(config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if config.BackendTLS == nil || config.BackendTLS.InsecureSkipVerify || len(config.BackendTLS.Certificates) == 0 || config.BackendTLS.RootCAs == nil {
		return nil, errors.New("backend TLS requires a gateway identity and trusted server roots")
	}
	if len(config.AdminNetworks) == 0 {
		return nil, errors.New("at least one explicit administrator source network is required")
	}
	networks := append([]netip.Prefix(nil), config.AdminNetworks...)
	for _, prefix := range networks {
		if !prefix.IsValid() || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return nil, errors.New("administrator networks must be explicit IPv4 or IPv6 prefixes, not the entire Internet")
		}
	}
	proxies := make([]http.Handler, 3)
	for i, address := range []string{config.AppleURL, config.ConsoleURL, config.AuthURL} {
		upstream, err := ParseOrigin(address)
		if err != nil {
			return nil, err
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// Never route a private backend or gateway credentials through an
		// environment-provided outbound HTTP proxy.
		transport.Proxy = nil
		transport.TLSClientConfig = config.BackendTLS.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		transport.ResponseHeaderTimeout = 45 * time.Second
		proxies[i] = &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(upstream)
				r.Out.Host = origin.Host
				for key := range r.Out.Header {
					lower := strings.ToLower(key)
					if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") {
						delete(r.Out.Header, key)
					}
				}
				r.SetXForwarded()
				r.Out.Header.Set("X-Forwarded-Host", origin.Host)
				r.Out.Header.Set("X-Forwarded-Proto", "https")
				clientidentity.Forward(r.Out, r.In)
			},
			// Transport errors may contain enrollment URLs or other secrets.
			ErrorLog: log.New(io.Discard, "", 0),
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "service temporarily unavailable", http.StatusBadGateway)
			},
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Omit URL paths/tokens while preserving Origin on native form POSTs.
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.TLS == nil || !r.TLS.HandshakeComplete || !strings.EqualFold(r.Host, origin.Host) || !canonicalPath(r.URL) {
			http.Error(w, "invalid request origin or path", http.StatusBadRequest)
			return
		}
		if appleDeviceRoute(r) {
			proxies[0].ServeHTTP(w, r)
			return
		}
		if !allowedAdmin(r.RemoteAddr, networks) {
			http.Error(w, "administrator access requires an approved network", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/auth" {
			proxies[2].ServeHTTP(w, r)
		} else {
			proxies[1].ServeHTTP(w, r)
		}
	}), nil
}

func canonicalPath(u *url.URL) bool {
	if u.RawPath != "" || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(u.Path, "\\\x00\r\n") || strings.Contains(u.Path, "//") {
		return false
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func appleDeviceRoute(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "mdm" || parts[2] != "apple" {
		return false
	}
	if parts[3] == "enroll" && (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodPost) {
		if len(parts[4]) != 43 {
			return false
		}
		for _, ch := range parts[4] {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return false
			}
		}
		return true
	}
	if r.Method != http.MethodPut || (parts[4] != "checkin" && parts[4] != "connect") {
		return false
	}
	id, err := uuid.Parse(parts[3])
	return err == nil && id.String() == parts[3]
}

func allowedAdmin(remote string, networks []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range networks {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
