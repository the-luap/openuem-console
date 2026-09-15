// Package clientidentity authenticates certificate forwarding across an explicit
// TLS gateway boundary. A certificate header alone is never a credential.
package clientidentity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

const GatewayCertificatesEnv = "OPENUEM_TRUSTED_GATEWAY_CERTIFICATES"

var ErrUnauthorized = errors.New("client certificate identity is not authorized")

// Policy pins gateway leaf certificates, not a CA that could issue device or
// administrator certificates. Its zero value supports direct TLS only.
type Policy struct {
	gateways map[[32]byte]struct{}
}

// FromEnvironment loads a PEM bundle of explicitly trusted gateway certificates.
// An invalid configured bundle fails startup instead of reverting to direct mode.
func FromEnvironment() (Policy, error) {
	path := os.Getenv(GatewayCertificatesEnv)
	if path == "" {
		return Policy{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return FromPEM(data)
}

func FromPEM(data []byte) (Policy, error) {
	p := Policy{gateways: make(map[[32]byte]struct{})}
	for len(strings.TrimSpace(string(data))) > 0 {
		// Reject ignored prefixes and private keys in a trust bundle.
		data = []byte(strings.TrimSpace(string(data)))
		if !strings.HasPrefix(string(data), "-----BEGIN CERTIFICATE-----") {
			return Policy{}, errors.New("gateway trust must contain only PEM certificates")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return Policy{}, errors.New("invalid gateway certificate bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.IsCA || !validClientCertificate(cert, time.Now()) {
			return Policy{}, errors.New("gateway trust requires currently valid client-auth leaf certificates")
		}
		p.gateways[sha256.Sum256(cert.Raw)] = struct{}{}
		data = rest
	}
	if len(p.gateways) == 0 {
		return Policy{}, errors.New("gateway certificate bundle is empty")
	}
	return p, nil
}

func validClientCertificate(cert *x509.Certificate, now time.Time) bool {
	if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func (p Policy) Enabled() bool { return len(p.gateways) > 0 }

// IsGateway requires TLS proof of possession and an exact, unexpired leaf pin.
func (p Policy) IsGateway(r *http.Request) bool {
	if r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cert := r.TLS.PeerCertificates[0]
	if !validClientCertificate(cert, time.Now()) {
		return false
	}
	_, ok := p.gateways[sha256.Sum256(cert.Raw)]
	return ok
}

// Certificate returns the TLS-authenticated end-client leaf. Callers still must
// validate its issuer, account/device binding, validity and revocation status.
func (p Policy) Certificate(r *http.Request) (*x509.Certificate, error) {
	if p.Enabled() {
		if !p.IsGateway(r) {
			return nil, ErrUnauthorized
		}
		values := r.Header.Values("Client-Cert")
		if len(values) != 1 || len(values[0]) > 24<<10 {
			return nil, ErrUnauthorized
		}
		value := values[0]
		if len(value) < 3 || value[0] != ':' || value[len(value)-1] != ':' {
			return nil, ErrUnauthorized
		}
		encoded := value[1 : len(value)-1]
		der, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(der) != encoded {
			return nil, ErrUnauthorized
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrUnauthorized
		}
		return cert, nil
	}
	if r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrUnauthorized
	}
	return r.TLS.PeerCertificates[0], nil
}

// Protect rejects every direct backend request when a gateway is configured,
// including enrollment and administrator pages that need no client identity.
func (p Policy) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Enabled() && !p.IsGateway(r) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "trusted gateway required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ConfigureTLS preserves direct mode and rejects untrusted gateway connections
// during the handshake in addition to the per-request check (including expiry).
func (p Policy) ConfigureTLS(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
	if !p.Enabled() {
		return
	}
	config.ClientAuth = tls.RequireAnyClientCert
	config.ClientCAs = nil
	config.VerifyConnection = func(state tls.ConnectionState) error {
		state.HandshakeComplete = true // VerifyConnection runs before completion.
		if !p.IsGateway(&http.Request{TLS: &state}) {
			return ErrUnauthorized
		}
		return nil
	}
}

// Forward removes untrusted identity aliases before adding the TLS peer leaf in
// RFC 9440 format. The caller must send this request over authenticated backend TLS.
func Forward(out, in *http.Request) {
	for key := range out.Header {
		lower := strings.ToLower(key)
		if lower == "client-cert" || lower == "client-cert-chain" || strings.HasPrefix(lower, "x-client-cert") || strings.HasPrefix(lower, "x-ssl-client") || strings.HasPrefix(lower, "ssl-client") || strings.HasPrefix(lower, "x-forwarded-client-cert") {
			delete(out.Header, key)
		}
	}
	if in.TLS != nil && in.TLS.HandshakeComplete && len(in.TLS.PeerCertificates) > 0 {
		out.Header.Set("Client-Cert", ":"+base64.StdEncoding.EncodeToString(in.TLS.PeerCertificates[0].Raw)+":")
	}
}
