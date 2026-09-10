package windows

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/windows/protocol"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestWindowsGatewayIdentityRequiresPinnedTLSAndCanonicalCertificate(t *testing.T) {
	root, leaf, _ := managementTestCertificates(t)
	gateway, policy := protocolTestGatewayIdentity(t)
	other, _ := protocolTestGatewayIdentity(t)
	options := enrollmentTestOptions()
	request := func() *http.Request {
		r := managementTestRequest(t, gateway.Certificate[0], options)
		r.Header.Set("Client-Cert", ":"+base64.StdEncoding.EncodeToString(leaf.Raw)+":")
		return r
	}
	r := request()
	got, err := managementPeerCertificateWithIdentity(r, options, policy)
	if err != nil || !bytes.Equal(got.Raw, leaf.Raw) || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, gateway.Certificate[0]) {
		t.Fatal("gateway identity was not resolved independently of TLS peer")
	}
	got, err = managementPeerCertificateWithIdentity(r, options, clientidentity.Policy{})
	if err != nil || !bytes.Equal(got.Raw, gateway.Certificate[0]) {
		t.Fatal("direct mode trusted forwarded certificate")
	}
	for name, mutate := range map[string]func(*http.Request){
		"untrusted TLS":  func(r *http.Request) { r.TLS.PeerCertificates[0] = other.Leaf },
		"no TLS":         func(r *http.Request) { r.TLS = nil },
		"incomplete TLS": func(r *http.Request) { r.TLS.HandshakeComplete = false },
		"old TLS":        func(r *http.Request) { r.TLS.Version = tls.VersionTLS11 },
		"no leaf":        func(r *http.Request) { r.TLS.PeerCertificates = nil },
		"absent header":  func(r *http.Request) { r.Header.Del("Client-Cert") },
		"alias only": func(r *http.Request) {
			r.Header.Set("X-SSL-Client-Cert", r.Header.Get("Client-Cert"))
			r.Header.Del("Client-Cert")
		},
		"duplicate":    func(r *http.Request) { r.Header.Add("Client-Cert", r.Header.Get("Client-Cert")) },
		"plain base64": func(r *http.Request) { r.Header.Set("Client-Cert", base64.StdEncoding.EncodeToString(leaf.Raw)) },
		"oversized":    func(r *http.Request) { r.Header.Set("Client-Cert", strings.Repeat("x", 25<<10)) },
		"invalid DER":  func(r *http.Request) { r.Header.Set("Client-Cert", ":YWJj:") },
		"CA": func(r *http.Request) {
			r.Header.Set("Client-Cert", ":"+base64.StdEncoding.EncodeToString(root.Raw)+":")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := request()
			mutate(r)
			if _, err := managementPeerCertificateWithIdentity(r, options, policy); err == nil {
				t.Fatal("untrusted forwarded identity admitted")
			}
		})
	}
	h, err := NewProtocolHandler(policyClosedStore(t), protocolTestOptions("https://uem.example.test"), policy)
	if err != nil {
		t.Fatal(err)
	}
	server := h.Server("127.0.0.1:0")
	if server.TLSConfig.ClientAuth != tls.RequireAnyClientCert || server.TLSConfig.VerifyConnection == nil {
		t.Fatal("private listener did not enforce pinned gateway TLS")
	}
	for _, path := range []string{protocol.DiscoveryPath, protocol.PolicyPath, protocol.EnrollmentPath, protocol.ManagementPath} {
		r := httptest.NewRequest("POST", "https://uem.example.test"+path, nil)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{other.Leaf}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0" {
			t.Fatal("private endpoint bypassed gateway guard", path)
		}
	}
}
