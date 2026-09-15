package clientidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCertificate(t *testing.T, name string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestIdentityRequiresAnAuthenticatedHop(t *testing.T) {
	gateway, bundle := testCertificate(t, "gateway")
	device, _ := testCertificate(t, "device")
	other, _ := testCertificate(t, "untrusted gateway")
	policy, err := FromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	header := ":" + base64.StdEncoding.EncodeToString(device.Leaf.Raw) + ":"
	tests := []struct {
		name     string
		policy   Policy
		peer     *x509.Certificate
		complete bool
		header   []string
		want     string
	}{
		{name: "plain HTTP replay", policy: policy, header: []string{header}},
		{name: "untrusted gateway replay", policy: policy, peer: other.Leaf, complete: true, header: []string{header}},
		{name: "direct device bypass", policy: policy, peer: device.Leaf, complete: true, header: []string{header}},
		{name: "unfinished TLS handshake", policy: policy, peer: gateway.Leaf, header: []string{header}},
		{name: "valid gateway", policy: policy, peer: gateway.Leaf, complete: true, header: []string{header}, want: "device"},
		{name: "gateway without client", policy: policy, peer: gateway.Leaf, complete: true},
		{name: "duplicate header", policy: policy, peer: gateway.Leaf, complete: true, header: []string{header, header}},
		{name: "list header", policy: policy, peer: gateway.Leaf, complete: true, header: []string{header + "," + header}},
		{name: "oversized header", policy: policy, peer: gateway.Leaf, complete: true, header: []string{strings.Repeat("A", 25<<10)}},
		{name: "invalid DER", policy: policy, peer: gateway.Leaf, complete: true, header: []string{":YWJj:"}},
		{name: "missing delimiters", policy: policy, peer: gateway.Leaf, complete: true, header: []string{strings.Trim(header, ":")}},
		{name: "direct TLS ignores forged identity", peer: device.Leaf, complete: true, header: []string{":" + base64.StdEncoding.EncodeToString(other.Leaf.Raw) + ":"}, want: "device"},
		{name: "direct HTTP cannot use header", header: []string{header}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "https://example.test/device", nil)
			r.TLS = nil
			if tt.peer != nil {
				r.TLS = &tls.ConnectionState{HandshakeComplete: tt.complete, PeerCertificates: []*x509.Certificate{tt.peer}}
			}
			r.Header["Client-Cert"] = tt.header
			cert, err := tt.policy.Certificate(r)
			if tt.want == "" {
				if err == nil {
					t.Fatal("untrusted identity accepted")
				}
				return
			}
			if err != nil || cert.Subject.CommonName != tt.want {
				t.Fatalf("unexpected identity %v: %v", cert, err)
			}
		})
	}
}

func TestGatewayTLSRejectsDirectConnectionsAndSupportsPinRotation(t *testing.T) {
	gateway, bundle := testCertificate(t, "gateway")
	replacement, nextBundle := testCertificate(t, "replacement")
	intruder, _ := testCertificate(t, "intruder")
	policy, err := FromPEM(append(bundle, nextBundle...))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(policy.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	server.TLS = &tls.Config{}
	policy.ConfigureTLS(server.TLS)
	server.StartTLS()
	defer server.Close()
	for _, tt := range []struct {
		name    string
		cert    *tls.Certificate
		allowed bool
	}{{"anonymous", nil, false}, {"untrusted", &intruder, false}, {"current pin", &gateway, true}, {"next pin", &replacement, true}} {
		t.Run(tt.name, func(t *testing.T) {
			transport := server.Client().Transport.(*http.Transport).Clone()
			if tt.cert != nil {
				transport.TLSClientConfig.Certificates = []tls.Certificate{*tt.cert}
			}
			client := &http.Client{Transport: transport}
			defer client.CloseIdleConnections()
			r, _ := http.NewRequest(http.MethodGet, server.URL+"/login", nil)
			r.Header.Set("Client-Cert", ":"+base64.StdEncoding.EncodeToString(gateway.Leaf.Raw)+":")
			response, err := client.Do(r)
			if response != nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			if tt.allowed {
				if err != nil || response.StatusCode != 204 {
					t.Fatalf("gateway rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("untrusted direct TLS accepted")
			}
		})
	}
	// Removing an old leaf from the bundle revokes that gateway, including requests
	// on already established connections because Protect rechecks every request.
	rotated, err := FromPEM(nextBundle)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://example.test/login", nil)
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{gateway.Leaf}}
	rec := httptest.NewRecorder()
	rotated.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("removed pin accepted") })).ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal(rec.Code)
	}
}

func TestForwardOverwritesEveryUntrustedIdentity(t *testing.T) {
	device, _ := testCertificate(t, "device")
	for _, authenticated := range []bool{false, true} {
		in := httptest.NewRequest("GET", "https://example.test", nil)
		in.TLS = &tls.ConnectionState{HandshakeComplete: true}
		if authenticated {
			in.TLS.PeerCertificates = []*x509.Certificate{device.Leaf}
		}
		out := in.Clone(in.Context())
		for _, key := range []string{"Client-Cert", "Client-Cert-Chain", "X-Client-Cert", "X-Ssl-Client-Cert", "SSL-Client-Verify", "X-Forwarded-Client-Cert"} {
			out.Header.Set(key, "forged")
		}
		Forward(out, in)
		expected := 0
		if authenticated {
			expected = 1
		}
		if len(out.Header) != expected || strings.Contains(out.Header.Get("Client-Cert"), "forged") {
			t.Fatal("untrusted identity survived", out.Header)
		}
	}
}

func TestTrustBundleFailsClosed(t *testing.T) {
	_, bundle := testCertificate(t, "gateway")
	for _, input := range [][]byte{nil, []byte("invalid"), append([]byte("ignored junk\n"), bundle...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}), append(bundle, []byte("trailing junk")...)} {
		if _, err := FromPEM(input); err == nil {
			t.Fatal("invalid configured trust silently accepted")
		}
	}
	t.Setenv(GatewayCertificatesEnv, "/nonexistent/openuem-gateway.pem")
	if _, err := FromEnvironment(); err == nil {
		t.Fatal("missing configured trust silently accepted")
	}
}

func TestGatewayTrustRejectsInvalidCertificatePurposeOrTime(t *testing.T) {
	identity, _ := testCertificate(t, "gateway")
	key := identity.PrivateKey.(*ecdsa.PrivateKey)
	for _, name := range []string{"expired", "not yet valid", "CA", "server only", "cannot sign"} {
		t.Run(name, func(t *testing.T) {
			template := *identity.Leaf
			switch name {
			case "expired":
				template.NotAfter = time.Now().Add(-time.Second)
			case "not yet valid":
				template.NotBefore = time.Now().Add(time.Hour)
			case "CA":
				template.IsCA = true
				template.BasicConstraintsValid = true
			case "server only":
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "cannot sign":
				template.KeyUsage = x509.KeyUsageKeyEncipherment
			}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = FromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err == nil {
				t.Fatal("invalid gateway credential trusted")
			}
		})
	}
}
