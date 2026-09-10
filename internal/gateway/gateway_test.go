package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func testIdentity(t *testing.T, name string) (tls.Certificate, []byte) {
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

func TestGatewayRoutesOverMutualTLS(t *testing.T) {
	gateway, bundle := testIdentity(t, "gateway")
	device, _ := testIdentity(t, "device")
	policy, err := clientidentity.FromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(policy.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !policy.IsGateway(r) {
			t.Error("backend received untrusted request")
		}
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Real-IP") != "" || r.Header.Get("X-SSL-Client-Cert") != "" || strings.Contains(r.Header.Get("X-Forwarded-For"), "10.99.99.99") {
			t.Error("spoofed forwarding header survived")
		}
		if strings.HasSuffix(r.URL.Path, "/checkin") {
			cert, err := policy.Certificate(r)
			if err != nil {
				http.Error(w, "identity required", 401)
				return
			}
			if cert.Subject.CommonName != "device" {
				t.Error("wrong client identity", cert.Subject.CommonName)
			}
		}
		fmt.Fprint(w, r.URL.Path)
	})))
	backend.TLS = &tls.Config{}
	policy.ConfigureTLS(backend.TLS)
	backend.StartTLS()
	defer backend.Close()
	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())
	for _, internal := range []bool{false, true} {
		t.Run(fmt.Sprintf("internal=%v", internal), func(t *testing.T) {
			server := httptest.NewUnstartedServer(nil)
			origin := "https://" + server.Listener.Addr().String()
			cidr := "10.0.0.0/8"
			if internal {
				cidr = "127.0.0.1/32"
			}
			handler, err := New(Config{PublicOrigin: origin, AppleURL: backend.URL, ConsoleURL: backend.URL, AuthURL: backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix(cidr)}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{gateway}, RootCAs: roots}})
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = handler
			server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
			server.StartTLS()
			defer server.Close()
			checkin := "/mdm/apple/10000000-0000-0000-0000-000000000001/checkin"
			routes := []struct {
				method, path string
				public       bool
				code         int
			}{
				{"GET", "/login", false, 0}, {"GET", "/auth", false, 0}, {"GET", "/admin", false, 0}, {"GET", "/tenant/1/site/1/devices", false, 0}, {"POST", "/tenant/1/ios/setup", false, 0},
				{"GET", "/computers", false, 0}, {"GET", "/profiles", false, 0}, {"GET", "/deploy", false, 0}, {"GET", "/api/v1/devices", false, 0}, {"GET", "/assets/app.js", false, 0},
				{"GET", "/mdm/apple/enroll/" + strings.Repeat("a", 43), true, 200},
				{"HEAD", "/mdm/apple/enroll/" + strings.Repeat("a", 43), true, 200},
				{"POST", "/mdm/apple/enroll/" + strings.Repeat("a", 43), true, 200},
				{"DELETE", "/mdm/apple/enroll/" + strings.Repeat("a", 43), false, 0},
				{"POST", "/mdm/apple/ade/" + strings.Repeat("a", 43), true, 200},
				{"GET", "/mdm/apple/ade/" + strings.Repeat("a", 43), false, 0},
				{"PUT", "/mdm/apple/ade/" + strings.Repeat("a", 43), false, 0},
				{"POST", "/mdm/apple/ade/" + strings.Repeat("a", 42), false, 0},
				{"POST", "/mdm/apple/ade/" + strings.Repeat("a", 43) + "?x=1", false, 0},
				{"POST", "/mdm/apple/ade/" + strings.Repeat("a", 43) + "?", false, 0},
				{"POST", "/mdm/apple/ade/" + strings.Repeat("a", 43) + "/extra", false, 0},
				{"POST", "/mdm/apple/enroll/" + strings.Repeat("a", 43) + "/admin", false, 0},
				{"PUT", checkin, true, 200},
				{"GET", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep?operation=GetCACert", true, 200},
				{"POST", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep?operation=PKIOperation", true, 200},
				{"GET", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep/20000000-0000-0000-0000-000000000001?operation=GetCACert", true, 200},
				{"POST", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep/20000000-0000-0000-0000-000000000001?operation=PKIOperation", true, 200},
				{"PUT", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep/20000000-0000-0000-0000-000000000001", false, 0},
				{"GET", "/mdm/apple/10000000-0000-0000-0000-000000000001/checkin/20000000-0000-0000-0000-000000000001", false, 0},
				{"GET", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep/20000000-0000-0000-0000-000000000001/admin", false, 0},
				{"PUT", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep", false, 0},
				{"HEAD", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep", false, 0},
				{"GET", "/mdm/apple/invalid/scep", false, 0},
				{"GET", "/mdm/apple/10000000-0000-0000-0000-000000000001/scep/admin", false, 0},
				{"GET", checkin, false, 0}, {"PUT", "/mdm/apple/invalid/checkin", false, 0}, {"GET", "/mdm/apple/admin", false, 0}, {"GET", "/enroll/unknown", false, 0}, {"GET", "/agent-channel", false, 0},
				{"GET", "/mdm/apple/enroll/../../admin", false, 400}, {"GET", "/mdm/apple/%2e%2e/admin", false, 400}, {"GET", "//admin", false, 400}, {"GET", "/mdm%2fapple/enroll/" + strings.Repeat("a", 43), false, 400},
			}
			transport := server.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.Certificates = []tls.Certificate{device}
			client := &http.Client{Transport: transport}
			defer client.CloseIdleConnections()
			for _, route := range routes {
				t.Run(route.method+route.path, func(t *testing.T) {
					req, _ := http.NewRequest(route.method, server.URL+route.path, nil)
					req.Header.Set("X-Forwarded-For", "10.99.99.99")
					req.Header.Set("Forwarded", "for=10.99.99.99")
					req.Header.Set("X-Real-IP", "10.99.99.99")
					req.Header.Set("X-SSL-Client-Cert", "forged")
					req.Header.Set("Client-Cert", "forged")
					response, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, _ := io.ReadAll(response.Body)
					response.Body.Close()
					want := route.code
					if want == 0 {
						want = 403
						if internal {
							want = 200
						}
					}
					if response.StatusCode != want {
						t.Fatalf("got %d, want %d: %s", response.StatusCode, want, body)
					}
					if response.Header.Get("Referrer-Policy") != "strict-origin" {
						t.Fatal("missing referrer protection")
					}
				})
			}
			// An anonymous client cannot become a device by copying its header.
			req, _ := http.NewRequest("PUT", server.URL+checkin, nil)
			req.Header.Set("Client-Cert", "forged")
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 401 {
				t.Fatal("anonymous client acquired identity", response.StatusCode)
			}
			req, _ = http.NewRequest("GET", server.URL+"/login", nil)
			req.Host = "attacker.example"
			response, err = server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 400 {
				t.Fatal("untrusted Host accepted")
			}
		})
	}
}

func TestAdminNetworksDoNotTrustForwardedAddresses(t *testing.T) {
	networks := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("fd12:3456::/48")}
	for _, tt := range []struct {
		remote string
		want   bool
	}{{"10.42.1.2:4242", true}, {"[::ffff:10.42.1.2]:4242", true}, {"[fd12:3456::1]:4242", true}, {"203.0.113.10:4242", false}, {"10.42.1.2", false}, {"[fd12:3456::1%eth0]:4242", false}, {"localhost:443", false}} {
		if allowedAdmin(tt.remote, networks) != tt.want {
			t.Error(tt.remote)
		}
	}
}

func TestGatewayConfigurationRejectsUnsafeOriginsAndTrust(t *testing.T) {
	for _, origin := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test/path", "https://example.test/%2F", "https://example.test?", "https://example.test?next=bad", "https://example.test/#fragment", "//example.test"} {
		if _, err := ParseOrigin(origin); err == nil {
			t.Error("accepted", origin)
		}
	}
	identity, _ := testIdentity(t, "gateway")
	config := Config{PublicOrigin: "https://example.test", AppleURL: "https://apple.test", ConsoleURL: "https://console.test", AuthURL: "https://auth.test", AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: x509.NewCertPool()}}
	if _, err := New(config); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"http://broker.internal", "wss://broker.internal", "https://broker.internal/agent-channel", "https://broker.internal?token=secret"} {
		config.AgentURL = address
		if _, err := New(config); err == nil {
			t.Fatal("unsafe agent backend accepted", address)
		}
	}
	config.AgentURL = "https://broker.internal"
	for _, limit := range []int{-1, 65537} {
		config.AgentConnectionLimit = limit
		if _, err := New(config); err == nil {
			t.Fatal("invalid agent connection limit accepted")
		}
	}
	config.AgentConnectionLimit = 0
	config.BackendTLS.InsecureSkipVerify = true
	if _, err := New(config); err == nil {
		t.Fatal("insecure backend TLS accepted")
	}
	config.BackendTLS.InsecureSkipVerify = false
	config.BackendTLS.Certificates = []tls.Certificate{identity, identity}
	if _, err := New(config); err == nil {
		t.Fatal("ambiguous gateway identities accepted")
	}
	config.BackendTLS.Certificates = []tls.Certificate{identity}
	config.BackendTLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &identity, nil }
	if _, err := New(config); err == nil {
		t.Fatal("dynamic identity override accepted")
	}
	config.BackendTLS.GetClientCertificate = nil
	config.AdminNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, err := New(config); err == nil {
		t.Fatal("public administrator network accepted")
	}
}
