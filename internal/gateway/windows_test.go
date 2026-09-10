package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/windows/protocol"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestGatewayWindowsExactRoutesAreOptionalAndSeparateFromConsole(t *testing.T) {
	identity, bundle := testIdentity(t, "synthetic Windows gateway")
	policy, err := clientidentity.FromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var deviceCalls, consoleCalls atomic.Int32
	newBackend := func(counter *atomic.Int32) *httptest.Server {
		server := httptest.NewUnstartedServer(policy.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { counter.Add(1); w.WriteHeader(204) })))
		server.TLS = &tls.Config{}
		policy.ConfigureTLS(server.TLS)
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}
	windows, console := newBackend(&deviceCalls), newBackend(&consoleCalls)
	roots := x509.NewCertPool()
	roots.AddCert(windows.Certificate())
	roots.AddCert(console.Certificate())
	for _, enabled := range []bool{false, true} {
		for _, internal := range []bool{false, true} {
			front := httptest.NewUnstartedServer(nil)
			network := "10.42.0.0/16"
			if internal {
				network = "127.0.0.1/32"
			}
			config := Config{PublicOrigin: "https://" + front.Listener.Addr().String(), AppleURL: console.URL, ConsoleURL: console.URL, AuthURL: console.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix(network)}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: roots}}
			if enabled {
				config.WindowsURL = windows.URL
			}
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			front.Config.Handler = g
			front.StartTLS()
			defer front.Close()
			for _, path := range []string{protocol.DiscoveryPath, protocol.PolicyPath, protocol.EnrollmentPath, protocol.ManagementPath} {
				for _, suffix := range []string{"", "/", "?", "?tenant=2", "/admin"} {
					for _, method := range []string{"GET", "HEAD", "POST", "PUT", "OPTIONS", "DELETE"} {
						beforeDevice, beforeConsole := deviceCalls.Load(), consoleCalls.Load()
						r, err := http.NewRequest(method, front.URL+path+suffix, nil)
						if err != nil {
							t.Fatal(err)
						}
						response, err := front.Client().Do(r)
						if err != nil {
							t.Fatal(err)
						}
						io.Copy(io.Discard, response.Body)
						response.Body.Close()
						public := enabled && suffix == "" && (method == "POST" || path == protocol.DiscoveryPath && (method == "GET" || method == "HEAD"))
						want := 403
						if public || internal {
							want = 204
						}
						if response.StatusCode != want {
							t.Fatal("unexpected Windows routing status", method, path+suffix, response.StatusCode)
						}
						if deviceCalls.Load()-beforeDevice != boolCount(public) || consoleCalls.Load()-beforeConsole != boolCount(!public && internal) {
							t.Fatal("Windows request reached wrong backend")
						}
					}
				}
			}
			for _, path := range []string{"/windows/certificate-reminders", "/tenant/1/windows/certificate-reminders", "/tenant/1/site/1/windows/certificate-reminders", "/windows/certificate-health", "/tenant/1/windows/certificate-health", "/tenant/1/site/1/windows/certificate-health", "/windows", "/tenant/1/site/1/windows", "/windows/device/disconnections", "/tenant/1/windows/device/disconnections/create", "/tenant/1/site/1/windows/device/disconnections/request/release", "/EnrollmentServer/%44iscovery.svc", "/mdm/windows//syncml"} {
				for _, method := range []string{"GET", "POST"} {
					r, _ := http.NewRequest(method, front.URL+path, nil)
					response, err := front.Client().Do(r)
					if err != nil {
						t.Fatal(err)
					}
					response.Body.Close()
					want := 403
					if internal {
						want = 204
					}
					if strings.Contains(path, "%") || strings.Contains(path, "//") {
						want = 400
					}
					if response.StatusCode != want {
						t.Fatal("nonprotocol route became public")
					}
				}
			}
			config.WindowsURL = "http://private.example.test"
			if bad, err := New(config); err == nil {
				bad.Close()
				t.Fatal("plaintext Windows backend admitted")
			}
		}
	}
}

func boolCount(value bool) int32 {
	if value {
		return 1
	}
	return 0
}
