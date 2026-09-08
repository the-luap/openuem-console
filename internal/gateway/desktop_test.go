package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/desktop/protocol"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestDesktopDownloadsSurviveOrdinaryHTTPDeadlineAndStopWithGateway(t *testing.T) {
	identity, bundle := testIdentity(t, "gateway")
	policy, err := clientidentity.FromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "download deadline", true: "gateway shutdown"}[shutdown], func(t *testing.T) {
			release, stopped := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
			backend := httptest.NewUnstartedServer(policy.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(stopped)
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = io.WriteString(w, "start")
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				select {
				case <-release:
					_, _ = io.WriteString(w, "end")
				case <-r.Context().Done():
				}
			})))
			backend.TLS = &tls.Config{}
			policy.ConfigureTLS(backend.TLS)
			backend.StartTLS()
			defer backend.Close()
			roots := x509.NewCertPool()
			roots.AddCert(backend.Certificate())
			server := httptest.NewUnstartedServer(nil)
			g, err := New(Config{PublicOrigin: "https://" + server.Listener.Addr().String(), AppleURL: backend.URL, ConsoleURL: backend.URL, AuthURL: backend.URL, DesktopURL: backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: roots}})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			server.Config.Handler = g
			server.Config.WriteTimeout = 50 * time.Millisecond
			server.StartTLS()
			defer server.Close()
			defer closeRelease()
			client := server.Client()
			client.Timeout = 5 * time.Second
			path := protocol.DownloadPath(strings.Repeat("a", 64), "windows", "amd64")
			response, err := client.Get(server.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			prefix := make([]byte, 5)
			if _, err = io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "start" {
				t.Fatal("download did not begin", err)
			}
			if shutdown {
				if err = g.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-stopped:
				case <-time.After(5 * time.Second):
					t.Fatal("gateway shutdown did not cancel the private download")
				}
				_, _ = io.ReadAll(response.Body)
				closed, err := client.Get(server.URL + path)
				if err != nil {
					t.Fatal(err)
				}
				closed.Body.Close()
				if closed.StatusCode != 503 {
					t.Fatal("closed gateway admitted another desktop request")
				}
			} else {
				// Cross the deliberately short ordinary response deadline while
				// holding the backend body open. Downloads have their own bound.
				<-time.After(150 * time.Millisecond)
				closeRelease()
				rest, err := io.ReadAll(response.Body)
				if err != nil || string(rest) != "end" {
					t.Fatal("ordinary HTTP deadline truncated an admitted download", err)
				}
			}
		})
	}
}
