package readiness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func deadline(t *testing.T, duration time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), duration)
	t.Cleanup(cancel)
	return ctx
}
func write(t *testing.T, directory, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if keyfile.Create(path, value) != nil {
		t.Fatal("cannot create protected synthetic input")
	}
	return path
}
func identity(t *testing.T) ([]byte, []byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic readiness identity"}, DNSNames: []string{"uem.example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, privatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	pair, err := tls.X509KeyPair(publicPEM, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return publicPEM, privatePEM, pair
}

func TestReferenceReadinessHTTPAndGateway(t *testing.T) {
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Error("probe reached an unrelated endpoint")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer health.Close()
	if err := Wait(deadline(t, time.Second), Options{Mode: "http", Address: health.URL + "/healthz"}); err != nil {
		t.Fatal(err)
	}
	public, _, pair := identity(t)
	routes := map[string]bool{}
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "uem.example.test" {
			t.Error("public HTTP authority changed")
		}
		if r.URL.Path != "/EnrollmentServer/Discovery.svc" && r.URL.Path != "/enroll/desktop/bootstrap-keys" {
			t.Error("probe requested an unrelated route")
		}
		routes[r.URL.Path] = true
		w.WriteHeader(http.StatusOK)
	}))
	gateway.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	gateway.Config.ErrorLog = log.New(io.Discard, "", 0)
	gateway.StartTLS()
	defer gateway.Close()
	options := Options{Mode: "gateway", Address: gateway.Listener.Addr().String(), Origin: "https://uem.example.test", TrustFile: write(t, t.TempDir(), "gateway.pem", public)}
	if err := Wait(deadline(t, time.Second), options); err != nil || len(routes) != 2 {
		t.Fatal("public gateway readiness failed", err)
	}
	other, _, _ := identity(t)
	options.TrustFile = write(t, t.TempDir(), "other.pem", other)
	if err := Wait(deadline(t, 150*time.Millisecond), options); !errors.Is(err, ErrNotReady) {
		t.Fatal("another gateway certificate was trusted", err)
	}
}

func TestReferenceReadinessRejectsRedirectsAndUnexpectedResponses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://127.0.0.1:1/unrelated")
				w.WriteHeader(status)
			}))
			defer service.Close()
			if err := Wait(deadline(t, 80*time.Millisecond), Options{Mode: "http", Address: service.URL + "/healthz"}); !errors.Is(err, ErrNotReady) {
				t.Fatal("unexpected health response accepted", err)
			}
		})
	}
}

func brokerFixture(t *testing.T, grant string) Options {
	t.Helper()
	directory := t.TempDir()
	certificate, private, _ := identity(t)
	cert := write(t, directory, "server.pem", certificate)
	key := write(t, directory, "server.key", private)
	issuer, _ := nkeys.CreateAccount()
	defer issuer.Wipe()
	issuerPublic, _ := issuer.PublicKey()
	public := make([]string, 5)
	var worker string
	for i := range public {
		pair, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		public[i], _ = pair.PublicKey()
		if i == 2 {
			seed, _ := pair.Seed()
			worker = write(t, directory, "worker.seed", seed)
			clear(seed)
		}
		pair.Wipe()
	}
	config := enrollment.BrokerConfiguration{Name: "readiness", Listen: "127.0.0.1:4222", WebsocketListen: "127.0.0.1:9222", CertificateFile: cert, KeyFile: key, GatewayCAFile: cert, StoreDirectory: filepath.Join(directory, "jetstream"), Issuer: issuerPublic, AuthorizationUser: public[0], RevocationUser: public[1], WorkerUser: public[2], ConsoleUser: public[3], ProvisionerUser: public[4]}
	data, err := config.Render()
	if err != nil {
		t.Fatal(err)
	}
	if grant != "current" {
		var document map[string]any
		if json.Unmarshal(data, &document) != nil {
			t.Fatal("invalid fixture config")
		}
		permissions := document["accounts"].(map[string]any)["UEM_DEVICES"].(map[string]any)["users"].([]any)[0].(map[string]any)["permissions"].(map[string]any)
		subjects := []string{"uem.v1.agent.*.request.report"}
		if grant == "broad" {
			subjects = []string{"uem.v1.agent.*.request.>"}
		}
		permissions["subscribe"] = subjects
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if encoder.Encode(document) != nil {
			t.Fatal("cannot render fixture grant")
		}
		data = encoded.Bytes()
	}
	opts, err := server.ProcessConfigFile(write(t, directory, "broker.json", data))
	if err != nil {
		t.Fatal("cannot parse fixture broker configuration")
	}
	opts.Port, opts.Websocket.Port = -1, -1
	opts.NoLog, opts.NoSigs = true, true
	broker, err := server.NewServer(opts)
	if err != nil {
		t.Fatal("cannot create fixture broker")
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(time.Second) {
		t.Fatal("fixture broker did not start")
	}
	return Options{Mode: "broker", Address: "tls://" + broker.Addr().String(), TrustFile: cert, KeyFile: worker}
}

func TestReferenceReadinessBrokerGrantBoundary(t *testing.T) {
	for _, grant := range []string{"current", "missing", "broad"} {
		t.Run(grant, func(t *testing.T) {
			options := brokerFixture(t, grant)
			budget := 400 * time.Millisecond
			if grant == "current" {
				// Native Windows TLS/key-file setup and the broker flushes can
				// exceed 400 ms on shared CI runners. Cancellation is tested below.
				budget = 5 * time.Second
			}
			err := Wait(deadline(t, budget), options)
			if grant == "current" && err != nil || grant != "current" && !errors.Is(err, ErrNotReady) {
				t.Fatal("incorrect broker readiness decision", err)
			}
		})
	}
}

func TestReferenceReadinessCancellationAndConfiguration(t *testing.T) {
	for _, options := range []Options{{}, {Mode: "http", Address: "http://example.test:1326/healthz"}, {Mode: "http", Address: "http://127.0.0.1:1326/other"}, {Mode: "http", Address: "http://synthetic-secret@127.0.0.1:1326/healthz"}, {Mode: "gateway", Origin: "https://uem.example.test/", Address: "127.0.0.1:8443"}, {Mode: "broker", Address: "tls://user:synthetic-secret@127.0.0.1:4222"}} {
		if err := Wait(deadline(t, time.Second), options); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid probe configuration accepted", err)
		}
	}
	if err := Wait(context.Background(), Options{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded probe accepted")
	}
	options := brokerFixture(t, "current")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			<-done
			connection.Close()
		}
	}()
	defer close(done)
	options.Address = "tls://" + listener.Addr().String()
	started := time.Now()
	if err := Wait(deadline(t, 60*time.Millisecond), options); !errors.Is(err, ErrNotReady) {
		t.Fatal("stalled broker accepted", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("stalled handshake ignored the caller deadline")
	}
}
