//go:build linux

package acmeissuer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func referenceACME(t *testing.T, local bool) netip.Addr {
	t.Helper()
	if os.Getenv("OPENUEM_ACME_REFERENCE_FIXTURE") != "1" {
		t.Skip("requires the owned isolated reference ACME network")
	}
	value := os.Getenv("OPENUEM_ACME_REFERENCE_ADDRESS")
	if local && value == "" {
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			t.Fatal("reference ACME network address is unavailable")
		}
		for _, candidate := range addresses {
			prefix, err := netip.ParsePrefix(candidate.String())
			if err == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() {
				if value != "" {
					t.Fatal("reference ACME server network is ambiguous")
				}
				value = prefix.Addr().String()
			}
		}
	}
	address, err := netip.ParseAddr(value)
	if os.Geteuid() == 0 || err != nil || !address.Is4() || !address.IsPrivate() {
		t.Fatal("reference ACME fixture requires a non-root account and private IPv4 address")
	}
	return address
}

// This server exists only in the test image. The production issuer and gateway
// images never contain Pebble, provider control routes or test signing keys.
func TestACMEReferenceServer(t *testing.T) {
	address := referenceACME(t, true)
	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	dns := startACMEDNSOn(t, "0.0.0.0", address.As4())
	provider := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/fixture/fail" || r.URL.Path == "/fixture/allow" {
				username, password, valid := r.BasicAuth()
				if r.Method != http.MethodPost || !valid || username != "fixture" || password != "synthetic-dns-secret" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				dns.mu.Lock()
				dns.fail = r.URL.Path == "/fixture/fail"
				dns.mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.URL.Path == "/fixture/status" && r.Method == http.MethodGet {
				dns.mu.Lock()
				defer dns.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]int{"present": dns.present, "cleanup": dns.cleanup, "txt": dns.txt, "records": len(dns.records)})
				return
			}
			dns.provider(w, r)
		})}
	listener, err := net.Listen("tcp4", "0.0.0.0:18080")
	if err != nil {
		t.Fatal("reference provider listener is unavailable")
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = provider.Serve(listener) }()
	defer func() { _ = provider.Close(); <-done }()
	base := t.TempDir()
	certificate, key := fixtureACMETLSNames(t, []string{"localhost", "acme.example.test"}, []net.IP{net.ParseIP("127.0.0.1"), net.IP(address.AsSlice())})
	certificatePath, keyPath := filepath.Join(base, "acme.pem"), filepath.Join(base, "acme.key")
	writeFixture(t, certificatePath, certificate)
	writeFixture(t, keyPath, key)
	configuration, _ := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress": "0.0.0.0:14000", "managementListenAddress": "127.0.0.1:15000",
		"certificate": certificatePath, "privateKey": keyPath, "httpPort": 5002, "tlsPort": 5001,
		"profiles":   map[string]any{"default": map[string]any{"description": "isolated reference DNS-01 fixture", "validityPeriod": 3600}},
		"retryAfter": map[string]int{"authz": 1, "order": 1},
	}})
	path := filepath.Join(base, "pebble.json")
	writeFixture(t, path, configuration)
	process := exec.CommandContext(ctx, "/pebble", "-config", path, "-dnsserver", "127.0.0.1:53")
	process.Env = []string{"PEBBLE_VA_NOSLEEP=1", "PEBBLE_AUTHZREUSE=0", "PEBBLE_WFE_NONCEREJECT=0"}
	process.Stdout, process.Stderr = io.Discard, io.Discard
	if err := process.Start(); err != nil {
		t.Fatal("reference ACME server did not start")
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	ready, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var roots []byte
	eventuallyACME(t, ready, func() bool {
		response, err := client.Get("https://127.0.0.1:15000/roots/0")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		roots, err = io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return err == nil && response.StatusCode == http.StatusOK
	})
	writeFixture(t, "/fixture/acme-roots.pem", certificate)
	writeFixture(t, "/fixture/gateway-roots.pem", roots)
	writeFixture(t, "/fixture/ready.json", []byte(`{"ready":true}`))
	<-ctx.Done()
}

func TestACMEReferenceClient(t *testing.T) {
	address := referenceACME(t, false)
	c, _ := fixtureConfig(t)
	c.DirectoryURL = "https://acme.example.test:14000/dir"
	c.ACMERootsFile = "/fixture/acme-roots.pem"
	c.Resolvers = []string{net.JoinHostPort(address.String(), "53")}
	c.AttemptTimeout = "20s"
	provider := "http://acme.example.test:18080"
	values, _ := json.Marshal(map[string]string{"HTTPREQ_ENDPOINT": provider, "HTTPREQ_USERNAME": "fixture", "HTTPREQ_PASSWORD": "synthetic-dns-secret",
		"HTTPREQ_PROPAGATION_TIMEOUT": "10", "HTTPREQ_POLLING_INTERVAL": "1", "HTTPREQ_HTTP_TIMEOUT": "2"})
	writeFixture(t, c.ProviderEnvironmentFile, values)
	encoded, _ := json.Marshal(c)
	path := filepath.Join(filepath.Dir(c.StateDirectory), "issuer.json")
	writeFixture(t, path, encoded)
	controlTransport := &http.Transport{}
	defer controlTransport.CloseIdleConnections()
	control := &http.Client{Transport: controlTransport, Timeout: 2 * time.Second}
	change := func(action string) {
		t.Helper()
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, provider+"/fixture/"+action, nil)
		request.SetBasicAuth("fixture", "synthetic-dns-secret")
		response, err := control.Do(request)
		if err != nil {
			t.Fatal("reference provider control did not respond")
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("reference provider control was rejected")
		}
	}
	run := func() error {
		command := exec.CommandContext(t.Context(), "/openuem-acme", "--config", path, "--once")
		output, err := command.CombinedOutput()
		assertACMELogPrivacy(t, output)
		return err
	}
	change("fail")
	if err := run(); err == nil {
		t.Fatal("reference provider failure unexpectedly issued public TLS")
	}
	if _, err := os.Lstat(filepath.Join(c.PublicationDirectory, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed reference DNS provider published a certificate")
	}
	account := accountFingerprints(t, c.StateDirectory)
	if len(account) != 1 {
		t.Fatal("reference provider failure did not retain exactly one account")
	}
	change("allow")
	if err := run(); err != nil {
		t.Fatal("reference DNS-01 issuance did not recover")
	}
	if !reflect.DeepEqual(account, accountFingerprints(t, c.StateDirectory)) {
		t.Fatal("reference DNS-01 retry replaced the original account")
	}
	generation := readFixtureGeneration(t, c)
	certificate, err := os.ReadFile(filepath.Join(c.PublicationDirectory, generation.Name, "fullchain.pem"))
	if err != nil {
		t.Fatal("reference issuer publication is unavailable")
	}
	block, _ := pem.Decode(certificate)
	if block == nil {
		t.Fatal("reference issuer did not publish certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	roots, rootErr := os.ReadFile("/fixture/gateway-roots.pem")
	pool := x509.NewCertPool()
	if err != nil || rootErr != nil || !pool.AppendCertsFromPEM(roots) {
		t.Fatal("reference issued certificate or pinned test CA is unavailable")
	}
	intermediates := x509.NewCertPool()
	intermediates.AppendCertsFromPEM(certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "uem.example.test", Roots: pool, Intermediates: intermediates}); err != nil {
		t.Fatal("reference public certificate does not verify against the test CA")
	}
	response, err := control.Get(provider + "/fixture/status")
	if err != nil {
		t.Fatal("reference DNS challenge evidence is unavailable")
	}
	defer response.Body.Close()
	var counts map[string]int
	if json.NewDecoder(response.Body).Decode(&counts) != nil || counts["present"] == 0 || counts["txt"] == 0 || counts["cleanup"] == 0 || counts["records"] != 0 {
		t.Fatal("reference DNS-01 validation or challenge cleanup did not occur")
	}
	t.Log("separate reference issuer: real DNS-01, provider-failure recovery, retained account and pinned public chain passed")
}
