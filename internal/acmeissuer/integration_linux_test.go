//go:build linux

package acmeissuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/gateway"
	"golang.org/x/net/dns/dnsmessage"
)

// This fixture requires the smoke image's isolated network namespace. It never
// contacts a public CA or DNS provider and never disables challenge validation.
func TestACMEContainerDNS01(t *testing.T) {
	binaryPath := os.Getenv("OPENUEM_ACME_TEST_BINARY")
	if binaryPath == "" {
		t.Skip("requires the isolated ACME smoke container")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	c, _ := fixtureConfig(t)
	c.AttemptTimeout = "20s"
	c.Resolvers = []string{"127.0.0.1:53"}
	dns := startACMEDNS(t)
	provider := httptest.NewServer(http.HandlerFunc(dns.provider))
	defer provider.Close()
	providerJSON, _ := json.Marshal(map[string]string{
		"HTTPREQ_ENDPOINT": provider.URL, "HTTPREQ_USERNAME": "fixture",
		"HTTPREQ_PASSWORD": "synthetic-dns-secret", "HTTPREQ_PROPAGATION_TIMEOUT": "10",
		"HTTPREQ_POLLING_INTERVAL": "1", "HTTPREQ_HTTP_TIMEOUT": "2",
	})
	writeFixture(t, c.ProviderEnvironmentFile, providerJSON)

	// The ACME HTTPS listener has its own private fixture trust anchor. The
	// subsequently issued gateway certificate is verified against Pebble's root.
	base := filepath.Dir(c.StateDirectory)
	certificate, key := fixtureACMETLS(t)
	c.ACMERootsFile = filepath.Join(base, "acme-root.pem")
	writeFixture(t, c.ACMERootsFile, certificate)
	keyPath := filepath.Join(base, "acme-server.key")
	writeFixture(t, keyPath, key)
	pebbleConfig, _ := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
		"certificate": c.ACMERootsFile, "privateKey": keyPath,
		"httpPort": 5002, "tlsPort": 5001,
		"profiles":   map[string]any{"default": map[string]any{"description": "local DNS-01 fixture", "validityPeriod": 120}},
		"retryAfter": map[string]int{"authz": 1, "order": 1},
	}})
	pebblePath := filepath.Join(base, "pebble.json")
	writeFixture(t, pebblePath, pebbleConfig)
	pebble := exec.CommandContext(ctx, "/pebble", "-config", pebblePath, "-dnsserver", "127.0.0.1:53")
	pebble.Env = []string{"PEBBLE_VA_NOSLEEP=1", "PEBBLE_AUTHZREUSE=0", "PEBBLE_WFE_NONCEREJECT=0"}
	pebble.Stdout, pebble.Stderr = io.Discard, io.Discard
	if err := pebble.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pebble.Process.Kill(); _ = pebble.Wait() }()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		t.Fatal("invalid ACME fixture trust")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	eventuallyACME(t, ctx, func() bool {
		response, err := client.Get(c.DirectoryURL)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
	configPath := filepath.Join(base, "issuer.json")
	encodedConfig, _ := json.Marshal(c)
	writeFixture(t, configPath, encodedConfig)
	runOnce := func() error {
		command := exec.CommandContext(ctx, binaryPath, "--config", configPath, "--once")
		output, err := command.CombinedOutput()
		assertACMELogPrivacy(t, output)
		if err != nil {
			t.Logf("issuer fixture result: %s", output)
		}
		return err
	}

	// Failure after ACME registration must retain the account and publish nothing.
	dns.mu.Lock()
	dns.fail = true
	dns.mu.Unlock()
	if err := runOnce(); err == nil {
		t.Fatal("failed provider was accepted")
	}
	if _, err := os.Lstat(filepath.Join(c.PublicationDirectory, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("provider failure published a certificate", err)
	}
	account := accountFingerprints(t, c.StateDirectory)
	if len(account) != 1 {
		t.Fatal("expected exactly one persisted account key", len(account))
	}
	dns.mu.Lock()
	dns.fail = false
	dns.mu.Unlock()
	if err := runOnce(); err != nil {
		t.Fatal("real DNS-01 issuance failed", err)
	}
	first := readFixtureGeneration(t, c)
	if !reflect.DeepEqual(account, accountFingerprints(t, c.StateDirectory)) {
		t.Fatal("retry replaced the ACME account")
	}
	firstPEM, err := os.ReadFile(filepath.Join(c.PublicationDirectory, first.Name, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}

	rootResponse, err := client.Get("https://127.0.0.1:15000/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := io.ReadAll(io.LimitReader(rootResponse.Body, 64<<10))
	rootResponse.Body.Close()
	issuedRoots := x509.NewCertPool()
	if err != nil || rootResponse.StatusCode != http.StatusOK || !issuedRoots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("cannot trust the synthetic issuing CA", err)
	}
	publicTLS, err := gateway.NewPublicTLS(c.PublicOrigin,
		filepath.Join(c.PublicationDirectory, "current", "fullchain.pem"),
		filepath.Join(c.PublicationDirectory, "current", "private.pem"))
	if err != nil {
		t.Fatal("gateway rejected ACME output", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ready") }))
	server.TLS = publicTLS.Config()
	server.StartTLS()
	defer server.Close()
	checkHandshake := func() [32]byte {
		t.Helper()
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Listener.Addr().String(),
			&tls.Config{RootCAs: issuedRoots, ServerName: c.domain(), MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal("gateway handshake failed", err)
		}
		defer connection.Close()
		return sha256.Sum256(connection.ConnectionState().PeerCertificates[0].Raw)
	}
	firstHandshake := checkHandshake()
	watchCtx, stopWatch := context.WithCancel(ctx)
	watchDone := make(chan error, 1)
	go func() { watchDone <- publicTLS.Watch(watchCtx, time.Second, nil) }()
	defer func() {
		stopWatch()
		if err := <-watchDone; err != nil {
			t.Error(err)
		}
	}()

	// Use the real server's ARI endpoint to request immediate renewal. No client
	// force-renew flag, DNS propagation bypass or wall-clock adjustment is used.
	ariResponse, _ := json.Marshal(map[string]any{"suggestedWindow": map[string]time.Time{
		"start": time.Now().Add(-time.Hour).UTC(), "end": time.Now().Add(-time.Minute).UTC(),
	}})
	ariRequest, _ := json.Marshal(map[string]string{"Certificate": string(firstPEM), "ARIResponse": string(ariResponse)})
	response, err := client.Post("https://127.0.0.1:15000/set-renewal-info/", "application/json", bytes.NewReader(ariRequest))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("ARI update rejected", response.StatusCode)
	}

	// Exercise the distributed executable's default daemon mode and SIGTERM.
	daemon := exec.CommandContext(ctx, binaryPath, "--config", configPath)
	var daemonLog bytes.Buffer
	daemon.Stdout, daemon.Stderr = &daemonLog, &daemonLog
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = daemon.Process.Kill()
			_ = daemon.Wait()
		}
		// Wait has joined the output copier before reading the buffer. Preserve
		// the sanitized service result when a renewal deadline fails in CI.
		if t.Failed() {
			assertACMELogPrivacy(t, daemonLog.Bytes())
			t.Logf("issuer daemon fixture result: %s", daemonLog.Bytes())
		}
	}()
	eventuallyACME(t, ctx, func() bool {
		current, err := os.Readlink(filepath.Join(c.PublicationDirectory, "current"))
		return err == nil && current != first.Name
	})
	second := readFixtureGeneration(t, c)
	if second.CertificateSHA256 == first.CertificateSHA256 {
		t.Fatal("renewal reused the certificate")
	}
	eventuallyACME(t, ctx, func() bool { return checkHandshake() != firstHandshake })
	if err := daemon.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := daemon.Wait(); err != nil {
		t.Fatal("issuer did not shut down cleanly", err)
	}
	joined = true
	assertACMELogPrivacy(t, daemonLog.Bytes())
	if !reflect.DeepEqual(account, accountFingerprints(t, c.StateDirectory)) {
		t.Fatal("renewal replaced the ACME account")
	}
	service, err := Open(c, "/lego")
	if err != nil {
		t.Fatal("restart did not release leases or retain valid state", err)
	}
	service.Close()
	dns.mu.Lock()
	defer dns.mu.Unlock()
	if dns.present < 2 || dns.cleanup < 2 || dns.txt < 4 || len(dns.records) != 0 {
		t.Fatal("real issuance and renewal must validate and clean DNS challenges", dns.present, dns.cleanup, dns.txt, len(dns.records))
	}
	if err := filepath.WalkDir(c.PublicationDirectory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		name := entry.Name()
		if name != "issuer.lock" && name != "installation.json" && name != "generation.json" && name != "fullchain.pem" && name != "private.pem" {
			t.Errorf("unexpected published file: %s", name)
		}
		data, err := os.ReadFile(path)
		if bytes.Contains(data, []byte("synthetic-dns-secret")) {
			t.Error("DNS credential entered publication")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Log("actual issuer and lego: provider failure, DNS-01, retained account, ARI renewal, gateway reload and clean shutdown passed")
}

func assertACMELogPrivacy(t *testing.T, output []byte) {
	t.Helper()
	for _, secret := range []string{"synthetic-dns-secret", "operator@example.test", "PRIVATE KEY"} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatal("issuer output exposed account or provider material")
		}
	}
}

func readFixtureGeneration(t *testing.T, c Config) Generation {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(c.PublicationDirectory, "current", "generation.json"))
	var generation Generation
	if err != nil || decodeJSON(data, &generation) != nil {
		t.Fatal("missing published generation", err)
	}
	return generation
}

func accountFingerprints(t *testing.T, state string) map[string][32]byte {
	t.Helper()
	result := map[string][32]byte{}
	root := filepath.Join(state, "lego", "accounts")
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".key") {
			return nil
		}
		data, err := readProtected(path, 64<<10, true)
		if err != nil {
			return err
		}
		defer clear(data)
		name, err := filepath.Rel(root, path)
		result[name] = sha256.Sum256(data)
		return err
	}); err != nil {
		t.Fatal("cannot inspect protected synthetic account", err)
	}
	return result
}

func eventuallyACME(t *testing.T, ctx context.Context, check func() bool) {
	t.Helper()
	for !check() {
		select {
		case <-ctx.Done():
			t.Fatal("local ACME fixture did not reach the expected state", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func fixtureACMETLS(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

type acmeDNS struct {
	mu                    sync.Mutex
	records               map[string]bool
	fail                  bool
	present, cleanup, txt int
}

func (d *acmeDNS) provider(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok || username != "fixture" || password != "synthetic-dns-secret" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var request struct {
		FQDN  string `json:"fqdn"`
		Value string `json:"value"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request) != nil || request.FQDN != "_acme-challenge.uem.example.test." || request.Value == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/present":
		d.records[request.Value] = true
		d.present++
	case "/cleanup":
		delete(d.records, request.Value)
		d.cleanup++
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func startACMEDNS(t *testing.T) *acmeDNS {
	t.Helper()
	d := &acmeDNS{records: map[string]bool{}}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		t.Fatal("isolated DNS listener", err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		buffer := make([]byte, 4096)
		for {
			n, address, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if response := d.answer(buffer[:n]); response != nil {
				_, _ = udp.WriteTo(response, address)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			connection, err := tcp.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(connection, size[:]); err != nil {
					return
				}
				message := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(connection, message); err != nil {
					return
				}
				response := d.answer(message)
				binary.BigEndian.PutUint16(size[:], uint16(len(response)))
				_, _ = connection.Write(append(size[:], response...))
			}()
		}
	}()
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close(); workers.Wait() })
	return d
}

func (d *acmeDNS) answer(data []byte) []byte {
	var query dnsmessage.Message
	if query.Unpack(data) != nil || len(query.Questions) != 1 {
		return nil
	}
	q := query.Questions[0]
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
	header := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 0}
	add := func(body dnsmessage.ResourceBody) {
		response.Answers = append(response.Answers, dnsmessage.Resource{Header: header, Body: body})
	}
	name := q.Name.String()
	switch q.Type {
	case dnsmessage.TypeSOA:
		if name == "example.test." {
			add(&dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.test."), MBox: dnsmessage.MustNewName("hostmaster.example.test."), Serial: 1, Refresh: 60, Retry: 60, Expire: 60})
		}
	case dnsmessage.TypeNS:
		if name == "example.test." {
			add(&dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns.example.test.")})
		}
	case dnsmessage.TypeA:
		if name == "ns.example.test." {
			add(&dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
		}
	case dnsmessage.TypeTXT:
		if name == "_acme-challenge.uem.example.test." {
			d.mu.Lock()
			defer d.mu.Unlock()
			d.txt++
			for value := range d.records {
				add(&dnsmessage.TXTResource{TXT: []string{value}})
			}
		}
	}
	encoded, err := response.Pack()
	if err != nil {
		return nil
	}
	return encoded
}
