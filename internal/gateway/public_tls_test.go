package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type publicTLSFixture struct {
	root                     *x509.Certificate
	rootKey                  *ecdsa.PrivateKey
	certificatePath, keyPath string
	now                      time.Time
}

func newPublicTLSFixture(t *testing.T) *publicTLSFixture {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated gateway test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	return &publicTLSFixture{root: root, rootKey: key, now: now,
		certificatePath: filepath.Join(directory, "public.pem"), keyPath: filepath.Join(directory, "private.pem")}
}

func (f *publicTLSFixture) issue(t *testing.T, edit func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: serial, DNSNames: []string{"uem.example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if edit != nil {
		edit(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.root, &key.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, f.root.Raw}, PrivateKey: key, Leaf: leaf}
}

func (f *publicTLSFixture) publish(t *testing.T, pair tls.Certificate) {
	t.Helper()
	var chain []byte
	for _, der := range pair.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePublicTLSFile(t, f.certificatePath, chain)
	writePublicTLSFile(t, f.keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}

func writePublicTLSFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *publicTLSFixture) clientTLS() *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(f.root)
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

func publicTLSServer(t *testing.T, publicTLS *PublicTLS) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 1 {
			w.Header().Set("X-Test-Client", r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		_, _ = io.WriteString(w, "ready")
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = publicTLS.Config()
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func publicTLSClient(t *testing.T, config *tls.Config, keepAlive bool) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true, DisableKeepAlives: !keepAlive}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func getPublicTLS(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ready" {
		t.Fatalf("unexpected TLS response: %q, %v", body, err)
	}
	return response
}

func TestPublicTLSReloadRetainsHTTP2ConnectionsAndValidatesNewHandshakes(t *testing.T) {
	f := newPublicTLSFixture(t)
	first, second := f.issue(t, nil), f.issue(t, nil)
	f.publish(t, first)
	publicTLS, err := NewPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	server := publicTLSServer(t, publicTLS)
	clientTLS := f.clientTLS()
	device, _ := testIdentity(t, "isolated-client")
	clientTLS.Certificates = []tls.Certificate{device}
	client := publicTLSClient(t, clientTLS, true)
	response := getPublicTLS(t, client, server.URL)
	if response.ProtoMajor != 2 || !response.TLS.PeerCertificates[0].Equal(first.Leaf) || response.Header.Get("X-Test-Client") != "isolated-client" {
		t.Fatal("initial HTTP/2 handshake did not use the configured certificate")
	}
	f.publish(t, second)
	if changed, err := publicTLS.Reload(); err != nil || !changed {
		t.Fatalf("reload: %v, %v", changed, err)
	}
	response = getPublicTLS(t, client, server.URL)
	if !response.TLS.PeerCertificates[0].Equal(first.Leaf) {
		t.Fatal("certificate renewal replaced an established HTTP/2 connection")
	}
	response = getPublicTLS(t, publicTLSClient(t, clientTLS.Clone(), true), server.URL)
	if response.ProtoMajor != 2 || !response.TLS.PeerCertificates[0].Equal(second.Leaf) || response.Header.Get("X-Test-Client") != "isolated-client" {
		t.Fatal("new handshake did not use the replacement certificate and HTTP/2")
	}
	if changed, err := publicTLS.Reload(); err != nil || changed {
		t.Fatalf("unchanged reload: %v, %v", changed, err)
	}
}

func TestPublicTLSSuppliedIssuerConstraintsAndLifetime(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(*x509.Certificate)
		allowed bool
	}{
		{name: "issuer expiry", allowed: true, edit: func(c *x509.Certificate) { c.NotAfter = time.Now().Add(2 * time.Minute).Truncate(time.Second) }},
		{name: "issuer purpose", edit: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "issuer name constraint", edit: func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"example.test"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPublicTLSFixture(t)
			tc.edit(f.root)
			der, err := x509.CreateCertificate(rand.Reader, f.root, f.root, &f.rootKey.PublicKey, f.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			f.root, err = x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			f.publish(t, f.issue(t, nil))
			var offset atomic.Int64
			publicTLS, err := newPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath, func() time.Time { return f.now.Add(time.Duration(offset.Load())) })
			if !tc.allowed {
				if !errors.Is(err, errPublicTLSCertificate) {
					t.Fatal("incompatible supplied issuer accepted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			server := publicTLSServer(t, publicTLS)
			client := publicTLSClient(t, f.clientTLS(), false)
			getPublicTLS(t, client, server.URL)
			offset.Store(int64(3 * time.Minute))
			if response, err := client.Get(server.URL); err == nil {
				response.Body.Close()
				t.Fatal("expired supplied issuer admitted another TLS handshake")
			}
			if changed, err := publicTLS.Reload(); err == nil || changed {
				t.Fatal("expired supplied issuer reloaded")
			}
		})
	}
}

func TestPublicTLSRejectsInvalidPublicationAndPreservesTheLoadedPair(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*x509.Certificate)
		files func(*testing.T, *publicTLSFixture, *tls.Certificate)
	}{
		{name: "foreign hostname", edit: func(c *x509.Certificate) { c.DNSNames = []string{"foreign.example.test"} }},
		{name: "expired", edit: func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }},
		{name: "not yet valid", edit: func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{name: "client purpose", edit: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "CA identity", edit: func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{name: "no signing usage", edit: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
		{name: "unknown critical extension", edit: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
		}},
		{name: "missing certificate", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			if err := os.Remove(f.certificatePath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "partial certificate", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			writePublicTLSFile(t, f.certificatePath, []byte("-----BEGIN CERTIFICATE-----"))
		}},
		{name: "unfinished appended certificate", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			data, err := os.ReadFile(f.certificatePath)
			if err != nil {
				t.Fatal(err)
			}
			writePublicTLSFile(t, f.certificatePath, append(data, []byte("-----BEGIN CERTIFICATE-----\nunfinished")...))
		}},
		{name: "unfinished preceding certificate", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			data, err := os.ReadFile(f.certificatePath)
			if err != nil {
				t.Fatal(err)
			}
			writePublicTLSFile(t, f.certificatePath, append([]byte("-----BEGIN CERTIFICATE-----\nunfinished\n"), data...))
		}},
		{name: "extra private key", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			data, err := os.ReadFile(f.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			writePublicTLSFile(t, f.keyPath, append(data, data...))
		}},
		{name: "unfinished appended key", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			data, err := os.ReadFile(f.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			writePublicTLSFile(t, f.keyPath, append(data, []byte("-----BEGIN PRIVATE KEY-----\nunfinished")...))
		}},
		{name: "empty key", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) { writePublicTLSFile(t, f.keyPath, nil) }},
		{name: "oversized key", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			writePublicTLSFile(t, f.keyPath, make([]byte, (64<<10)+1))
		}},
		{name: "oversized certificate", files: func(t *testing.T, f *publicTLSFixture, _ *tls.Certificate) {
			writePublicTLSFile(t, f.certificatePath, make([]byte, (1<<20)+1))
		}},
		{name: "mismatched pair", files: func(t *testing.T, f *publicTLSFixture, pair *tls.Certificate) {
			pair.PrivateKey = f.issue(t, nil).PrivateKey
			f.publish(t, *pair)
		}},
		{name: "foreign chain", files: func(t *testing.T, f *publicTLSFixture, pair *tls.Certificate) {
			other := newPublicTLSFixture(t)
			pair.Certificate[1] = other.root.Raw
			f.publish(t, *pair)
		}},
		{name: "too many certificates", files: func(t *testing.T, f *publicTLSFixture, pair *tls.Certificate) {
			for len(pair.Certificate) < 9 {
				pair.Certificate = append(pair.Certificate, f.root.Raw)
			}
			f.publish(t, *pair)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPublicTLSFixture(t)
			first := f.issue(t, nil)
			f.publish(t, first)
			publicTLS, err := NewPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			candidate := f.issue(t, tc.edit)
			f.publish(t, candidate)
			if tc.files != nil {
				tc.files(t, f, &candidate)
			}
			if changed, err := publicTLS.Reload(); err == nil || changed {
				t.Fatalf("invalid publication accepted: %v, %v", changed, err)
			}
			if _, err := NewPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath); err == nil {
				t.Fatal("restart admitted invalid certificate files")
			}
			config, err := publicTLS.Config().GetConfigForClient(nil)
			if err != nil || !config.Certificates[0].Leaf.Equal(first.Leaf) {
				t.Fatal("invalid files replaced the loaded pair", err)
			}
			f.publish(t, first)
			if changed, err := publicTLS.Reload(); err != nil || changed {
				t.Fatal("could not recover the original files", changed, err)
			}
		})
	}
	t.Run("regular files only", func(t *testing.T) {
		f := newPublicTLSFixture(t)
		if _, err := NewPublicTLS("https://uem.example.test", filepath.Dir(f.certificatePath), f.keyPath); err == nil {
			t.Fatal("directory accepted as certificate")
		}
	})
}

func TestPublicTLSExpiredCertificateDeniesResumptionUntilValidReplacement(t *testing.T) {
	f := newPublicTLSFixture(t)
	first := f.issue(t, func(c *x509.Certificate) { c.NotAfter = f.now.Add(5 * time.Minute) })
	f.publish(t, first)
	var offset atomic.Int64
	publicTLS, err := newPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath, func() time.Time { return f.now.Add(time.Duration(offset.Load())) })
	if err != nil {
		t.Fatal(err)
	}
	server := publicTLSServer(t, publicTLS)
	config := f.clientTLS()
	config.MaxVersion = tls.VersionTLS12
	config.NextProtos = []string{"http/1.1"}
	config.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	client := publicTLSClient(t, config, false)
	// Use HTTP/1.1 so every request closes its connection and actually attempts
	// another TLS handshake with the same session cache.
	client.Transport.(*http.Transport).ForceAttemptHTTP2 = false
	getPublicTLS(t, client, server.URL)
	if response := getPublicTLS(t, client, server.URL); !response.TLS.DidResume {
		t.Fatal("fixture did not resume its TLS session")
	}
	offset.Store(int64(10 * time.Minute))
	// The client clock still trusts its cached certificate. Server-side validity
	// must reject this resumed handshake before the previous session can bypass it.
	if response, err := client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("expired loaded certificate admitted resumption")
	}
	if changed, err := publicTLS.Reload(); err == nil || changed {
		t.Fatal("expired unchanged files were accepted")
	}
	f.publish(t, f.issue(t, nil))
	if changed, err := publicTLS.Reload(); err != nil || !changed {
		t.Fatal("valid replacement did not restore admission", changed, err)
	}
	getPublicTLS(t, client, server.URL)
	offset.Store(int64(-2 * time.Minute))
	if response, err := client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("clock rollback before validity admitted a handshake")
	}
}

func TestPublicTLSConcurrentReloadAndHandshakes(t *testing.T) {
	f := newPublicTLSFixture(t)
	pairs := []tls.Certificate{f.issue(t, nil), f.issue(t, nil)}
	f.publish(t, pairs[0])
	publicTLS, err := NewPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	server := publicTLSServer(t, publicTLS)
	client := publicTLSClient(t, f.clientTLS(), false)
	var readers sync.WaitGroup
	for range 3 {
		readers.Go(func() {
			for range 10 {
				response, err := client.Get(server.URL)
				if err != nil {
					t.Error(err)
					return
				}
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if err != nil || (!response.TLS.PeerCertificates[0].Equal(pairs[0].Leaf) && !response.TLS.PeerCertificates[0].Equal(pairs[1].Leaf)) {
					t.Error("concurrent handshake did not retain a complete certificate snapshot", err)
				}
			}
		})
	}
	for i := range 10 {
		f.publish(t, pairs[i%2])
		if _, err := publicTLS.Reload(); err != nil {
			t.Error(err)
		}
	}
	readers.Wait()
}

func TestPublicTLSWatchRecoversFailedPublicationAndJoins(t *testing.T) {
	f := newPublicTLSFixture(t)
	pair := f.issue(t, nil)
	f.publish(t, pair)
	publicTLS, err := NewPublicTLS("https://uem.example.test", f.certificatePath, f.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := publicTLS.Watch(context.Background(), 0, nil); err == nil {
		t.Fatal("unbounded polling configuration accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reports := make(chan error, 4)
	done := make(chan error, 1)
	writePublicTLSFile(t, f.keyPath, []byte("interrupted private key publication"))
	go func() { done <- publicTLS.Watch(ctx, time.Second, func(err error) { reports <- err }) }()
	select {
	case err := <-reports:
		if !errors.Is(err, errPublicTLSFiles) {
			t.Fatal("unexpected publication failure report", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("invalid file publication was not reported")
	}
	f.publish(t, pair)
	select {
	case err := <-reports:
		if err != nil {
			t.Fatal("restored files did not recover", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovery was not reported")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("certificate watcher did not join on cancellation")
	}
}
