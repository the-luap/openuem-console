package desktop

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"golang.org/x/time/rate"
)

type publicFixture struct {
	*catalogTestFixture
	invitation *InstallerInvitation
	request    *enrollment.Request
	handler    *PublicHandler
	server     *httptest.Server
}

func newPublicFixture(t *testing.T, bootstrapKeys ...ed25519.PrivateKey) *publicFixture {
	t.Helper()
	f := newCatalogFixture(t)
	invitation, request := prepareInstallerInvitation(t, f)
	handler, err := NewPublicHandler(f.store, f.catalog, "https://uem.example.test", clientidentity.Policy{}, bootstrapKeys...)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config = handler.Server("")
	// httptest uses Serve with a separately wrapped TLS listener; production
	// ServeTLS configures ALPN automatically. Keep both fixture configs aligned.
	server.Config.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
	server.TLS = server.Config.TLSConfig.Clone()
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(func() { server.CloseClientConnections(); handler.Close(); server.Close() })
	return &publicFixture{f, invitation, request, handler, server}
}

func publicRequest(t *testing.T, client *http.Client, base, method, path string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal("could not construct test request")
	}
	r.Host = "uem.example.test"
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	response, err := client.Do(r)
	if err != nil {
		var transport *url.Error
		if errors.As(err, &transport) {
			t.Fatal("public request failed", transport.Err)
		}
		t.Fatal("public request failed without transport details")
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal("could not read public response")
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("response lost cache, sniffing or cross-origin protection")
	}
	return response, data
}

func (f *publicFixture) path(kind string) string {
	return "/enroll/desktop/" + f.request.Invitation + "/" + kind
}

func TestPublicDesktopMetadataAndPackagesNeverConsumeInvitations(t *testing.T) {
	f := newPublicFixture(t)
	for _, method := range []string{"GET", "HEAD", "GET"} {
		response, data := publicRequest(t, f.server.Client(), f.server.URL, method, f.path("metadata"), nil, nil)
		if response.ProtoMajor != 2 {
			t.Fatal("native TLS fixture did not exercise HTTP/2")
		}
		if response.StatusCode != 200 {
			t.Fatal("metadata unavailable", response.StatusCode, string(data))
		}
		if method == "HEAD" {
			if len(data) != 0 || response.ContentLength <= 0 {
				t.Fatal("HEAD returned data or omitted representation length")
			}
			continue
		}
		var metadata InstallerMetadata
		if err := json.Unmarshal(data, &metadata); err != nil {
			t.Fatal(err)
		}
		verified, err := artifacts.Verify(metadata.ReleaseEnvelope, []ed25519.PublicKey{f.public}, time.Now(), artifacts.Checkpoint{})
		if err != nil || verified.Digest() != f.invitation.ReleaseDigest || metadata.ReleaseDigest != verified.Digest() || metadata.AvailableUses != 1 || metadata.Organization != "Test organization" || metadata.Artifact != f.invitation.Artifact {
			t.Fatal("metadata does not describe the signed approved target", err)
		}
		if strings.Contains(string(data), f.request.Invitation) || strings.Contains(string(data), "PRIVATE KEY") || strings.Contains(string(data), f.request.BrokerKey) {
			t.Fatal("public metadata exposed enrollment credentials")
		}
	}
	path := protocol.DownloadPath(f.invitation.ReleaseDigest, "windows", "amd64")
	for _, method := range []string{"HEAD", "GET"} {
		response, data := publicRequest(t, f.server.Client(), f.server.URL, method, path, nil, nil)
		if response.StatusCode != 200 || response.ContentLength != int64(len(f.content)) || !strings.Contains(response.Header.Get("Content-Disposition"), f.invitation.Artifact.Filename) {
			t.Fatal("approved package headers incorrect", response.StatusCode)
		}
		if method == "GET" && !bytes.Equal(data, f.content) {
			t.Fatal("download bytes differ from approved package")
		}
	}
	response, data := publicRequest(t, f.server.Client(), f.server.URL, "GET", path, nil, map[string]string{"Range": "bytes=3-8"})
	if response.StatusCode != 206 || !bytes.Equal(data, f.content[3:9]) {
		t.Fatal("single-range resume failed", response.StatusCode)
	}
	response, _ = publicRequest(t, f.server.Client(), f.server.URL, "GET", path, nil, map[string]string{"Range": "bytes=999999-"})
	if response.StatusCode != 416 {
		t.Fatal("out-of-bounds range accepted")
	}
	response, _ = publicRequest(t, f.server.Client(), f.server.URL, "GET", path, nil, map[string]string{"Range": "bytes=0-1,3-4"})
	if response.StatusCode != 400 {
		t.Fatal("multipart range amplification accepted")
	}
	var uses, identities int
	if err := f.store.db.QueryRow(`SELECT (SELECT uses FROM uem_agent_invitations WHERE id=$1),(SELECT count(*) FROM uem_agent_identities)`, f.invitation.ID).Scan(&uses, &identities); err != nil || uses != 0 || identities != 0 {
		t.Fatal("read-only request issued an identity", err)
	}
	packagePath := filepath.Join(f.directory, f.invitation.ReleaseDigest, f.invitation.Artifact.Filename)
	if err := os.WriteFile(packagePath, bytes.Repeat([]byte("x"), len(f.content)), 0644); err != nil {
		t.Fatal(err)
	}
	response, data = publicRequest(t, f.server.Client(), f.server.URL, "GET", path, nil, nil)
	if response.StatusCode != 503 || bytes.Contains(data, []byte(f.directory)) || bytes.Contains(data, []byte("xxxxxxxx")) {
		t.Fatal("changed package was served or leaked storage details")
	}
}

func TestPublicDesktopClaimsRejectAmbiguousBodiesAndRecoverOneIdentity(t *testing.T) {
	f := newPublicFixture(t)
	body, _ := json.Marshal(f.request)
	for _, tc := range []struct {
		name    string
		body    []byte
		headers map[string]string
		code    int
	}{
		{"missing media type", body, nil, 415},
		{"form body", body, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, 415},
		{"foreign origin", body, map[string]string{"Content-Type": "application/json", "Origin": "https://other.example.test"}, 403},
		{"null origin", body, map[string]string{"Content-Type": "application/json", "Origin": "null"}, 403},
		{"same-site cross-origin", body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-site"}, 403},
		{"oversized", bytes.Repeat([]byte("x"), maxClaimBody+1), map[string]string{"Content-Type": "application/json"}, 413},
		{"duplicate proof", append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"proof":"other"}`)...), map[string]string{"Content-Type": "application/json"}, 400},
		{"case alias", bytes.Replace(body, []byte(`"version"`), []byte(`"Version"`), 1), map[string]string{"Content-Type": "application/json"}, 400},
		{"trailing object", append(append([]byte(nil), body...), []byte(`{}`)...), map[string]string{"Content-Type": "application/json"}, 400},
		{"forged proof", bytes.Replace(body, []byte("Approved Windows endpoint"), []byte("Changed endpoint"), 1), map[string]string{"Content-Type": "application/json"}, 400},
		{"missing proof", []byte(`{}`), map[string]string{"Content-Type": "application/json"}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, data := publicRequest(t, f.server.Client(), f.server.URL, "POST", f.path("claim"), tc.body, tc.headers)
			if response.StatusCode != tc.code {
				t.Fatal("incorrect rejection", response.StatusCode, string(data))
			}
			if bytes.Contains(data, []byte(f.request.Invitation)) || bytes.Contains(data, []byte(f.request.CSR)) {
				t.Fatal("error reflected a credential")
			}
		})
	}
	var uses int
	if err := f.store.db.QueryRow(`SELECT uses FROM uem_agent_invitations WHERE id=$1`, f.invitation.ID).Scan(&uses); err != nil || uses != 0 {
		t.Fatal("rejected request consumed invitation", err)
	}
	var first enrollment.Response
	for i := 0; i < 2; i++ {
		response, data := publicRequest(t, f.server.Client(), f.server.URL, "POST", f.path("claim"), body, map[string]string{"Content-Type": "application/json", "Origin": "https://uem.example.test"})
		if response.StatusCode != 200 {
			t.Fatal("valid claim failed", response.StatusCode, string(data))
		}
		var issued enrollment.Response
		if err := json.Unmarshal(data, &issued); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = issued
		} else if issued != first {
			t.Fatal("same-key retry changed identity")
		}
		if issued.TenantID != 1 || issued.SiteID != 1 || issued.Endpoint != "wss://uem.example.test/agent-channel" || issued.Certificate == "" || bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Fatal("incorrect public identity response")
		}
	}
	response, data := publicRequest(t, f.server.Client(), f.server.URL, "GET", f.path("metadata"), nil, nil)
	var metadata InstallerMetadata
	if err := json.Unmarshal(data, &metadata); err != nil || response.StatusCode != 200 || metadata.AvailableUses != 0 {
		t.Fatal("used invitation lost recovery metadata", err)
	}
	if err := f.catalog.Withdraw(context.Background(), f.invitation.ReleaseDigest, "server-admin"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"metadata", "claim"} {
		method, payload := "GET", []byte(nil)
		if kind == "claim" {
			method, payload = "POST", body
		}
		response, _ = publicRequest(t, f.server.Client(), f.server.URL, method, f.path(kind), payload, map[string]string{"Content-Type": "application/json"})
		if response.StatusCode != 404 {
			t.Fatal("withdrawn release remained available", kind, response.StatusCode)
		}
	}
}

func publicTestIdentity(t *testing.T, name string) (tls.Certificate, []byte) {
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPublicDesktopThroughGatewayRejectsDirectAccessAndAdministratorAliases(t *testing.T) {
	f := newCatalogFixture(t)
	_, bootstrapKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bootstrapKey)
	invitation, claim := prepareInstallerInvitation(t, f)
	identity, bundle := publicTestIdentity(t, "gateway")
	device, _ := publicTestIdentity(t, "endpoint")
	policy, err := clientidentity.FromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, brokerEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "without broker", true: "with broker"}[brokerEnabled], func(t *testing.T) {
			h, err := NewPublicHandler(f.store, f.catalog, "https://uem.example.test", policy, bootstrapKey)
			if err != nil {
				t.Fatal(err)
			}
			backend := httptest.NewUnstartedServer(nil)
			backend.Config = h.Server("")
			backend.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Error("private TLS proxy did not exercise HTTP/2")
				}
				cert, err := policy.Certificate(r)
				if err != nil || cert.Subject.CommonName != "endpoint" {
					t.Error("desktop backend lost TLS-proven endpoint identity", err)
				}
				if r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("X-SSL-Client-Cert") != "" {
					t.Error("gateway preserved untrusted forwarding headers")
				}
				h.ServeHTTP(w, r)
			})
			backend.Config.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
			backend.TLS = backend.Config.TLSConfig.Clone()
			backend.EnableHTTP2 = true
			backend.StartTLS()
			defer func() { backend.CloseClientConnections(); h.Close(); backend.Close() }()
			roots := x509.NewCertPool()
			roots.AddCert(backend.Certificate())
			config := gateway.Config{PublicOrigin: "https://uem.example.test", AppleURL: backend.URL, ConsoleURL: backend.URL, AuthURL: backend.URL, DesktopURL: backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: roots}}
			if brokerEnabled {
				config.AgentURL = backend.URL
			}
			g, err := gateway.New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			server := httptest.NewUnstartedServer(g)
			server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
			server.StartTLS()
			defer server.Close()
			transport := server.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.Certificates = []tls.Certificate{device}
			client := &http.Client{Transport: transport}
			defer client.CloseIdleConnections()
			tokenPath := "/enroll/desktop/" + claim.Invitation
			for _, path := range []string{tokenPath + "/metadata", tokenPath + "/configuration", "/enroll/desktop/bootstrap-keys", protocol.DownloadPath(invitation.ReleaseDigest, "windows", "amd64")} {
				response, data := publicRequest(t, client, server.URL, "GET", path, nil, map[string]string{"Client-Cert": "forged", "X-SSL-Client-Cert": "forged", "X-Forwarded-For": "10.42.1.1"})
				if response.StatusCode != 200 {
					t.Fatal("public route failed through gateway", response.StatusCode, string(data))
				}
			}
			for _, path := range []string{"/login", "/desktop/enrollment", "/tenant/1/site/1/desktop/enrollment", "/desktop/setup", tokenPath, tokenPath + "/claim", tokenPath + "/metadata?token=other", tokenPath + "/metadata/", tokenPath + "/configuration/", "/enroll/desktop/bootstrap-keys?", "/enroll/desktop/releases/" + invitation.ReleaseDigest + "/windows/arm64/admin"} {
				response, _ := publicRequest(t, client, server.URL, "GET", path, nil, map[string]string{"X-Forwarded-For": "10.42.1.1"})
				if response.StatusCode != 403 {
					t.Fatal("unlisted public path reached a backend", response.StatusCode)
				}
			}
			// Knowing either a forwarded certificate or an endpoint private key
			// cannot authenticate directly to the gateway-pinned listener.
			for _, certs := range [][]tls.Certificate{nil, {device}} {
				tr := backend.Client().Transport.(*http.Transport).Clone()
				tr.TLSClientConfig.Certificates = certs
				direct := &http.Client{Transport: tr}
				r, _ := http.NewRequest("GET", backend.URL+tokenPath+"/metadata", nil)
				r.Host = "uem.example.test"
				r.Header.Set("Client-Cert", "forged")
				response, err := direct.Do(r)
				if err == nil {
					response.Body.Close()
					t.Error("direct unpinned backend connection succeeded")
				}
				direct.CloseIdleConnections()
			}
		})
	}
}

func TestPublicDesktopClaimConcurrencyIsBoundedAndShutdownCancelsDatabaseWaits(t *testing.T) {
	f := newPublicFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	blocker, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	var pid int
	if err = blocker.QueryRowContext(ctx, `SELECT pg_backend_pid() FROM uem_desktop_release_checkpoint WHERE id=1 FOR UPDATE`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(f.request)
	var requests sync.WaitGroup
	results := make(chan int, 4)
	for i := 0; i < 4; i++ {
		requests.Go(func() {
			r, _ := http.NewRequestWithContext(ctx, "POST", f.server.URL+f.path("claim"), bytes.NewReader(body))
			r.Host = "uem.example.test"
			r.Header.Set("Content-Type", "application/json")
			response, err := f.server.Client().Do(r)
			if err != nil {
				results <- 0
				return
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			results <- response.StatusCode
		})
	}
	defer func() { cancel(); blocker.Rollback(); requests.Wait() }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		if err := f.store.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, pid).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 4 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("claims did not reach the database lock")
		case <-ticker.C:
		}
	}
	response, _ := publicRequest(t, f.server.Client(), f.server.URL, "POST", f.path("claim"), body, map[string]string{"Content-Type": "application/json"})
	if response.StatusCode != 429 || response.Header.Get("Retry-After") == "" {
		t.Fatal("claim concurrency was not bounded")
	}
	closed := make(chan struct{})
	go func() { f.handler.Close(); close(closed) }()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("shutdown did not cancel and join database waits")
	}
	requests.Wait()
	for i := 0; i < 4; i++ {
		if code := <-results; code != 503 {
			t.Error("cancelled claim returned unexpected status", code)
		}
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_identities`).Scan(&count); err != nil || count != 0 {
		t.Fatal("cancelled claim left an identity", err)
	}
	response, _ = publicRequest(t, f.server.Client(), f.server.URL, "GET", f.path("metadata"), nil, nil)
	if response.StatusCode != 503 {
		t.Fatal("closed handler admitted another request")
	}
}

func TestHTTP2ClaimBodyDeadlineDoesNotResetCompletedBodyDuringIssuance(t *testing.T) {
	f := newPublicFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	blocker, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var requests sync.WaitGroup
	defer func() { cancel(); blocker.Rollback(); requests.Wait() }()
	var pid int
	if err = blocker.QueryRowContext(ctx, `SELECT pg_backend_pid() FROM uem_desktop_release_checkpoint WHERE id=1 FOR UPDATE`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(f.request)
	results := make(chan int, 1)
	requests.Go(func() {
		r, _ := http.NewRequestWithContext(ctx, "POST", f.server.URL+f.path("claim"), bytes.NewReader(body))
		r.Host = "uem.example.test"
		r.Header.Set("Content-Type", "application/json")
		response, err := f.server.Client().Do(r)
		if err != nil {
			results <- 0
			return
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		results <- response.StatusCode
	})
	_ = waitForBlockedConnection(t, ctx, f.store.db, pid)
	// The bounded body has already been read. Cross its real 10-second read
	// deadline while a database lock delays issuance within its 20-second bound.
	select {
	case code := <-results:
		t.Fatal("completed request body was reset while issuance waited", code)
	case <-time.After(10500 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal("test deadline reached before the body deadline")
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-results:
		if code != 200 {
			t.Fatal("valid HTTP/2 claim lost its response", code)
		}
	case <-ctx.Done():
		t.Fatal("claim did not complete after the lock was released")
	}
}

func TestPublicMetadataRejectsRevocationExpiryAndChangedSiteOwnership(t *testing.T) {
	f := newPublicFixture(t)
	for _, tc := range []struct{ name, change, restore string }{
		{"revoked invitation", `UPDATE uem_agent_invitations SET revoked_at=now()`, `UPDATE uem_agent_invitations SET revoked_at=NULL`},
		{"expired invitation", `UPDATE uem_agent_invitations SET expires_at=now()-interval '1 minute'`, `UPDATE uem_agent_invitations SET expires_at=now()+interval '10 minutes'`},
		{"moved site", `UPDATE sites SET tenant_sites=2 WHERE id=1`, `UPDATE sites SET tenant_sites=1 WHERE id=1`},
		{"expired authority", `UPDATE uem_agent_authorities SET expires_at=now()-interval '1 minute' WHERE tenant_id=1`, `UPDATE uem_agent_authorities SET expires_at=now()+interval '1 day' WHERE tenant_id=1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.store.db.Exec(tc.change); err != nil {
				t.Fatal(err)
			}
			response, _ := publicRequest(t, f.server.Client(), f.server.URL, "GET", f.path("metadata"), nil, nil)
			if response.StatusCode != 404 {
				t.Fatal("inactive invitation metadata remained available", response.StatusCode)
			}
			if _, err := f.store.db.Exec(tc.restore); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := f.catalog.Withdraw(context.Background(), f.invitation.ReleaseDigest, "server-admin"); err != nil {
		t.Fatal(err)
	}
	response, _ := publicRequest(t, f.server.Client(), f.server.URL, "GET", protocol.DownloadPath(f.invitation.ReleaseDigest, "windows", "amd64"), nil, nil)
	if response.StatusCode != 404 {
		t.Fatal("withdrawn package remained downloadable")
	}
}

func TestPublicLimiterUsesAuthenticatedSourcesAndBoundsIPv6Buckets(t *testing.T) {
	identity, bundle := publicTestIdentity(t, "gateway")
	policy, err := clientidentity.FromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	newLimiter := func() *PublicHandler {
		return &PublicHandler{identity: policy, clients: make(map[netip.Addr]publicBucket), global: rate.NewLimiter(rate.Inf, 1)}
	}
	h := newLimiter()
	r := httptest.NewRequest("GET", "https://uem.example.test/", nil)
	r.RemoteAddr = "198.51.100.1:4200"
	for i := 0; i < 30; i++ {
		r.Header.Set("X-Forwarded-For", netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}).String())
		if !h.allow(r) {
			t.Fatal("source burst was rejected early")
		}
	}
	if h.allow(r) || len(h.clients) != 1 {
		t.Fatal("untrusted forwarding headers bypassed source limits")
	}
	h = newLimiter()
	r.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{identity.Leaf}}
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::ffff"} {
		r.Header.Set("X-Forwarded-For", ip)
		if !h.allow(r) {
			t.Fatal("pinned gateway source was rejected")
		}
	}
	if len(h.clients) != 1 {
		t.Fatal("IPv6 address rotation created separate /64 buckets")
	}
	for _, source := range []string{"203.0.113.1, 203.0.113.2", "", "fe80::1%eth0"} {
		r.Header.Set("X-Forwarded-For", source)
		if h.allow(r) {
			t.Fatal("ambiguous gateway source was accepted")
		}
	}
	h = newLimiter()
	for i := 0; i < 4096; i++ {
		h.clients[netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})] = publicBucket{last: time.Now(), limiter: rate.NewLimiter(2, 30)}
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	if h.allow(r) || len(h.clients) != 4096 {
		t.Fatal("unbounded source map admitted another address")
	}
	for key, bucket := range h.clients {
		bucket.last = time.Now().Add(-6 * time.Minute)
		h.clients[key] = bucket
	}
	if !h.allow(r) || len(h.clients) != 1 {
		t.Fatal("idle source buckets were not reclaimed")
	}
}

func TestClaimDecoderRejectsMalformedAndAmbiguousJSON(t *testing.T) {
	valid := []byte(`{"version":1,"invitation":"token","platform":"windows","architecture":"amd64","device_name":"Name","csr":"csr","broker_key":"key","proof":"proof"}`)
	if _, err := decodeClaim(valid); err != nil {
		t.Fatal("well-formed wire object did not decode")
	}
	for _, data := range [][]byte{
		[]byte(`null`), []byte(`[]`), []byte(`{"version":1`), append(append([]byte(nil), valid...), []byte(`null`)...),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1.0`), 1),
		bytes.Replace(valid, []byte(`"device_name":"Name"`), []byte(`"device_name":null`), 1),
		bytes.Replace(valid, []byte(`"device_name":"Name"`), []byte(`"device_name":[]`), 1),
		bytes.Replace(valid, []byte(`"proof":"proof"`), []byte(`"proof":"proof","\u0070roof":"other"`), 1),
		bytes.Replace(valid, []byte(`"proof":"proof"`), []byte(`"proof":"proof","unknown":1`), 1),
		bytes.Replace(valid, []byte(`Name`), []byte{0xff}, 1),
	} {
		if _, err := decodeClaim(data); err == nil {
			t.Fatal("malformed claim was accepted")
		}
	}
}
