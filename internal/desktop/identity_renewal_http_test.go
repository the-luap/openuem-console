package desktop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

type renewalPublicFixture struct {
	*catalogTestFixture
	server, backend    *httptest.Server
	handler            *PublicHandler
	client             *enrollment.HTTPClient
	roots              *x509.CertPool
	source             enrollment.RenewalSource
	current, candidate *enrollment.Keys
	request            *enrollment.RenewalRequest
	invitation         *registry.Invitation
	loseConfirmation   atomic.Bool
	loseResolution     atomic.Bool
	backendRequests    atomic.Int64
}

type renewalCapture struct {
	http.ResponseWriter
	body   bytes.Buffer
	status int
}

func (w *renewalCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *renewalCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *renewalCapture) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(data)
}

func newRenewalPublicFixture(t *testing.T, throughGateway, due bool) *renewalPublicFixture {
	t.Helper()
	return newRenewalPublicTargetFixture(t, throughGateway, due, "windows")
}

func newRenewalPublicTargetFixture(t *testing.T, throughGateway, due bool, platform string) *renewalPublicFixture {
	t.Helper()
	f := &renewalPublicFixture{catalogTestFixture: newCatalogFixture(t)}
	f.server = httptest.NewUnstartedServer(nil)
	origin := "https://" + f.server.Listener.Addr().String()
	if _, err := f.store.db.Exec(`INSERT INTO tenants VALUES(3); INSERT INTO sites(id,tenant_sites) VALUES(4,3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Registry.EnsureAuthority(t.Context(), 3, "Renewal HTTP fixture", origin, "fixture-admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	var err error
	f.invitation, err = f.store.Registry.Invite(t.Context(), registry.InvitationOptions{Scope: registry.Scope{TenantID: 3, SiteID: 4}, Platform: platform, Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	f.current, err = enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.current.Broker.Wipe)
	f.candidate, err = enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.candidate.Broker.Wipe)
	token := f.invitation.URL[strings.LastIndex(f.invitation.URL, "/")+1:]
	claim, err := f.current.Request(token, platform, "amd64", "Existing renewal fixture")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.store.Registry.Claim(t.Context(), *claim)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := enrollment.ValidateResponse(*issued, origin, &f.current.Certificate.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if due {
		cert = shortenRenewalPublicCertificate(t, f, cert)
	}
	broker, _ := f.current.Broker.PublicKey()
	f.source = enrollment.RenewalSource{DeviceID: issued.DeviceID, TenantID: 3, SiteID: 4, Origin: origin, Platform: platform, Architecture: "amd64", BrokerKey: broker, Certificate: cert.Raw}
	f.request, err = enrollment.NewRenewalRequest(f.source, f.current, f.candidate, uuid.NewString(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Renewal of an existing identity must not depend on a still-valid invitation
	// or an approved installer. This catalog intentionally contains no release.
	if err := f.store.Registry.RevokeInvitation(t.Context(), registry.Scope{TenantID: 3, SiteID: 4}, f.invitation.ID, "fixture-admin"); err != nil {
		t.Fatal(err)
	}
	var policy clientidentity.Policy
	var gatewayIdentity tls.Certificate
	if throughGateway {
		var bundle []byte
		gatewayIdentity, bundle = publicTestIdentity(t, "renewal-gateway")
		policy, err = clientidentity.FromPEM(bundle)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.handler, err = NewPublicHandler(f.store, f.catalog, origin, policy)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.backendRequests.Add(1)
		if throughGateway && (r.ProtoMajor != 2 || !policy.IsGateway(r) || r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("Client-Cert") != "" || r.Header.Get("X-SSL-Client-Cert") != "") {
			t.Error("renewal gateway lost its pinned transport or retained forged identity headers")
		}
		if strings.HasSuffix(r.URL.Path, "/renewal/resolve") && f.loseResolution.Load() {
			capture := &renewalCapture{ResponseWriter: w}
			f.handler.ServeHTTP(capture, r)
			if capture.status == 200 && f.loseResolution.Swap(false) {
				w.Header().Del("Content-Length")
				http.Error(w, "synthetic lost resolution acknowledgement", 503)
				return
			}
			w.WriteHeader(capture.status)
			w.Write(capture.body.Bytes())
			return
		}
		if strings.HasSuffix(r.URL.Path, "/renewal/confirm") && f.loseConfirmation.Load() {
			capture := &renewalCapture{ResponseWriter: w}
			f.handler.ServeHTTP(capture, r)
			if capture.status == 200 && f.loseConfirmation.Swap(false) {
				w.Header().Del("Content-Length")
				http.Error(w, "synthetic lost confirmation acknowledgement", 503)
				return
			}
			w.WriteHeader(capture.status)
			w.Write(capture.body.Bytes())
			return
		}
		f.handler.ServeHTTP(w, r)
	})
	var g *gateway.Gateway
	if throughGateway {
		f.backend = httptest.NewUnstartedServer(wrapped)
		f.backend.Config = f.handler.Server("")
		f.backend.Config.Handler = wrapped
		f.backend.Config.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
		f.backend.TLS = f.backend.Config.TLSConfig.Clone()
		f.backend.EnableHTTP2 = true
		f.backend.StartTLS()
		roots := x509.NewCertPool()
		roots.AddCert(f.backend.Certificate())
		g, err = gateway.New(gateway.Config{PublicOrigin: origin, AppleURL: f.backend.URL, ConsoleURL: f.backend.URL, AuthURL: f.backend.URL, DesktopURL: f.backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{gatewayIdentity}, RootCAs: roots}})
		if err != nil {
			t.Fatal(err)
		}
		f.server.Config.Handler = g
	} else {
		f.server.Config = f.handler.Server("")
		f.server.Config.Handler = wrapped
		f.server.Config.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
		f.server.TLS = f.server.Config.TLSConfig.Clone()
	}
	f.server.EnableHTTP2 = true
	f.server.StartTLS()
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.server.Certificate())
	f.client, err = enrollment.NewHTTPClient(origin, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.client.CloseIdleConnections()
		f.server.CloseClientConnections()
		f.server.Close()
		if g != nil {
			g.Close()
		}
		f.handler.Close()
		if f.backend != nil {
			f.backend.CloseClientConnections()
			f.backend.Close()
		}
	})
	return f
}

func shortenRenewalPublicCertificate(t *testing.T, f *renewalPublicFixture, original *x509.Certificate) *x509.Certificate {
	t.Helper()
	// Only this owned fixture accesses its own CA key to issue a genuinely due
	// certificate; expiry metadata alone would not exercise the renewal proof.
	var authority, encrypted []byte
	if err := f.store.db.QueryRow(`SELECT certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=3`).Scan(&authority, &encrypted); err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("openuem/agent-registry/secrets/v1\x00isolated-desktop-metadata-master-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(encrypted) < aead.NonceSize() {
		t.Fatal("invalid fixture encryption")
	}
	private, err := aead.Open(nil, encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():], []byte("3/authority/key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	caBlock, _ := pem.Decode(authority)
	keyBlock, _ := pem.Decode(private)
	if caBlock == nil || keyBlock == nil {
		t.Fatal("invalid fixture issuer")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	clear(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		t.Fatal("fixture issuer cannot sign")
	}
	leaf := *original
	leaf.SerialNumber = big.NewInt(42)
	leaf.NotAfter = time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &leaf, ca, &f.current.Certificate.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(der)
	if _, err := f.store.db.Exec(`UPDATE uem_agent_identities SET certificate=$2,certificate_hash=$3,certificate_expires_at=$4 WHERE id=$1`, leaf.Subject.CommonName, der, hex.EncodeToString(hash[:]), leaf.NotAfter); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestNativeIdentityRenewalThroughHTTPSAndPinnedGatewayRecoversLostCommitReply(t *testing.T) {
	for _, proxied := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct HTTPS", true: "pinned gateway"}[proxied], func(t *testing.T) {
			f := newRenewalPublicFixture(t, proxied, true)
			var first *enrollment.PreparedIdentityRenewal
			for range 2 {
				prepared, err := f.client.PrepareIdentityRenewal(t.Context(), *f.request, f.source)
				if err != nil {
					t.Fatal("HTTPS renewal preparation failed", err)
				}
				if first == nil {
					first = prepared
				} else if !reflect.DeepEqual(first, prepared) {
					t.Fatal("HTTPS retry changed issuance")
				}
			}
			target, err := enrollment.ValidatePreparedIdentityRenewal(*first, *f.request, f.source, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			confirmation, err := enrollment.NewRenewalConfirmation(*target, f.candidate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			f.loseConfirmation.Store(true)
			if _, err := f.client.ConfirmIdentityRenewal(t.Context(), *confirmation, *target); !errors.Is(err, enrollment.ErrEnrollmentBusy) {
				t.Fatal("lost acknowledgement did not remain ambiguous", err)
			}
			var records int
			if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_identity_renewal_confirmations WHERE id=$1`, first.ID).Scan(&records); err != nil || records != 1 {
				t.Fatal("fixture did not commit before losing reply", err)
			}
			restarted, err := enrollment.NewHTTPClient(f.source.Origin, f.roots)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.CloseIdleConnections()
			fresh, err := enrollment.NewRenewalConfirmation(*target, f.candidate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			results := make(chan *enrollment.ConfirmedIdentityRenewal, 2)
			failures := make(chan error, 2)
			for range 2 {
				wg.Go(func() {
					r, err := restarted.ConfirmIdentityRenewal(t.Context(), *fresh, *target)
					if err != nil {
						failures <- err
					} else {
						results <- r
					}
				})
			}
			wg.Wait()
			close(results)
			close(failures)
			for err := range failures {
				t.Fatal(err)
			}
			var confirmed *enrollment.ConfirmedIdentityRenewal
			for r := range results {
				if confirmed == nil {
					confirmed = r
				} else if *confirmed != *r {
					t.Fatal("restart changed committed confirmation")
				}
			}
			if confirmed == nil || confirmed.DeviceID != f.source.DeviceID {
				t.Fatal("renewal lost original device")
			}
			if _, err := restarted.PrepareIdentityRenewal(t.Context(), *f.request, f.source); !errors.Is(err, enrollment.ErrIdentityRenewalDenied) {
				t.Fatal("retired source proof remained authorized", err)
			}
			access, _ := registry.NewAccessStore(f.store.db)
			old, _ := x509.ParseCertificate(f.source.Certificate)
			candidate, _ := x509.ParseCertificate(target.Candidate.Certificate)
			if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, old); !errors.Is(err, registry.ErrDenied) {
				t.Fatal("retired certificate remained active", err)
			}
			if _, err := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, candidate); err != nil {
				t.Fatal("candidate not activated", err)
			}
			var identities, uses, audits int
			if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identities),(SELECT uses FROM uem_agent_invitations WHERE id=$1),(SELECT count(*) FROM uem_agent_audit WHERE action='agent.identity.renew.confirm')`, f.invitation.ID).Scan(&identities, &uses, &audits); err != nil || identities != 1 || uses != 1 || audits != 1 {
				t.Fatal("renewal duplicated enrollment or audit", err)
			}
		})
	}
}

func TestPublicIdentityRenewalRejectsMalformedScopeAndBrowserRequests(t *testing.T) {
	f := newRenewalPublicFixture(t, false, true)
	body, _ := json.Marshal(f.request)
	path := enrollment.IdentityRenewalPath(f.source.DeviceID, "prepare")
	for _, tc := range []struct {
		name, method, path string
		body               []byte
		headers            map[string]string
		status             int
	}{
		{"method", "GET", path, nil, nil, 404},
		{"path device", "POST", enrollment.IdentityRenewalPath(uuid.NewString(), "prepare"), body, nil, 400},
		{"query", "POST", path + "?", body, nil, 404},
		{"foreign browser", "POST", path, body, map[string]string{"Origin": "https://other.example.test"}, 403},
		{"cross-site fetch", "POST", path, body, map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"bearer", "POST", path, body, map[string]string{"Authorization": "Bearer untrusted"}, 400},
		{"compressed", "POST", path, body, map[string]string{"Content-Encoding": "gzip"}, 400},
		{"media type", "POST", path, body, map[string]string{"Content-Type": "text/plain"}, 415},
		{"oversized", "POST", path, bytes.Repeat([]byte("x"), enrollment.MaxRenewalRequestBytes+1), nil, 413},
		{"confirmation bound", "POST", enrollment.IdentityRenewalPath(f.source.DeviceID, "confirm"), bytes.Repeat([]byte("x"), enrollment.MaxRenewalConfirmationBytes+1), nil, 413},
		{"unknown field", "POST", path, append(bytes.Clone(body[:len(body)-1]), []byte(`,"unknown":true}`)...), nil, 400},
		{"null", "POST", path, []byte(`null`), nil, 400},
		{"forged proof header", "POST", path, []byte(`{}`), map[string]string{"Client-Cert": "forged", "X-Forwarded-For": "10.42.1.1"}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(tc.method, f.server.URL+tc.path, bytes.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			response, err := f.server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != tc.status || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("invalid renewal crossed HTTP boundary", response.StatusCode)
			}
			if bytes.Contains(data, []byte(f.request.RequestID)) || bytes.Contains(data, []byte("PRIVATE KEY")) {
				t.Fatal("renewal error exposed request details")
			}
		})
	}
	var count int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM uem_agent_identity_renewals`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied request persisted renewal", err)
	}
}

func TestPublicIdentityRenewalReturnsBoundedNotDueConflict(t *testing.T) {
	f := newRenewalPublicFixture(t, false, false)
	if _, err := f.client.PrepareIdentityRenewal(t.Context(), *f.request, f.source); !errors.Is(err, enrollment.ErrIdentityRenewalNotDue) {
		t.Fatal("fresh identity did not receive typed due-window result", err)
	}
}

func (f *renewalPublicFixture) raw(t *testing.T, method, path string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	response, err := f.server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, data
}

func TestPublicIdentityRenewalGatewayRejectsAliasesAndUnpinnedBackend(t *testing.T) {
	f := newRenewalPublicFixture(t, true, true)
	body, _ := json.Marshal(f.request)
	for _, operation := range []string{"prepare", "confirm", "resolve"} {
		path := enrollment.IdentityRenewalPath(f.source.DeviceID, operation)
		for _, method := range []string{"GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			response, _ := f.raw(t, method, path, nil, map[string]string{"X-Forwarded-For": "10.42.1.1"})
			if response.StatusCode != 403 {
				t.Fatal("gateway accepted a nonpublic renewal method", method, response.StatusCode)
			}
		}
		for _, invalid := range []string{path + "/", path + "?", path + "?device=other", path + "/admin", strings.Replace(path, "identities", "identit%69es", 1), strings.Replace(path, "/renewal/", "//renewal/", 1), "/desktop/enrollment", "/login"} {
			response, _ := f.raw(t, "POST", invalid, body, map[string]string{"X-Forwarded-For": "10.42.1.1"})
			status := 403
			if strings.Contains(invalid, "%") || strings.Contains(invalid, "//") {
				status = 400
			}
			if response.StatusCode != status {
				t.Fatal("gateway accepted a nonpublic renewal path", response.StatusCode)
			}
		}
	}
	if f.backendRequests.Load() != 0 {
		t.Fatal("denied gateway request reached a backend")
	}
	path := enrollment.IdentityRenewalPath(f.source.DeviceID, "prepare")
	forged := map[string]string{"Client-Cert": "forged", "X-SSL-Client-Cert": "forged", "X-Forwarded-For": "10.42.1.1", "X-Forwarded-Host": "other.example.test"}
	response, _ := f.raw(t, "POST", path, []byte(`{}`), forged)
	if response.StatusCode != 400 || f.backendRequests.Load() != 1 {
		t.Fatal("forwarded headers substituted for a signed renewal proof")
	}
	// Even a valid application proof cannot bypass the private listener's pinned
	// gateway identity. Test no client certificate and an unrelated endpoint key.
	endpoint, _ := publicTestIdentity(t, "untrusted-endpoint")
	for _, certs := range [][]tls.Certificate{nil, {endpoint}} {
		tr := f.backend.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = certs
		client := &http.Client{Transport: tr}
		r, _ := http.NewRequestWithContext(t.Context(), "POST", f.backend.URL+path, bytes.NewReader(body))
		r.Host = f.server.Listener.Addr().String()
		r.Header.Set("Content-Type", "application/json")
		for k, v := range forged {
			r.Header.Set(k, v)
		}
		response, err := client.Do(r)
		if err == nil {
			response.Body.Close()
			t.Error("direct unpinned renewal reached the private listener")
		}
		client.CloseIdleConnections()
	}
	if f.backendRequests.Load() != 1 {
		t.Fatal("unpinned TLS handshake admitted a renewal handler")
	}
	response, data := f.raw(t, "POST", path, body, forged)
	if response.StatusCode != 200 {
		t.Fatal("valid key proof failed after forged headers were removed", response.StatusCode)
	}
	prepared, err := enrollment.DecodePreparedIdentityRenewal(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.ValidatePreparedIdentityRenewal(*prepared, *f.request, f.source, time.Now()); err != nil {
		t.Fatal("gateway response lost its candidate binding", err)
	}
}

func TestPublicIdentityRenewalConcurrencyIsBoundedAndShutdownCancelsDatabaseWaits(t *testing.T) {
	for _, operation := range []string{"prepare", "confirm", "resolve"} {
		t.Run(operation, func(t *testing.T) {
			f := newRenewalPublicFixture(t, false, true)
			body, _ := json.Marshal(f.request)
			preparations := 0
			if operation != "prepare" {
				prepared, err := f.client.PrepareIdentityRenewal(t.Context(), *f.request, f.source)
				if err != nil {
					t.Fatal(err)
				}
				target, err := enrollment.ValidatePreparedIdentityRenewal(*prepared, *f.request, f.source, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				confirmation, err := enrollment.NewRenewalConfirmation(*target, f.candidate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				body, _ = json.Marshal(confirmation)
				if operation == "resolve" {
					resolution, err := enrollment.NewRenewalResolution(*target, f.candidate, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					body, _ = json.Marshal(resolution)
				}
				preparations = 1
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			blocker, err := f.store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			var pid int
			if err = blocker.QueryRowContext(ctx, `SELECT pg_backend_pid() FROM uem_agent_identities WHERE id=$1 FOR UPDATE`, f.source.DeviceID).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			path := enrollment.IdentityRenewalPath(f.source.DeviceID, operation)
			var requests sync.WaitGroup
			results := make(chan int, 4)
			for range 4 {
				requests.Go(func() {
					r, _ := http.NewRequestWithContext(ctx, "POST", f.server.URL+path, bytes.NewReader(body))
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
				// Include tuple-lock waiters queued behind another renewal, not just
				// connections waiting directly on the fixture's transaction lock.
				err := f.store.db.QueryRowContext(ctx, `WITH RECURSIVE blocked(pid) AS (
				 SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
				 UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid))
				) SELECT count(*) FROM blocked`, pid).Scan(&count)
				if err != nil {
					t.Fatal(err)
				}
				if count == 4 {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("renewals did not reach the database lock")
				case <-ticker.C:
				}
			}
			response, _ := f.raw(t, "POST", path, body, nil)
			if response.StatusCode != 429 || response.Header.Get("Retry-After") == "" {
				t.Fatal("renewal concurrency was not bounded", response.StatusCode)
			}
			closed := make(chan struct{})
			go func() { f.handler.Close(); close(closed) }()
			select {
			case <-closed:
			case <-ctx.Done():
				t.Fatal("shutdown did not cancel and join waiting renewals")
			}
			requests.Wait()
			for range 4 {
				if code := <-results; code != 503 {
					t.Error("cancelled renewal returned an unexpected status", code)
				}
			}
			if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			f.assertUnchanged(t, preparations)
			response, _ = f.raw(t, "POST", path, body, nil)
			if response.StatusCode != 503 {
				t.Fatal("closed handler admitted another renewal")
			}
		})
	}
}

func (f *renewalPublicFixture) assertUnchanged(t *testing.T, preparations int) {
	t.Helper()
	var issued, confirmed, cancelled, audits, reservations int
	var hash string
	err := f.store.db.QueryRow(`SELECT
	 (SELECT count(*) FROM uem_agent_identity_renewals),
	 (SELECT count(*) FROM uem_agent_identity_renewal_confirmations),
	 (SELECT count(*) FROM uem_agent_identity_renewal_cancellations),
	 (SELECT count(*) FROM uem_agent_audit WHERE action LIKE 'agent.identity.renew.%'),
	 (SELECT count(*) FROM uem_agent_key_reservations),
	 certificate_hash FROM uem_agent_identities WHERE id=$1`, f.source.DeviceID).Scan(&issued, &confirmed, &cancelled, &audits, &reservations, &hash)
	if err != nil || issued != preparations || confirmed != 0 || cancelled != 0 || audits != preparations || reservations != 2+2*preparations || hash != f.request.SourceCertificateHash {
		t.Fatal("failed renewal changed issuance, activation, audit or key ownership", issued, confirmed, audits, reservations, err)
	}
}

func (f *renewalPublicFixture) prepareConfirmation(t *testing.T) (*enrollment.RenewalConfirmationTarget, *enrollment.RenewalConfirmation) {
	t.Helper()
	prepared, err := f.client.PrepareIdentityRenewal(t.Context(), *f.request, f.source)
	if err != nil {
		t.Fatal(err)
	}
	target, err := enrollment.ValidatePreparedIdentityRenewal(*prepared, *f.request, f.source, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := enrollment.NewRenewalConfirmation(*target, f.candidate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return target, confirmation
}

func TestPublicIdentityRenewalProofsPendingAndCurrentAuthorization(t *testing.T) {
	f := newRenewalPublicFixture(t, false, true)
	target, confirmation := f.prepareConfirmation(t)
	other, err := enrollment.NewRenewalRequest(f.source, f.current, f.candidate, uuid.NewString(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.PrepareIdentityRenewal(t.Context(), *other, f.source); !errors.Is(err, enrollment.ErrIdentityRenewalPending) {
		t.Fatal("second request did not receive the pending conflict", err)
	}
	for _, operation := range []string{"prepare", "confirm", "resolve"} {
		body, _ := json.Marshal(f.request)
		if operation == "confirm" {
			body, _ = json.Marshal(confirmation)
		}
		if operation == "resolve" {
			resolution, err := enrollment.NewRenewalResolution(*target, f.candidate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			body, _ = json.Marshal(resolution)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"certificate_proof", "source_broker_proof", "candidate_broker_proof", "broker_proof"} {
			original, exists := fields[name]
			if !exists {
				continue
			}
			var encoded string
			json.Unmarshal(original, &encoded)
			proof, _ := base64.RawURLEncoding.DecodeString(encoded)
			proof[0] ^= 1
			fields[name], _ = json.Marshal(base64.RawURLEncoding.EncodeToString(proof))
			malformed, _ := json.Marshal(fields)
			response, data := f.raw(t, "POST", enrollment.IdentityRenewalPath(f.source.DeviceID, operation), malformed, map[string]string{"Client-Cert": "forged"})
			if response.StatusCode != 404 || string(data) != "identity renewal is unavailable\n" {
				t.Fatal("invalid possession proof escaped the fixed denial", operation, name, response.StatusCode)
			}
			fields[name] = original
		}
	}
	f.assertUnchanged(t, 1)
	if _, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=1 WHERE id=4`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.ConfirmIdentityRenewal(t.Context(), *confirmation, *target); !errors.Is(err, enrollment.ErrIdentityRenewalDenied) {
		t.Fatal("scope movement did not revoke candidate activation", err)
	}
	if _, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=3 WHERE id=4`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Registry.RevokeIdentity(t.Context(), registry.Scope{TenantID: 3, SiteID: 4}, f.source.DeviceID, "fixture-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.PrepareIdentityRenewal(t.Context(), *f.request, f.source); !errors.Is(err, enrollment.ErrIdentityRenewalDenied) {
		t.Fatal("revocation did not deny preparation retry", err)
	}
	if _, err := f.client.ConfirmIdentityRenewal(t.Context(), *confirmation, *target); !errors.Is(err, enrollment.ErrIdentityRenewalDenied) {
		t.Fatal("revocation did not deny candidate activation", err)
	}
	f.assertUnchanged(t, 1)
}

func TestPublicIdentityRenewalAuditFailureRollsBackBeforeResponse(t *testing.T) {
	for _, operation := range []string{"prepare", "confirm", "resolve"} {
		t.Run(operation, func(t *testing.T) {
			f := newRenewalPublicFixture(t, false, true)
			body, _ := json.Marshal(f.request)
			preparations := 0
			if operation != "prepare" {
				target, confirmation := f.prepareConfirmation(t)
				body, _ = json.Marshal(confirmation)
				if operation == "resolve" {
					resolution, err := enrollment.NewRenewalResolution(*target, f.candidate, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					body, _ = json.Marshal(resolution)
				}
				preparations = 1
			}
			action := operation
			if operation == "resolve" {
				action = "cancel"
			}
			if _, err := f.store.db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT renewal_fixture_audit_failure CHECK(action!='agent.identity.renew.` + action + `')`); err != nil {
				t.Fatal(err)
			}
			path := enrollment.IdentityRenewalPath(f.source.DeviceID, operation)
			for range 2 {
				response, data := f.raw(t, "POST", path, body, nil)
				if response.StatusCode != 503 || string(data) != "service temporarily unavailable\n" {
					t.Fatal("failed audit exposed issuance or internal diagnostics", response.StatusCode)
				}
				f.assertUnchanged(t, preparations)
			}
			if _, err := f.store.db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT renewal_fixture_audit_failure`); err != nil {
				t.Fatal(err)
			}
			response, _ := f.raw(t, "POST", path, body, nil)
			if response.StatusCode != 200 {
				t.Fatal("same retained request could not recover after audit restoration", response.StatusCode)
			}
		})
	}
}

func TestPublicIdentityRenewalPreservesDeliveredRecoveryUntilSignedCompletion(t *testing.T) {
	for _, resolve := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirm after completion", true: "cancel before completion"}[resolve], func(t *testing.T) {
			f := newRenewalPublicTargetFixture(t, true, true, "macos")
			target, confirmation := f.prepareConfirmation(t)
			access, err := registry.NewAccessStore(f.store.db)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := access.ActiveIdentity(t.Context(), f.source.DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			cert, _ := x509.ParseCertificate(f.source.Certificate)
			key, err := enrollment.NewRecoveryRecipientKey()
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			reply, err := access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "challenge", PublicKey: key.PublicKey()})
			if err != nil || reply.Registration == nil {
				t.Fatal("fixture registration challenge failed", err)
			}
			signature, err := enrollment.SignRecoveryRegistration(*reply.Registration, cert, f.current.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			reply, err = access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "register", Registration: reply.Registration, Signature: signature})
			if err != nil || reply.Recipient == nil {
				t.Fatal("fixture recovery registration failed", err)
			}
			recipient := reply.Recipient
			context := enrollment.RecoveryContext{Version: 1, Identity: recipient.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: recipient.ID, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
			nonce := bytes.Repeat([]byte{8}, 32)
			task, err := enrollment.EncryptRecoveryTask(*recipient, context, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			tx, err := f.store.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, _, err := access.RecoveryRecipient(t.Context(), tx, identity.Scope, identity.ID); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(nonce)
			if err := access.QueueRecoveryTask(t.Context(), tx, *task, hex.EncodeToString(hash[:])); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			reply, err = access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "poll", RecipientID: recipient.ID})
			if err != nil || reply.Task == nil || reply.Task.Context != task.Context {
				t.Fatal("fixture recovery task was not delivered", err)
			}
			if _, err := f.client.ConfirmIdentityRenewal(t.Context(), *confirmation, *target); !errors.Is(err, enrollment.ErrIdentityRenewalRecoveryPending) {
				t.Fatal("delivered recovery did not return its typed renewal conflict", err)
			}
			f.assertUnchanged(t, 1)
			if resolve {
				resolution, err := enrollment.NewRenewalResolution(*target, f.candidate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				outcome, err := f.client.ResolveIdentityRenewal(t.Context(), *resolution, *target, f.source)
				if err != nil || outcome.Outcome != "cancelled" {
					t.Fatal("resolution did not recover original recovery authority", err)
				}
				var unchanged bool
				if err := f.store.db.QueryRow(`SELECT t.status='pending' AND t.delivered_at IS NOT NULL AND r.id=$2 FROM uem_agent_recovery_tasks t JOIN uem_agent_recovery_recipients r ON r.device_id=t.device_id WHERE t.id=$1`, task.Context.TaskID, recipient.ID).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("resolution retired delivered recovery or its recipient", err)
				}
			}
			secret, err := key.Open(*task, recipient.Identity, recipient.ID, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Close()
			result, err := secret.Result("invalid", cert, f.current.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := access.HandleRecovery(t.Context(), *identity, enrollment.RecoveryRequest{Version: 1, AgentID: identity.ID, Action: "result", Result: result}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.client.ConfirmIdentityRenewal(t.Context(), *confirmation, *target); (resolve && !errors.Is(err, enrollment.ErrIdentityRenewalDenied)) || (!resolve && err != nil) {
				t.Fatal("recovery completion changed the retained renewal decision", err)
			}
			var retained bool
			if err := f.store.db.QueryRow(`SELECT status='completed' AND octet_length(result)>0 FROM uem_agent_recovery_tasks WHERE id=$1`, task.Context.TaskID).Scan(&retained); err != nil || !retained {
				t.Fatal("activation discarded the completed recovery receipt", err)
			}
		})
	}
}
