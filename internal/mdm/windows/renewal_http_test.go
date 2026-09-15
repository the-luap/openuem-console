package windows

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/mdm/windows/protocol"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestWSTEPRenewalRealTLSAndGateway(t *testing.T) {
	for _, viaGateway := range []bool{false, true} {
		t.Run(strconv.FormatBool(viaGateway), func(t *testing.T) {
			s := authorityTestStore(t)
			issuerOptions := authorityTestOptions()
			issuerOptions.ValiditySeconds, issuerOptions.RenewalSeconds = 86400, 86399
			if _, err := s.InitializeAuthority(t.Context(), "admin", 1, issuerOptions); err != nil {
				t.Fatal(err)
			}
			front := httptest.NewUnstartedServer(nil)
			t.Cleanup(front.Close)
			options := protocolTestOptions("https://" + front.Listener.Addr().String())
			enrollment, err := options.EnrollmentOptions()
			if err != nil {
				t.Fatal(err)
			}
			policy := clientidentity.Policy{}
			var gatewayCertificate tls.Certificate
			if viaGateway {
				gatewayCertificate, policy = protocolTestGatewayIdentity(t)
			}
			public, err := NewProtocolHandler(s, options, policy)
			if err != nil {
				t.Fatal(err)
			}
			var active atomic.Pointer[ProtocolHandler]
			active.Store(public)
			dispatcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { active.Load().ServeHTTP(w, r) })
			var serve http.Handler = dispatcher
			if viaGateway {
				backend := httptest.NewUnstartedServer(nil)
				backend.Config = public.Server(backend.Listener.Addr().String())
				backend.Config.Handler = dispatcher
				backend.TLS = backend.Config.TLSConfig
				backend.StartTLS()
				t.Cleanup(backend.Close)
				roots := x509.NewCertPool()
				roots.AddCert(backend.Certificate())
				g, err := gateway.New(gateway.Config{PublicOrigin: options.PublicOrigin, AppleURL: backend.URL, ConsoleURL: backend.URL, AuthURL: backend.URL, WindowsURL: backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{gatewayCertificate}, RootCAs: roots}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = g.Close() })
				serve = g
			}
			resumed := make(chan bool, 32)
			front.Config = public.Server(front.Listener.Addr().String())
			front.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { resumed <- r.TLS.DidResume; serve.ServeHTTP(w, r) })
			front.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
			front.StartTLS()
			clientFor := func(certificate tls.Certificate) *http.Client {
				transport := front.Client().Transport.(*http.Transport).Clone()
				transport.Proxy = nil
				transport.DisableKeepAlives = true
				transport.TLSClientConfig = transport.TLSClientConfig.Clone()
				if len(certificate.Certificate) > 0 {
					transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
				}
				transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(4)
				t.Cleanup(transport.CloseIdleConnections)
				return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			}
			anonymous := clientFor(tls.Certificate{})
			var forged []byte
			post := func(client *http.Client, path string, data []byte, status int) ([]byte, bool) {
				t.Helper()
				r, err := http.NewRequest(http.MethodPost, front.URL+path, bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Content-Type", "application/soap+xml")
				if path == protocol.ManagementPath {
					r.Header.Set("Content-Type", syncMLContentType)
				}
				r.Header.Set("Client-Cert", ":"+base64.StdEncoding.EncodeToString(forged)+":")
				r.Header.Set("X-Forwarded-Client-Cert", "synthetic forged certificate")
				response, err := client.Do(r)
				if err != nil {
					t.Fatal("owned TLS request failed", err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || response.StatusCode != status || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) || len(response.TransferEncoding) != 0 || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("unexpected renewal HTTP response", response.StatusCode, status, err)
				}
				return body, <-resumed
			}
			i, initialRequest, key := enrollmentTestRequest(t, s)
			initialWire := strings.NewReplacer(wstepTestURL, front.URL+protocol.EnrollmentPath, "synthetic-secret-marker", initialRequest.Credential.Password, "synthetic@example.test", initialRequest.Credential.Username).Replace(wstepTestMessage(initialRequest.CSRDER))
			post(anonymous, protocol.EnrollmentPath, []byte(initialWire), 200)
			result := readEnrollmentTestResult(t, s, i.ID)
			f := renewalStoreFixture{syncMLTestEnrolled(t, s, result, enrollment), key}
			forged = f.certificate.Raw
			oldClient := clientFor(tls.Certificate{Certificate: [][]byte{f.certificate.Raw}, PrivateKey: f.key})
			newKey := renewalTestKey(t)
			renewalRequest := f.request(t, newKey)
			if delay := time.Until(f.certificate.NotAfter.Add(-86399*time.Second)) + 10*time.Millisecond; delay > 0 {
				time.Sleep(delay)
			}
			now := time.Now().UTC()
			security := `<wsse:Security s:mustUnderstand="1">` + renewalSOAPTimestamp(now, now.Add(5*time.Minute)) + renewalSOAPUsername + `</wsse:Security>`
			wire := strings.ReplaceAll(renewalSOAPTestMessage(renewalRequest.CMSDER, security), wstepTestURL, front.URL+protocol.EnrollmentPath)
			fault, _ := post(anonymous, protocol.EnrollmentPath, []byte(wire), 500)
			assertWSTEPFault(t, fault, "Receiver", "Authentication")
			for _, bad := range []string{
				strings.Replace(wire, `"></wsse:Password>`, `">synthetic-account-secret</wsse:Password>`, 1),
				strings.Replace(wire, securityNS+"#PKCS7", wstepNS+"#PKCS10", 1),
				strings.Replace(wire, trustNS+"/Renew", trustNS+"/Issue", 1),
				strings.Replace(wire, front.URL+protocol.EnrollmentPath, front.URL+protocol.ManagementPath, 1),
			} {
				body, _ := post(oldClient, protocol.EnrollmentPath, []byte(bad), 400)
				assertWSTEPFault(t, body, "Sender", "MessageFormat")
			}
			renewalTestCounts(t, s, 1, 0, 0)
			first, _ := post(oldClient, protocol.ManagementPath, f.initial(t), 200)
			response, wasResumed := post(oldClient, protocol.EnrollmentPath, []byte(wire), 200)
			if !wasResumed {
				t.Fatal("renewal did not exercise resumed old TLS")
			}
			provisioning, requestID := provisioningFromResponse(t, response, discoveryTestID)
			r := f.history(t)[0]
			candidate := f.candidate(t, r.RenewedCertificateID, newKey)
			newClient := clientFor(tls.Certificate{Certificate: [][]byte{candidate.certificate.Raw}, PrivateKey: newKey})
			// Replace the service instance while preserving its database and master
			// key; the public TLS listeners and trusted proxy remain the same.
			restarted, err := NewStoreWithMasterKey(s.db, authorityTestMasterKey)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := NewProtocolHandler(restarted, options, policy)
			if err != nil {
				t.Fatal(err)
			}
			active.Store(reloaded)
			id := "urn:uuid:12345678-1234-4567-89ab-123456789012"
			replay, _ := post(oldClient, protocol.EnrollmentPath, []byte(strings.Replace(wire, discoveryTestID, id, 1)), 200)
			replayed, replayID := provisioningFromResponse(t, replay, id)
			if requestID != replayID || !bytes.Equal(provisioning, replayed) {
				t.Fatal("SOAP restart/retry changed certificate")
			}
			ack := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
			final, _ := post(newClient, protocol.ManagementPath, ack, 200)
			if f.history(t)[0].Phase != "confirmed" {
				t.Fatal("new-key SyncML did not confirm renewal")
			}
			fault, wasResumed = post(oldClient, protocol.EnrollmentPath, []byte(wire), 500)
			if !wasResumed {
				t.Fatal("retired renewal did not exercise TLS resumption")
			}
			assertWSTEPFault(t, fault, "Receiver", "Authentication")
			post(oldClient, protocol.ManagementPath, ack, 403)
			if replay, wasResumed := post(newClient, protocol.ManagementPath, ack, 200); !bytes.Equal(replay, final) || !wasResumed {
				t.Fatal("new key failed resumed SyncML replay")
			}
			renewalTestCounts(t, s, 2, 1, 5)
		})
	}
}

func TestWSTEPRenewalTimestampExpiryRollsBackIssuanceAndReplay(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(strconv.FormatBool(replay), func(t *testing.T) {
			f := renewalTestStore(t)
			request := f.request(t, f.key)
			certificates, renewals, audits := 1, 0, 0
			if replay {
				if _, err := f.renew(request); err != nil {
					t.Fatal(err)
				}
				certificates, renewals, audits = 2, 1, 1
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			hold, err := f.store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback()
			var pid int
			if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(`LOCK TABLE mdm_windows_renewal_audit IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			now, expiry := time.Now().UTC(), time.Now().UTC().Add(2*time.Second)
			request.CreatedAt, request.ExpiresAt = &now, &expiry
			done := make(chan error, 1)
			go func() {
				data, err := f.store.RenewWindowsCertificate(ctx, f.certificate, request, f.options)
				if len(data) > 0 {
					done <- ErrSOAP
					return
				}
				done <- err
			}()
			waitForCredentialLock(t, f.store.db, pid, 1)
			if delay := time.Until(expiry) + 10*time.Millisecond; delay > 0 {
				time.Sleep(delay)
			}
			if err := hold.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != ErrCertificateRenewal {
				t.Fatal("timestamp expiry after audit wait released response", err)
			}
			renewalTestCounts(t, f.store, certificates, renewals, audits)
			for _, bad := range []CertificateRenewalRequest{
				{MessageID: request.MessageID, CMSDER: request.CMSDER, CreatedAt: &now},
				{MessageID: request.MessageID, CMSDER: request.CMSDER, ExpiresAt: &expiry},
				request,
			} {
				if data, err := f.renew(bad); err == nil || data != nil {
					t.Fatal("invalid timestamp accepted")
				}
			}
		})
	}
}
