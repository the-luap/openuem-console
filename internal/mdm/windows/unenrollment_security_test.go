package windows

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWindowsUnenrollmentRealTLSRejectsRetiredResumedIdentity(t *testing.T) {
	var handler *SyncMLHandler
	resumed := make(chan bool, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { resumed <- r.TLS.DidResume; handler.ServeHTTP(w, r) }))
	defer server.Close()
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	options := enrollmentTestOptions()
	options.ManagementURL = "https://" + server.Listener.Addr().String() + "/windows/syncml"
	f := renewalTestStoreOptions(t, options)
	var err error
	handler, err = NewSyncMLHandler(f.store, options)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{f.certificate.Raw}, PrivateKey: f.key}}
	transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	defer transport.CloseIdleConnections()
	client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
	post := func(data []byte, status int, wantResumed bool) []byte {
		t.Helper()
		request, err := http.NewRequest("POST", options.ManagementURL, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", syncMLContentType)
		request.Header.Set("X-Client-Cert", "untrusted certificate header")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" || len(response.TransferEncoding) != 0 {
			t.Fatal("unexpected disconnection TLS response", response.StatusCode, err)
		}
		if got := <-resumed; got != wantResumed {
			t.Fatal("TLS fixture did not exercise expected resumption", got)
		}
		if status != 200 && len(body) != 0 {
			t.Fatal("rejected notification disclosed protocol bytes")
		}
		return body
	}
	invalid := unenrollmentTestMessage(t, f.syncMLStoreFixture, f.secrets.ClientNonce)
	invalid.Header.Credential.Digest = base64.StdEncoding.EncodeToString(make([]byte, 16))
	post(syncMLTestWire(t, invalid), 400, false)
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_reports", 0)
	// A pending replacement must lose access with the source when the device
	// reports disconnection; it is not falsely confirmed by the notification.
	candidateKey := renewalTestKey(t)
	if _, err := f.renew(f.request(t, candidateKey)); err != nil {
		t.Fatal(err)
	}
	pending := f.history(t)[0]
	data := syncMLTestWire(t, unenrollmentTestMessage(t, f.syncMLStoreFixture, f.secrets.ClientNonce))
	response := post(data, 200, true)
	if parsed := syncMLTestParsed(t, response); len(parsed.Commands) < 2 || parsed.Commands[len(parsed.Commands)-1].Data.Text != "200" {
		t.Fatal("notification was not acknowledged")
	}
	post(data, 403, true)
	post(f.initial(t), 403, true)
	if _, err := f.renew(f.request(t, f.key)); !errors.Is(err, ErrManagementIdentity) {
		t.Fatal("retired identity still renewed", err)
	}
	candidate := f.candidate(t, pending.RenewedCertificateID, candidateKey)
	if identity, err := f.store.AuthenticateManagementDevice(managementTestRequest(t, candidate.certificate.Raw, options), options); !errors.Is(err, ErrManagementIdentity) || identity != nil {
		t.Fatal("pending candidate survived device disconnection", err)
	}
	if report, err := f.store.CertificateRenewalDetails(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, pending.ID); err != nil || report.Renewal.Phase != "pending" {
		t.Fatal("notification fabricated a confirmed renewal", err)
	}
}

func TestWindowsUnenrollmentExpiryDuringAuditWaitRollsBack(t *testing.T) {
	f := renewalTestShortAnchor(t, renewalTestStore(t))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
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
	if _, err := hold.Exec(`LOCK TABLE mdm_windows_unenrollment_audit IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	data := syncMLTestWire(t, unenrollmentTestMessage(t, f.syncMLStoreFixture, f.secrets.ClientNonce))
	done := make(chan error, 1)
	go func() {
		response, err := f.store.processSyncML(ctx, f.certificate, data, f.options)
		if len(response) > 0 {
			err = errors.New("expired peer received success")
		}
		done <- err
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	if err := waitUntilDatabaseExpiry(ctx, hold, f.certificate.NotAfter); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrManagementIdentity) {
		t.Fatal("expired transport committed disconnection", err)
	}
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_reports", 0)
	unenrollmentTestCount(t, f.store, "mdm_windows_unenrollment_audit", 0)
	syncMLTestCounts(t, f.store, 0, 0, 0, 0)
	if device, err := f.store.Device(t.Context(), "viewer", f.identity.Scope, f.identity.DeviceID); err != nil || device.RevokedAt != nil {
		t.Fatal("expired notification revoked access", err)
	}
}

func TestWindowsUnenrollmentMigrationPreservesExistingManagement(t *testing.T) {
	f := syncMLTestStore(t)
	first, err := f.process(f.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	before, session := f.state(t)
	if _, err := f.store.db.Exec(`DROP TABLE mdm_windows_unenrollment_audit,mdm_windows_unenrollment_reports; DELETE FROM mdm_windows_migrations WHERE name='migrations/012_unenrollment_notifications.sql'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := f.store.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	after, current := f.state(t)
	if before.Revision != after.Revision || before.Nonces != after.Nonces || session.Revision != current.Revision || session.Phase != current.Phase {
		t.Fatal("migration changed the existing protocol state")
	}
	if response, err := f.process(f.initial(t)); err != nil || !bytes.Equal(first, response) {
		t.Fatal("migration broke exact existing replay", err)
	}
	if _, err := f.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); err != nil {
		t.Fatal("migration broke existing management", err)
	}
}
