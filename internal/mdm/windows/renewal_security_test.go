package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestWindowsRenewalRealTLSHandoffRejectsResumedRetiredKey(t *testing.T) {
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
	clientFor := func(peer renewalStoreFixture) *http.Client {
		client := server.Client()
		transport := client.Transport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DisableKeepAlives = true
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{peer.certificate.Raw}, PrivateKey: peer.key}}
		transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(2)
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	post := func(client *http.Client, data []byte, status int, wantResumed bool) []byte {
		t.Helper()
		response, err := client.Post(options.ManagementURL, syncMLContentType, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" || len(response.TransferEncoding) != 0 {
			t.Fatal("unexpected renewal TLS response", response.StatusCode, err)
		}
		if got := <-resumed; got != wantResumed {
			t.Fatal("TLS test did not exercise expected resumption", got, wantResumed)
		}
		if status != http.StatusOK && len(body) != 0 {
			t.Fatal("retired TLS key received protocol bytes")
		}
		return body
	}
	oldClient := clientFor(f)
	initial := f.initial(t)
	first := post(oldClient, initial, http.StatusOK, false)
	if replay := post(oldClient, initial, http.StatusOK, true); !bytes.Equal(replay, first) {
		t.Fatal("initial TLS retry changed response")
	}
	key := renewalTestKey(t)
	if _, err := f.renew(f.request(t, key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, key)
	newClient := clientFor(candidate)
	ack := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
	final := post(newClient, ack, http.StatusOK, false)
	post(oldClient, initial, http.StatusForbidden, true)
	if replay := post(newClient, ack, http.StatusOK, true); !bytes.Equal(replay, final) {
		t.Fatal("new TLS key lost receipt replay")
	}
	if got := f.history(t)[0]; got.Phase != "confirmed" {
		t.Fatal("actual new TLS key did not confirm handoff")
	}
}

func TestWindowsRenewalPreservesUnknownCSPAndQueuedWork(t *testing.T) {
	f := renewalTestStore(t)
	unknown := cspTestQueue(t, f.syncMLStoreFixture, cspTestPolicy())
	_, delivery := cspTestStart(t, f.syncMLStoreFixture)
	queued := cspTestQueue(t, f.syncMLStoreFixture, cspTestPolicy())
	ack := cspTestReply(syncMLTestParsed(t, delivery))
	ack.Commands[1].Data.Text = "516"
	wire := syncMLTestWire(t, ack)
	response, err := f.process(wire)
	if err != nil {
		t.Fatal(err)
	}
	before := cspTestRead(t, f.syncMLStoreFixture, unknown.ID)
	if before.Command.Phase != "unknown" {
		t.Fatal("missing uncertain fixture outcome")
	}
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, f.key)
	if replay, err := candidate.process(wire); err != nil || !bytes.Equal(response, replay) {
		t.Fatal("renewal lost uncertain-result receipt", err)
	}
	cspTestNextSession(t, candidate.syncMLStoreFixture)
	after := cspTestRead(t, f.syncMLStoreFixture, unknown.ID)
	if after.Command.Phase != "unknown" || after.Command.Revision != before.Command.Revision || cspTestRead(t, f.syncMLStoreFixture, queued.ID).Command.Phase != "queued" {
		t.Fatal("renewal reopened or bypassed uncertain work")
	}
}

// Rewrite and reseal only an unused enrollment in this random test schema.
// Production migrations and certificate records never shorten or rebind it.
func renewalTestShortAnchor(t *testing.T, f renewalStoreFixture) renewalStoreFixture {
	t.Helper()
	signer, err := loadTestAuthority(t, f.store, 1)
	if err != nil {
		t.Fatal(err)
	}
	template := *f.certificate
	template.NotAfter = time.Now().Add(5 * time.Second).UTC().Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &template, signer.certificate, template.PublicKey, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	f.certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	f.identity.FingerprintSHA256 = hex.EncodeToString(fingerprint[:])
	f.identity.CertificateExpiry = f.certificate.NotAfter
	var requestDigest, configDigest []byte
	if err := f.store.db.QueryRow(`SELECT request_digest,configuration_digest FROM mdm_windows_enrollments WHERE device_id=$1`, f.identity.DeviceID).Scan(&requestDigest, &configDigest); err != nil {
		t.Fatal(err)
	}
	purpose := func(kind string) string {
		return enrollmentSecretPurpose(kind, f.identity.TenantID, f.identity.SiteID, f.identity.DeviceID, f.identity.AuthorityID, fingerprint[:], requestDigest, configDigest)
	}
	plain, err := json.Marshal(f.secrets)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	auth, err := f.store.secrets.seal(plain, purpose("syncml-bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err := buildProvisioningDocument(f.options, f.identity.DeviceID, f.identity.EnrollmentType, signer.certificate, f.certificate, f.secrets)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(provisioning)
	protected, err := f.store.secrets.sealBounded(provisioning, purpose("provisioning"), maxProvisioningBytes)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_enrollments DISABLE TRIGGER mdm_windows_enrollment_result; ALTER TABLE mdm_windows_device_certificates DISABLE TRIGGER mdm_windows_device_certificate`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE mdm_windows_device_certificates SET certificate=$1,fingerprint=$2,expires_at=$3 WHERE id=$4`, der, fingerprint[:], f.certificate.NotAfter, f.identity.CertificateID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE mdm_windows_enrollments SET encrypted_auth=$1,encrypted_provisioning=$2 WHERE device_id=$3`, auth, protected, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_enrollments ENABLE TRIGGER mdm_windows_enrollment_result; ALTER TABLE mdm_windows_device_certificates ENABLE TRIGGER mdm_windows_device_certificate`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWindowsRenewalChainSurvivesOriginalCertificateExpiry(t *testing.T) {
	f := renewalTestShortAnchor(t, renewalTestStore(t))
	first, err := f.process(f.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	key := renewalTestKey(t)
	if _, err := f.renew(f.request(t, key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, key)
	ack := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
	completed, err := candidate.process(ack)
	if err != nil {
		t.Fatal(err)
	}
	// A second renewal reuses the current key, preserving the original state
	// identity across more than one confirmed certificate generation.
	if delay := time.Until(candidate.certificate.NotAfter.Add(-86399*time.Second)) + 10*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	if _, err := candidate.renew(candidate.request(t, key)); err != nil {
		t.Fatal("second-generation renewal failed", err)
	}
	history := f.history(t)
	var next CertificateRenewal
	for _, r := range history {
		if r.Phase == "pending" {
			next = r
		}
	}
	if next.SourceCertificateID != r.RenewedCertificateID {
		t.Fatal("renewal chain skipped the current certificate")
	}
	latest := f.candidate(t, next.RenewedCertificateID, key)
	if replay, err := latest.process(ack); err != nil || !bytes.Equal(completed, replay) {
		t.Fatal("second handoff lost completed-packet replay", err)
	}
	if _, err := candidate.process(ack); !errors.Is(err, ErrManagementIdentity) {
		t.Fatal("intermediate retired key still authenticated", err)
	}
	delay := time.Until(f.certificate.NotAfter) + 20*time.Millisecond
	if delay > 6*time.Second {
		t.Fatal("unexpected synthetic expiry")
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	record, _ := f.state(t)
	secrets := *f.secrets
	secrets.ClientNonce = record.Nonces.ClientNonce
	initial := syncMLTestInitial(f.identity, f.options, &secrets)
	initial.Header.SessionID = "2"
	if _, err := latest.process(syncMLTestWire(t, initial)); err != nil {
		t.Fatal("expired encryption anchor blocked the current transport", err)
	}
	_, session := f.state(t)
	if !session.ExpiresAt.After(f.certificate.NotAfter) {
		t.Fatal("new session retained retired certificate expiry")
	}
	if len(f.history(t)) != 2 {
		t.Fatal("renewal chain history was lost")
	}
}

func TestWindowsRenewalAdmissionRejectsInactiveIdentityAndChangedIntent(t *testing.T) {
	f := renewalTestStore(t)
	request := f.request(t, f.key)
	ctx := context.Background()
	for name, change := range map[string]func(*CertificateRenewalRequest, *EnrollmentOptions){
		"message":     func(r *CertificateRenewalRequest, _ *EnrollmentOptions) { r.MessageID = "invalid" },
		"empty proof": func(r *CertificateRenewalRequest, _ *EnrollmentOptions) { r.CMSDER = nil },
		"large proof": func(r *CertificateRenewalRequest, _ *EnrollmentOptions) {
			r.CMSDER = make([]byte, MaxWindowsRenewalProofBytes+1)
		},
		"signature": func(r *CertificateRenewalRequest, _ *EnrollmentOptions) {
			r.CMSDER = bytes.Clone(r.CMSDER)
			r.CMSDER[len(r.CMSDER)-1] ^= 1
		},
		"provider": func(_ *CertificateRenewalRequest, o *EnrollmentOptions) { o.ProviderID = "OtherProvider" },
		"endpoint": func(_ *CertificateRenewalRequest, o *EnrollmentOptions) {
			o.ManagementURL = "https://other.example.test/management"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, o := request, f.options
			change(&r, &o)
			if data, err := f.store.RenewWindowsCertificate(ctx, f.certificate, r, o); err == nil || data != nil {
				t.Fatal("invalid renewal admitted")
			}
		})
	}
	if data, err := f.store.RenewWindowsCertificate(ctx, nil, request, f.options); err == nil || data != nil {
		t.Fatal("missing peer admitted")
	}
	// A valid peer from another enrollment cannot sign for this device.
	_, other, _ := managementTestEnrollment(t, f.store, f.options)
	peer, err := x509.ParseCertificate(other.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(peer.NotAfter.Add(-86399*time.Second)) + 10*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	if data, err := f.store.RenewWindowsCertificate(ctx, peer, request, f.options); !errors.Is(err, ErrRenewalProof) || data != nil {
		t.Fatal("peer and CMS identity were not bound", err)
	}
	if _, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	if data, err := f.renew(request); !errors.Is(err, ErrManagementIdentity) || data != nil {
		t.Fatal("reparented site renewed", err)
	}
	if _, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=1 WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeDevice(ctx, "admin", f.identity.Scope, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if data, err := f.renew(request); !errors.Is(err, ErrManagementIdentity) || data != nil {
		t.Fatal("revoked device renewed", err)
	}
	renewalTestCounts(t, f.store, 2, 0, 0)
	// The ordinary 90-day issuer does not admit freshly issued certificates.
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	_, result, key := managementTestEnrollment(t, s, enrollmentTestOptions())
	g := renewalStoreFixture{syncMLTestEnrolled(t, s, result, enrollmentTestOptions()), key}
	if data, err := g.renew(g.request(t, key)); !errors.Is(err, ErrRenewalWindow) || data != nil {
		t.Fatal("certificate renewed before the issuer window", err)
	}
	renewalTestCounts(t, s, 1, 0, 0)
}

func TestWindowsRenewalProtectedHistoryAndCanceledAuditRollback(t *testing.T) {
	f := renewalTestStore(t)
	request := f.request(t, f.key)
	if _, err := f.renew(request); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, f.key)
	for _, sql := range []string{
		`UPDATE mdm_windows_certificate_renewals SET phase='confirmed'`,
		`UPDATE mdm_windows_certificate_renewals SET source_certificate_id=renewed_certificate_id`,
		`UPDATE mdm_windows_certificate_renewals SET device_id='11111111-1111-4111-8111-111111111111'`,
		`UPDATE mdm_windows_certificate_renewals SET revision=revision+1`,
		`DELETE FROM mdm_windows_certificate_renewals`,
		`UPDATE mdm_windows_renewal_audit SET actor='other'`,
		`DELETE FROM mdm_windows_renewal_audit`,
	} {
		if _, err := f.store.db.Exec(sql); err == nil {
			t.Fatal("database allowed renewal identity or audit mutation")
		}
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_renewal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic renewal audit failure'; END; $$; CREATE TRIGGER reject_renewal_audit BEFORE INSERT ON mdm_windows_renewal_audit FOR EACH ROW EXECUTE FUNCTION reject_renewal_audit()`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.store.CancelCertificateRenewal(ctx, "admin", f.identity.Scope, f.identity.DeviceID, r.ID, 1, "synthetic rollback"); err == nil {
		t.Fatal("failed cancellation audit committed")
	}
	if data, err := f.renew(request); err == nil || data != nil {
		t.Fatal("failed replay audit disclosed provisioning")
	}
	if data, err := f.store.CertificateRenewals(ctx, "admin", f.identity.Scope, f.identity.DeviceID, 0, 10); err == nil || data != nil {
		t.Fatal("failed history audit disclosed metadata")
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_renewal_audit ON mdm_windows_renewal_audit`); err != nil {
		t.Fatal(err)
	}
	if got := f.history(t)[0]; got.Phase != "pending" || got.Revision != 1 {
		t.Fatal("cancellation audit did not roll back")
	}
	if _, err := candidate.store.AuthenticateManagementDevice(managementTestRequest(t, candidate.certificate.Raw, candidate.options), candidate.options); err != nil {
		t.Fatal("failed cancellation revoked the candidate", err)
	}
	var original []byte
	if err := f.store.db.QueryRow(`SELECT encrypted_record FROM mdm_windows_certificate_renewals WHERE id=$1`, r.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_certificate_renewals DISABLE TRIGGER mdm_windows_certificate_renewal_identity`); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(original)
	changed[len(changed)-1] ^= 1
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_certificate_renewals SET encrypted_record=$1 WHERE id=$2`, changed, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_certificate_renewals ENABLE TRIGGER mdm_windows_certificate_renewal_identity`); err != nil {
		t.Fatal(err)
	}
	if data, err := f.store.CertificateRenewals(ctx, "admin", f.identity.Scope, f.identity.DeviceID, 0, 10); !errors.Is(err, ErrAuthoritySecret) || data != nil {
		t.Fatal("corrupted history was disclosed", err)
	}
	if data, err := candidate.process(f.initial(t)); !errors.Is(err, ErrAuthoritySecret) || data != nil {
		t.Fatal("corrupt renewal authenticated candidate", err)
	}
	if data, err := f.renew(request); !errors.Is(err, ErrAuthoritySecret) || data != nil {
		t.Fatal("corrupt proof was replayed", err)
	}
	if _, err := f.process(f.initial(t)); err != nil {
		t.Fatal("corrupt pending history blocked the current key", err)
	}
}

func TestWindowsRenewalWaitsForRevocationAndPermissionLocks(t *testing.T) {
	f := renewalTestStore(t)
	request := f.request(t, f.key)
	if _, err := f.renew(request); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
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
	if _, err := hold.Exec(`UPDATE mdm_windows_devices SET revoked_at=clock_timestamp() WHERE id=$1`, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := f.store.RenewWindowsCertificate(ctx, f.certificate, request, f.options)
		finished <- err
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, ErrManagementIdentity) {
		t.Fatal("renewal replay escaped concurrent revocation", err)
	}
	if err := f.store.permissions.ReplaceGrants(ctx, "admin", "second", 1, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	hold, err = f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(`SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		t.Fatal(err)
	}
	go func() {
		finished <- f.store.CancelCertificateRenewal(ctx, "second", f.identity.Scope, f.identity.DeviceID, r.ID, 1, "synthetic permission wait")
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	if _, err := hold.Exec(`DELETE FROM uem_access_grants WHERE user_id='second'`); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err == nil {
		t.Fatal("cancellation escaped permission removal")
	}
	if got := f.history(t)[0]; got.Phase != "pending" {
		t.Fatal("denied cancellation changed candidate")
	}
	if err := f.store.CancelCertificateRenewal(ctx, "admin", f.identity.Scope, f.identity.DeviceID, uuid.NewString(), 1, "synthetic absent history"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing history resolution was ambiguous", err)
	}
}
