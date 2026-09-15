package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/smallstep/pkcs7"
)

type renewalStoreFixture struct {
	syncMLStoreFixture
	key *rsa.PrivateKey
}

func renewalTestStore(t *testing.T) renewalStoreFixture {
	t.Helper()
	return renewalTestStoreOptions(t, enrollmentTestOptions())
}

func renewalTestStoreOptions(t *testing.T, enrollmentOptions EnrollmentOptions) renewalStoreFixture {
	t.Helper()
	s := authorityTestStore(t)
	options := authorityTestOptions()
	options.ValiditySeconds, options.RenewalSeconds = 86400, 86399
	if _, err := s.InitializeAuthority(context.Background(), "admin", 1, options); err != nil {
		t.Fatal(err)
	}
	_, result, key := managementTestEnrollment(t, s, enrollmentOptions)
	f := renewalStoreFixture{syncMLTestEnrolled(t, s, result, enrollmentOptions), key}
	// The supported short-lifetime configuration opens its window after one
	// second. No host clock, production records or certificate stores change.
	delay := time.Until(f.certificate.NotAfter.Add(-time.Duration(options.RenewalSeconds)*time.Second)) + 10*time.Millisecond
	if delay > 2*time.Second {
		t.Fatal("unexpected synthetic renewal window")
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	return f
}

func (f renewalStoreFixture) request(t *testing.T, key *rsa.PrivateKey) CertificateRenewalRequest {
	t.Helper()
	csr := renewalTestCSR(t, key, f.certificate.Raw, nil)
	return CertificateRenewalRequest{MessageID: discoveryTestID, CMSDER: renewalTestCMS(t, csr, f.certificate, f.key, pkcs7.OIDDigestAlgorithmSHA256, true)}
}

func renewalTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (f renewalStoreFixture) renew(request CertificateRenewalRequest) ([]byte, error) {
	return f.store.RenewWindowsCertificate(context.Background(), f.certificate, request, f.options)
}

func (f renewalStoreFixture) history(t *testing.T) []CertificateRenewal {
	t.Helper()
	r, err := f.store.CertificateRenewals(context.Background(), "admin", f.identity.Scope, f.identity.DeviceID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f renewalStoreFixture) candidate(t *testing.T, id string, key *rsa.PrivateKey) renewalStoreFixture {
	t.Helper()
	var der []byte
	if err := f.store.db.QueryRow(`SELECT certificate FROM mdm_windows_device_certificates WHERE id=$1`, id).Scan(&der); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.certificate, f.key = cert, key
	return f
}

func renewalTestCounts(t *testing.T, s *Store, certificates, renewals, audits int) {
	t.Helper()
	for table, want := range map[string]int{"mdm_windows_device_certificates": certificates, "mdm_windows_certificate_renewals": renewals, "mdm_windows_renewal_audit": audits} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != want {
			t.Fatal("unexpected renewal count", table, n, want, err)
		}
	}
}

func renewalTestRemoveMigration(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`DROP TABLE mdm_windows_renewal_audit,mdm_windows_certificate_renewals; DROP FUNCTION mdm_windows_keep_certificate_renewal(); DELETE FROM mdm_windows_migrations WHERE name='migrations/011_certificate_renewal.sql'`); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsRenewalIssuanceReplayRestartAndNewKey(t *testing.T) {
	f := renewalTestStore(t)
	key := renewalTestKey(t)
	request := f.request(t, key)
	var before string
	if err := f.store.db.QueryRow(`SELECT row_to_json(e)::text FROM mdm_windows_enrollments e`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	response, err := f.renew(request)
	if err != nil {
		t.Fatal(err)
	}
	renewalTestCounts(t, f.store, 2, 1, 1)
	provisioning, requestID := provisioningFromResponse(t, response, request.MessageID)
	history := f.history(t)
	if len(history) != 1 || history[0].Phase != "pending" || history[0].Revision != 1 || history[0].CompletedAt != nil || history[0].SourceCertificateID != f.identity.CertificateID {
		t.Fatal("missing pending handoff")
	}
	candidate := f.candidate(t, history[0].RenewedCertificateID, key)
	if !candidate.certificate.PublicKey.(*rsa.PublicKey).Equal(&key.PublicKey) || candidate.certificate.Subject.CommonName != f.certificate.Subject.CommonName || len(candidate.certificate.DNSNames) != 0 {
		t.Fatal("renewed certificate lost its server-owned identity")
	}
	for _, absent := range []string{f.secrets.ClientSecret, f.secrets.ServerSecret, f.secrets.ClientNonce, f.secrets.ServerNonce, "APPAUTH", "DMClient", "Renew", "untrusted-new-subject"} {
		if bytes.Contains(provisioning, []byte(absent)) {
			t.Fatal("renewal provisioning reset credentials or copied untrusted names")
		}
	}
	if !bytes.Contains(provisioning, []byte("PrivateKeyContainer")) || !bytes.Contains(provisioning, []byte(f.options.ProviderID)) {
		t.Fatal("minimal renewal provisioning incomplete")
	}
	restarted, err := NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	f.store = restarted
	proof, err := VerifyWindowsRenewalProof(request.CMSDER, f.certificate.Raw, 2048)
	if err != nil {
		t.Fatal(err)
	}
	request.MessageID = "urn:uuid:12345678-1234-4567-89ab-123456789012"
	request.CMSDER = renewalTestCMS(t, proof.CSR.Raw, f.certificate, f.key, pkcs7.OIDDigestAlgorithmSHA384, false)
	replay, err := f.renew(request)
	if err != nil {
		t.Fatal(err)
	}
	replayProvisioning, replayID := provisioningFromResponse(t, replay, request.MessageID)
	if replayID != requestID || !bytes.Equal(provisioning, replayProvisioning) {
		t.Fatal("re-signed exact CSR issued another certificate")
	}
	if response, err := f.renew(f.request(t, renewalTestKey(t))); !errors.Is(err, ErrRenewalConflict) || response != nil {
		t.Fatal("different CSR replaced the pending candidate", err)
	}
	if response, err := candidate.renew(candidate.request(t, key)); !errors.Is(err, ErrRenewalConflict) || response != nil {
		t.Fatal("unconfirmed candidate renewed itself", err)
	}
	for _, peer := range []renewalStoreFixture{f, candidate} {
		if got, err := peer.store.AuthenticateManagementDevice(managementTestRequest(t, peer.certificate.Raw, peer.options), peer.options); err != nil || got.DeviceID != f.identity.DeviceID {
			t.Fatal("pending handoff rejected a valid transport", err)
		}
	}
	metadata, err := f.store.Device(context.Background(), "viewer", f.identity.Scope, f.identity.DeviceID)
	if err != nil || metadata.FingerprintSHA256 != f.identity.FingerprintSHA256 {
		t.Fatal("unconfirmed certificate appeared current", err)
	}
	var after string
	if err := f.store.db.QueryRow(`SELECT row_to_json(e)::text FROM mdm_windows_enrollments e`).Scan(&after); err != nil || before != after {
		t.Fatal("renewal rewrote the initial enrollment", err)
	}
	for _, v := range []any{request, history[0]} {
		encoded, err := json.Marshal(v)
		if err != nil || strings.Contains(string(encoded), f.identity.DeviceID) || strings.Contains(fmt.Sprintf("%+v %#v", v, v), f.identity.DeviceID) {
			t.Fatal("generic serialization exposed protected renewal data")
		}
	}
	renewalTestCounts(t, f.store, 2, 1, 3)
}

func TestWindowsRenewalConfirmsWithinActiveCSPExchange(t *testing.T) {
	f := renewalTestStore(t)
	queued := cspTestQueue(t, f.syncMLStoreFixture, cspTestPolicy())
	request, response := cspTestStart(t, f.syncMLStoreFixture)
	beforeRecord, beforeSession := f.state(t)
	beforeCommand := cspTestRead(t, f.syncMLStoreFixture, queued.ID)
	key := renewalTestKey(t)
	renewRequest := f.request(t, key)
	if _, err := f.renew(renewRequest); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, key)
	// An exact, authenticated packet retry with the new TLS key confirms the
	// handoff while preserving the active command and every stored nonce byte.
	if replay, err := candidate.process(request); err != nil || !bytes.Equal(response, replay) {
		t.Fatal("new key could not resume active command delivery", err)
	}
	afterRecord, afterSession := f.state(t)
	afterCommand := cspTestRead(t, f.syncMLStoreFixture, queued.ID)
	if beforeRecord.Revision != afterRecord.Revision || beforeRecord.Nonces != afterRecord.Nonces || beforeSession.ID != afterSession.ID || beforeSession.Revision != afterSession.Revision || beforeCommand.Command.Revision != afterCommand.Command.Revision {
		t.Fatal("certificate handoff reset protocol or delivery state")
	}
	r = f.history(t)[0]
	if r.Phase != "confirmed" || r.Revision != 2 || r.CompletedAt == nil || r.ConfirmedSessionID != afterSession.ID || r.ConfirmedMessageID != 2 {
		t.Fatal("authenticated packet was not bound to the confirmed handoff")
	}
	if data, err := f.process(request); !errors.Is(err, ErrManagementIdentity) || data != nil {
		t.Fatal("retired key could still replay management", err)
	}
	if data, err := f.renew(renewRequest); !errors.Is(err, ErrManagementIdentity) || data != nil {
		t.Fatal("retired key could still request renewal", err)
	}
	if err := f.store.CancelCertificateRenewal(context.Background(), "admin", f.identity.Scope, f.identity.DeviceID, r.ID, r.Revision, "synthetic rollback"); !errors.Is(err, ErrRenewalConflict) {
		t.Fatal("confirmed handoff could be rolled back", err)
	}
	ack := syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, response)))
	if _, err := candidate.process(ack); err != nil {
		t.Fatal("new key lost the outstanding command", err)
	}
	if got := cspTestRead(t, f.syncMLStoreFixture, queued.ID); got.Command.Phase != "acknowledged" {
		t.Fatal("command result was lost across handoff")
	}
	metadata, err := f.store.Device(context.Background(), "viewer", f.identity.Scope, f.identity.DeviceID)
	fingerprint := sha256.Sum256(candidate.certificate.Raw)
	if err != nil || metadata.CertificateRevokedAt != nil || metadata.FingerprintSHA256 != hex.EncodeToString(fingerprint[:]) || !metadata.CertificateExpiresAt.Equal(candidate.certificate.NotAfter) {
		t.Fatal("console did not report the confirmed certificate", err)
	}
	devices, err := f.store.Devices(context.Background(), "viewer", f.identity.Scope, "", 0, 10)
	if err != nil || len(devices) != 1 || devices[0].FingerprintSHA256 != metadata.FingerprintSHA256 {
		t.Fatal("renewal duplicated or lost console device metadata", err)
	}
}

func TestWindowsRenewalUnauthenticatedCandidateAndAuditRollback(t *testing.T) {
	f := renewalTestStore(t)
	request := f.request(t, f.key)
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_renewal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic renewal audit failure'; END; $$; CREATE TRIGGER reject_renewal_audit BEFORE INSERT ON mdm_windows_renewal_audit FOR EACH ROW EXECUTE FUNCTION reject_renewal_audit()`); err != nil {
		t.Fatal(err)
	}
	if data, err := f.renew(request); err == nil || data != nil {
		t.Fatal("failed issuance audit returned a certificate")
	}
	renewalTestCounts(t, f.store, 1, 0, 0)
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_renewal_audit ON mdm_windows_renewal_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.renew(request); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, f.key)
	initial := syncMLTestInitial(f.identity, f.options, f.secrets)
	initial.Header.Credential = nil
	if _, err := candidate.process(syncMLTestWire(t, initial)); err != nil {
		t.Fatal(err)
	}
	if got := f.history(t)[0]; got.Phase != "pending" {
		t.Fatal("TLS alone confirmed replacement")
	}
	// A separately enrolled peer exercises confirmation rollback after mutual
	// authentication, retaining the exact protocol reply for a successful retry.
	g := renewalTestStore(t)
	first, err := g.process(g.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.renew(g.request(t, g.key)); err != nil {
		t.Fatal(err)
	}
	r = g.history(t)[0]
	candidate = g.candidate(t, r.RenewedCertificateID, g.key)
	if _, err := g.store.db.Exec(`CREATE FUNCTION reject_renewal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic renewal audit failure'; END; $$; CREATE TRIGGER reject_renewal_audit BEFORE INSERT ON mdm_windows_renewal_audit FOR EACH ROW EXECUTE FUNCTION reject_renewal_audit()`); err != nil {
		t.Fatal(err)
	}
	ack := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
	if data, err := candidate.process(ack); err == nil || data != nil {
		t.Fatal("failed confirmation audit released SyncML output")
	}
	syncMLTestCounts(t, g.store, 1, 1, 1, 1)
	if _, err := g.process(g.initial(t)); err != nil {
		t.Fatal("failed confirmation retired the old transport", err)
	}
	if _, err := g.store.db.Exec(`DROP TRIGGER reject_renewal_audit ON mdm_windows_renewal_audit`); err != nil {
		t.Fatal(err)
	}
	if got := g.history(t)[0]; got.Phase != "pending" || got.Revision != 1 {
		t.Fatal("failed audit persisted handoff")
	}
	if _, err := candidate.process(ack); err != nil {
		t.Fatal("confirmation could not retry after rollback", err)
	}
	if got := g.history(t)[0]; got.Phase != "confirmed" {
		t.Fatal("successful retry did not confirm")
	}
}

func TestWindowsRenewalCancellationScopeAndHistory(t *testing.T) {
	f := renewalTestStore(t)
	request := f.request(t, f.key)
	if _, err := f.renew(request); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, f.key)
	ctx := context.Background()
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if got, err := f.store.CertificateRenewals(ctx, actor, f.identity.Scope, f.identity.DeviceID, 0, 10); err == nil || got != nil {
			t.Fatal("unprivileged renewal history disclosed")
		}
		if err := f.store.CancelCertificateRenewal(ctx, actor, f.identity.Scope, f.identity.DeviceID, r.ID, 1, "synthetic cancellation"); err == nil {
			t.Fatal("unprivileged cancellation admitted")
		}
	}
	for _, scope := range []access.Scope{{TenantID: 1, SiteID: 12}, {TenantID: 2, SiteID: 21}, {TenantID: 1}} {
		if got, err := f.store.CertificateRenewals(ctx, "admin", scope, f.identity.DeviceID, 0, 10); err == nil || got != nil {
			t.Fatal("renewal history crossed exact scope")
		}
	}
	if err := f.store.CancelCertificateRenewal(ctx, "admin", f.identity.Scope, f.identity.DeviceID, r.ID, 2, "synthetic cancellation"); !errors.Is(err, ErrRenewalConflict) {
		t.Fatal("stale cancellation revision accepted", err)
	}
	if err := f.store.CancelCertificateRenewal(ctx, "admin", f.identity.Scope, f.identity.DeviceID, r.ID, 1, "synthetic cancellation"); err != nil {
		t.Fatal(err)
	}
	if got := f.history(t)[0]; got.Phase != "canceled" || got.Revision != 2 {
		t.Fatal("cancellation was not durable")
	}
	if data, err := candidate.process(f.initial(t)); !errors.Is(err, ErrManagementIdentity) || data != nil {
		t.Fatal("canceled candidate still authenticated", err)
	}
	if _, err := f.process(f.initial(t)); err != nil {
		t.Fatal("canceling the candidate retired the current key", err)
	}
	if data, err := f.renew(request); !errors.Is(err, ErrRenewalConflict) || data != nil {
		t.Fatal("canceled intent reissued", err)
	}
	if _, err := f.renew(f.request(t, renewalTestKey(t))); err != nil {
		t.Fatal("cancel prevented a fresh reviewed key request", err)
	}
	if err := f.store.RevokeDevice(ctx, "admin", f.identity.Scope, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if len(f.history(t)) != 2 {
		t.Fatal("revocation erased lifecycle history")
	}
}

func TestWindowsRenewalConcurrentIssuanceAndMigration(t *testing.T) {
	f := renewalTestStore(t)
	initial := f.initial(t)
	response, err := f.process(initial)
	if err != nil {
		t.Fatal(err)
	}
	var before, after string
	snapshot := `SELECT json_build_array((SELECT row_to_json(e) FROM mdm_windows_enrollments e),(SELECT row_to_json(s) FROM mdm_windows_syncml_state s),(SELECT row_to_json(s) FROM mdm_windows_syncml_sessions s),(SELECT row_to_json(p) FROM mdm_windows_syncml_packets p))::text`
	if err := f.store.db.QueryRow(snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	renewalTestRemoveMigration(t, f.store)
	for n := 0; n < 2; n++ {
		if err := f.store.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.db.QueryRow(snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("renewal migration rewrote existing encrypted protocol state", err)
	}
	if replay, err := f.process(initial); err != nil || !bytes.Equal(replay, response) {
		t.Fatal("migration broke exact SyncML replay", err)
	}
	request := f.request(t, renewalTestKey(t))
	var wg sync.WaitGroup
	type result struct {
		data []byte
		err  error
	}
	results := make(chan result, 8)
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); data, err := f.renew(request); results <- result{data, err} }()
	}
	wg.Wait()
	close(results)
	var first []byte
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if first != nil && !bytes.Equal(first, r.data) {
			t.Fatal("concurrent renewal returned different certificates")
		}
		first = r.data
	}
	renewalTestCounts(t, f.store, 2, 1, 8)
}
