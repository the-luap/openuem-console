package windows

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func enrollmentTestRequest(t *testing.T, s *Store) (*EnrollmentInvitation, *WSTEPRequest, *rsa.PrivateKey) {
	t.Helper()
	i, credential := createTestInvitation(t, s, "operator")
	key, csr := enrollmentTestCSR(t)
	return i, &WSTEPRequest{MessageID: discoveryTestID, Credential: *credential, CSRDER: csr, Context: wstepTestContext()}, key
}

type enrollmentTestResult struct {
	DeviceID, AuthorityID                                                            string
	Certificate, Fingerprint, RequestDigest, ConfigurationDigest, Provisioning, Auth []byte
	RequestID                                                                        int64
}

func readEnrollmentTestResult(t *testing.T, s *Store, invitation string) enrollmentTestResult {
	t.Helper()
	var result enrollmentTestResult
	err := s.db.QueryRow(`SELECT e.device_id,c.authority_id,c.certificate,c.fingerprint,e.request_digest,e.configuration_digest,e.encrypted_provisioning,e.encrypted_auth,e.request_id FROM mdm_windows_enrollments e JOIN mdm_windows_device_certificates c ON c.id=e.certificate_id WHERE e.invitation_id=$1`, invitation).Scan(&result.DeviceID, &result.AuthorityID, &result.Certificate, &result.Fingerprint, &result.RequestDigest, &result.ConfigurationDigest, &result.Provisioning, &result.Auth, &result.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertEnrollmentCounts(t *testing.T, s *Store, expected int) {
	t.Helper()
	for _, table := range []string{"mdm_windows_devices", "mdm_windows_device_certificates", "mdm_windows_enrollments"} {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != expected {
			t.Fatal("unexpected persisted enrollment count", table, count, err)
		}
	}
}

func TestWindowsEnrollmentPersistsCertificateAndEncryptedBootstrap(t *testing.T) {
	s := authorityTestStore(t)
	a := initializeTestAuthority(t, s, 1)
	i, request, key := enrollmentTestRequest(t, s)
	request.Context = append(request.Context, EnrollmentContextItem{"TenantID", "2"}, EnrollmentContextItem{"SiteID", "21"}, EnrollmentContextItem{"AuthorityID", "12345678-1234-4567-89ab-123456789012"}, EnrollmentContextItem{"CertificateSubject", "CN=administrator"})
	ctx := context.Background()
	response, err := s.EnrollWindows(ctx, request, enrollmentTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	provisioning, requestID := provisioningFromResponse(t, response, request.MessageID)
	state := readEnrollmentTestResult(t, s, i.ID)
	var tenant, site int
	if err := s.db.QueryRow(`SELECT tenant_id,site_id FROM mdm_windows_devices WHERE id=$1`, state.DeviceID).Scan(&tenant, &site); err != nil {
		t.Fatal(err)
	}
	if tenant != i.TenantID || site != i.SiteID {
		t.Fatal("request hints reassigned device scope")
	}
	assertEnrollmentCounts(t, s, 1)
	if state.DeviceID == enrollmentContextValue(request.Context, "DeviceID") || !canonicalInvitationID(state.DeviceID) || state.AuthorityID != a.ID || state.RequestID != requestID {
		t.Fatal("enrollment did not allocate a scoped server identity")
	}
	certificate, err := x509.ParseCertificate(state.Certificate)
	if err != nil || !certificate.PublicKey.(*rsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("stored certificate differs from the device CSR key")
	}
	root, err := x509.ParseCertificate(a.Certificate)
	if err != nil || certificate.CheckSignatureFrom(root) != nil {
		t.Fatal("certificate was not issued by the scoped organization")
	}
	purpose := func(kind string) string {
		return enrollmentSecretPurpose(kind, i.TenantID, i.SiteID, state.DeviceID, state.AuthorityID, state.Fingerprint, state.RequestDigest, state.ConfigurationDigest)
	}
	stored, err := s.secrets.openBounded(state.Provisioning, purpose("provisioning"), maxProvisioningBytes)
	if err != nil || !bytes.Equal(stored, provisioning) || bytes.Equal(state.Provisioning, provisioning) {
		t.Fatal("complete encrypted provisioning did not persist")
	}
	clear(stored)
	auth, err := s.secrets.open(state.Auth, purpose("syncml-bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(auth)
	var secrets syncMLBootstrapSecrets
	if err := json.Unmarshal(auth, &secrets); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{secrets.ClientSecret, secrets.ServerSecret, secrets.ClientNonce, secrets.ServerNonce} {
		if !bytes.Contains(provisioning, []byte(value)) || bytes.Contains(state.Auth, []byte(value)) || bytes.Contains(state.Provisioning, []byte(value)) {
			t.Fatal("bootstrap secret absent from device provisioning or stored in plaintext")
		}
	}
	var audit string
	if err := s.db.QueryRow(`SELECT json_agg(a)::text FROM mdm_windows_audit a WHERE resource_id=$1`, i.ID).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{request.Credential.Password, request.Credential.Username, secrets.ClientSecret, secrets.ServerSecret, base64.StdEncoding.EncodeToString(request.CSRDER), "SYNTHETIC-WINDOWS"} {
		if strings.Contains(audit, value) {
			t.Fatal("issuance audit exposed credential, CSR or device hints")
		}
	}
	if invitationEventCount(t, s, i.ID, "invitation.consumed") != 1 || invitationEventCount(t, s, i.ID, "enrollment.issued") != 1 {
		t.Fatal("issuance or consumption audit missing")
	}
	if _, err := s.CheckPolicyCredential(ctx, request.Credential); !errors.Is(err, ErrCredential) {
		t.Fatal("issued invitation remained usable for policy")
	}
	restarted, err := NewStoreWithMasterKey(s.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	request.MessageID = "urn:uuid:12345678-1234-4567-89ab-123456789012"
	replayed, err := restarted.EnrollWindows(ctx, request, enrollmentTestOptions())
	if err != nil {
		t.Fatal("durable retry after restart failed", err)
	}
	decoded, replayID := provisioningFromResponse(t, replayed, request.MessageID)
	if !bytes.Equal(decoded, provisioning) || replayID != requestID || invitationEventCount(t, s, i.ID, "enrollment.replayed") != 1 {
		t.Fatal("retry changed the committed certificate or credentials")
	}
	assertEnrollmentCounts(t, s, 1)
}

func TestWindowsEnrollmentConcurrentRetryAndRequestBinding(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	i, request, _ := enrollmentTestRequest(t, s)
	ctx := context.Background()
	start := make(chan struct{})
	type result struct {
		data []byte
		err  error
	}
	results := make(chan result, 10)
	var wg sync.WaitGroup
	for n := 0; n < 10; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions())
			results <- result{data, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var first []byte
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if first != nil && !bytes.Equal(first, result.data) {
			t.Fatal("concurrent retries returned different provisioning")
		}
		first = result.data
	}
	assertEnrollmentCounts(t, s, 1)
	if invitationEventCount(t, s, i.ID, "invitation.consumed") != 1 || invitationEventCount(t, s, i.ID, "enrollment.issued") != 1 || invitationEventCount(t, s, i.ID, "enrollment.replayed") != 9 {
		t.Fatal("concurrent requests did not issue exactly once")
	}
	changed := *request
	changed.CSRDER = bytes.Clone(request.CSRDER)
	changed.CSRDER[len(changed.CSRDER)-1] ^= 1
	if data, err := s.EnrollWindows(ctx, &changed, enrollmentTestOptions()); !errors.Is(err, ErrEnrollmentReplay) || data != nil {
		t.Fatal("changed CSR reused a completed invitation")
	}
	changed.CSRDER = request.CSRDER
	changed.Context = append([]EnrollmentContextItem(nil), request.Context...)
	changed.Context[0].Value = "4"
	if data, err := s.EnrollWindows(ctx, &changed, enrollmentTestOptions()); !errors.Is(err, ErrEnrollmentReplay) || data != nil {
		t.Fatal("changed device hints reused a completed invitation")
	}
	options := enrollmentTestOptions()
	options.ManagementURL = "https://other.example.test/syncml"
	if data, err := s.EnrollWindows(ctx, request, options); !errors.Is(err, ErrEnrollmentReplay) || data != nil {
		t.Fatal("changed server configuration rewrote completed provisioning")
	}
	wrong, _ := NewStoreWithMasterKey(s.db, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if data, err := wrong.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrAuthoritySecret) || data != nil {
		t.Fatal("wrong master key returned durable provisioning")
	}
	if invitationEventCount(t, s, i.ID, "enrollment.replayed") != 9 {
		t.Fatal("rejected replay committed audit")
	}
}

func TestWindowsEnrollmentAuthorizationAndCSRFailuresDoNotConsume(t *testing.T) {
	s := authorityTestStore(t)
	i, request, _ := enrollmentTestRequest(t, s)
	ctx := context.Background()
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrAuthorityUnavailable) || data != nil {
		t.Fatal("issuance succeeded without CA")
	}
	initializeTestAuthority(t, s, 1)
	for _, change := range []func(*WSTEPRequest){
		func(r *WSTEPRequest) { r.Credential.Password = "not an enrollment credential" },
		func(r *WSTEPRequest) { r.Credential.Username = "other@example.test" },
		func(r *WSTEPRequest) { r.CSRDER = []byte("not DER") },
		func(r *WSTEPRequest) { r.MessageID = "invalid" },
		func(r *WSTEPRequest) { r.Context = nil },
	} {
		changed := *request
		change(&changed)
		if data, err := s.EnrollWindows(ctx, &changed, enrollmentTestOptions()); err == nil || data != nil {
			t.Fatal("invalid enrollment returned provisioning")
		}
	}
	changed := *request
	changed.Context = append([]EnrollmentContextItem(nil), request.Context...)
	for n := range changed.Context {
		if changed.Context[n].Name == "DeviceType" {
			changed.Context[n].Value = "WindowsPhone"
		}
	}
	if data, err := s.EnrollWindows(ctx, &changed, enrollmentTestOptions()); !errors.Is(err, ErrWindowsDeviceType) || data != nil {
		t.Fatal("legacy device type reached desktop provisioning")
	}
	if _, err := s.CheckPolicyCredential(ctx, request.Credential); err != nil {
		t.Fatal("failed issuance consumed invitation")
	}
	assertEnrollmentCounts(t, s, 0)
	if invitationEventCount(t, s, i.ID, "invitation.consumed") != 0 {
		t.Fatal("failed issuance committed consumption")
	}
	if err := s.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Viewer, Scope: credentialTestScope}}); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrCredential) || data != nil {
		t.Fatal("revoked issuer permissions admitted enrollment")
	}
	assertEnrollmentCounts(t, s, 0)
}

func TestWindowsEnrollmentAuditFailureRollsBackAllState(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	i, request, _ := enrollmentTestRequest(t, s)
	ctx := context.Background()
	_, err := s.db.Exec(`CREATE FUNCTION reject_windows_enrollment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('enrollment.issued','enrollment.replayed') THEN RAISE EXCEPTION 'synthetic enrollment audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_windows_enrollment_audit BEFORE INSERT ON mdm_windows_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_enrollment_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err == nil || data != nil {
		t.Fatal("failed audit returned provisioning")
	}
	assertEnrollmentCounts(t, s, 0)
	if invitationEventCount(t, s, i.ID, "invitation.consumed") != 0 || invitationEventCount(t, s, i.ID, "enrollment.issued") != 0 {
		t.Fatal("audit failure left partial issuance events")
	}
	if _, err := s.CheckPolicyCredential(ctx, request.Credential); err != nil {
		t.Fatal("audit failure consumed invitation")
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_windows_enrollment_audit ON mdm_windows_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal("retry after rollback failed", err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_windows_enrollment_audit BEFORE INSERT ON mdm_windows_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_enrollment_audit()`); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err == nil || data != nil {
		t.Fatal("replay audit failure released protected provisioning")
	}
	assertEnrollmentCounts(t, s, 1)
	if invitationEventCount(t, s, i.ID, "enrollment.replayed") != 0 {
		t.Fatal("failed replay committed audit")
	}
}

func TestWindowsEnrollmentExpiryAndCancellationDuringAudit(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "cancellation"}[cancelRequest], func(t *testing.T) {
			s := authorityTestStore(t)
			initializeTestAuthority(t, s, 1)
			_, der := enrollmentTestCSR(t)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var now time.Time
			if err := s.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			i, credential := insertTimedInvitation(t, s, now.Add(-time.Minute), now.Add(2*time.Second))
			request := &WSTEPRequest{MessageID: discoveryTestID, Credential: *credential, CSRDER: der, Context: wstepTestContext()}
			blocker, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			var pid int
			if err := blocker.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := blocker.Exec(`LOCK TABLE mdm_windows_audit IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions())
				if data != nil {
					result <- errors.New("failed transaction returned provisioning")
					return
				}
				result <- err
			}()
			waitForCredentialLock(t, s.db, pid, 1)
			if cancelRequest {
				cancel()
			} else if err := waitUntilDatabaseExpiry(ctx, blocker, i.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			err = <-result
			if cancelRequest {
				if err == nil {
					t.Fatal("canceled transaction succeeded")
				}
			} else if !errors.Is(err, ErrCredential) {
				t.Fatal(err)
			}
			assertEnrollmentCounts(t, s, 0)
			if invitationEventCount(t, s, i.ID, "invitation.consumed") != 0 {
				t.Fatal("late failure committed consumption")
			}
		})
	}
}

func TestWindowsEnrollmentReplayRevocationAndImmutableState(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	i, request, _ := enrollmentTestRequest(t, s)
	ctx := context.Background()
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE mdm_windows_devices SET site_id=12 WHERE invitation_id=$1`,
		`UPDATE mdm_windows_devices SET reported_device_id='replacement' WHERE invitation_id=$1`,
		`DELETE FROM mdm_windows_devices WHERE invitation_id=$1`,
		`UPDATE mdm_windows_device_certificates SET certificate=decode('010203','hex') WHERE device_id=(SELECT device_id FROM mdm_windows_enrollments WHERE invitation_id=$1)`,
		`DELETE FROM mdm_windows_device_certificates WHERE device_id=(SELECT device_id FROM mdm_windows_enrollments WHERE invitation_id=$1)`,
		`UPDATE mdm_windows_enrollments SET encrypted_auth=decode(repeat('00',32),'hex') WHERE invitation_id=$1`,
		`DELETE FROM mdm_windows_enrollments WHERE invitation_id=$1`,
	} {
		if _, err := s.db.Exec(statement, i.ID); err == nil {
			t.Fatal("immutable issuance state changed")
		}
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_device_certificates SET revoked_at=clock_timestamp() WHERE device_id=(SELECT device_id FROM mdm_windows_enrollments WHERE invitation_id=$1)`, i.ID); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrCredential) || data != nil {
		t.Fatal("revoked certificate returned provisioning")
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_device_certificates SET revoked_at=NULL WHERE device_id=(SELECT device_id FROM mdm_windows_enrollments WHERE invitation_id=$1)`, i.ID); err == nil {
		t.Fatal("certificate revocation was cleared")
	}
	i, request, _ = enrollmentTestRequest(t, s)
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_devices SET revoked_at=clock_timestamp() WHERE invitation_id=$1`, i.ID); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrCredential) || data != nil {
		t.Fatal("revoked device returned provisioning")
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_devices SET revoked_at=NULL WHERE invitation_id=$1`, i.ID); err == nil {
		t.Fatal("device revocation was cleared")
	}
	i, request, _ = enrollmentTestRequest(t, s)
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeEnrollmentInvitation(ctx, "operator", credentialTestScope, i.ID); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrCredential) || data != nil {
		t.Fatal("revoked invitation returned provisioning")
	}
	_, request, _ = enrollmentTestRequest(t, s)
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal(err)
	}
	if err := s.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Viewer, Scope: credentialTestScope}}); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrCredential) || data != nil {
		t.Fatal("revoked permissions returned completed provisioning")
	}
}

func TestWindowsEnrollmentReplayWindowAndCiphertextTampering(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	ctx := context.Background()
	var now time.Time
	if err := s.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	i, c := insertTimedInvitation(t, s, now.Add(-time.Hour), now.Add(time.Hour))
	_, der := enrollmentTestCSR(t)
	request := &WSTEPRequest{MessageID: discoveryTestID, Credential: *c, CSRDER: der, Context: wstepTestContext()}
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal(err)
	}
	state := readEnrollmentTestResult(t, s, i.ID)
	// Deliberate corruption only in this test's owned random schema. Production
	// update triggers are tested above; AEAD must also detect an altered backup.
	if _, err := s.db.Exec(`ALTER TABLE mdm_windows_enrollments DISABLE TRIGGER mdm_windows_enrollment_result`); err != nil {
		t.Fatal(err)
	}
	defer s.db.Exec(`ALTER TABLE mdm_windows_enrollments ENABLE TRIGGER mdm_windows_enrollment_result`)
	for _, corrupt := range [][]byte{bytes.Repeat([]byte{1}, len(state.Provisioning)), state.Auth} {
		if _, err := s.db.Exec(`UPDATE mdm_windows_enrollments SET encrypted_provisioning=$1 WHERE invitation_id=$2`, corrupt, i.ID); err != nil {
			t.Fatal(err)
		}
		if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrAuthoritySecret) || data != nil {
			t.Fatal("tampered or cross-purpose ciphertext returned provisioning")
		}
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_enrollments SET encrypted_provisioning=$1 WHERE invitation_id=$2`, state.Provisioning, i.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_enrollments SET encrypted_auth=$1 WHERE invitation_id=$2`, bytes.Repeat([]byte{1}, len(state.Auth)), i.ID); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrAuthoritySecret) || data != nil {
		t.Fatal("corrupt management credentials returned usable-looking provisioning")
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_enrollments SET encrypted_auth=$1 WHERE invitation_id=$2`, state.Auth, i.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal("restored encrypted result failed", err)
	}
	if _, err := s.db.Exec(`ALTER TABLE mdm_windows_invitations DISABLE TRIGGER mdm_windows_invitation_identity`); err != nil {
		t.Fatal(err)
	}
	defer s.db.Exec(`ALTER TABLE mdm_windows_invitations ENABLE TRIGGER mdm_windows_invitation_identity`)
	for _, timestamp := range []string{"clock_timestamp()-INTERVAL '11 minutes'", "clock_timestamp()+INTERVAL '1 minute'"} {
		if _, err := s.db.Exec(`UPDATE mdm_windows_invitations SET consumed_at=`+timestamp+` WHERE id=$1`, i.ID); err != nil {
			t.Fatal(err)
		}
		if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrCredential) || data != nil {
			t.Fatal("completed invitation outside retry window admitted")
		}
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_invitations SET consumed_at=clock_timestamp()-INTERVAL '2 minutes',expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE id=$1`, i.ID); err != nil {
		t.Fatal(err)
	}
	if data, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); !errors.Is(err, ErrCredential) || data != nil {
		t.Fatal("expired invitation returned completed provisioning")
	}
}

func TestWindowsEnrollmentUpgradePreservesExistingCA(t *testing.T) {
	base := credentialTestStoreBeforeMigration(t)
	ctx := context.Background()
	tx, err := base.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE mdm_windows_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"migrations/001_enrollment_credentials.sql", "migrations/002_enrollment_authorities.sql"} {
		body, err := migrations.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_migrations(name) VALUES($1)`, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s, err := NewStoreWithMasterKey(base.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	a := initializeTestAuthority(t, s, 1)
	i, request, _ := enrollmentTestRequest(t, s)
	if _, err := s.EnrollmentPolicyResponse(ctx, &PolicyRequest{MessageID: request.MessageID, Credential: request.Credential}); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	read, err := s.EnrollmentAuthority(ctx, "admin", 1)
	if err != nil || read.ID != a.ID || !bytes.Equal(read.Certificate, a.Certificate) {
		t.Fatal("device enrollment migration replaced the CA")
	}
	if _, err := s.EnrollWindows(ctx, request, enrollmentTestOptions()); err != nil {
		t.Fatal("upgraded credential failed to enroll", err)
	}
	if invitationEventCount(t, s, i.ID, "policy.read") != 1 {
		t.Fatal("migration changed prior audit")
	}
	if _, err := s.db.Exec(`INSERT INTO mdm_windows_audit(resource_id,tenant_id,site_id,actor,action) VALUES($1,1,12,'synthetic','enrollment.replayed')`, i.ID); err == nil {
		t.Fatal("cross-site invitation audit admitted")
	}
	state := readEnrollmentTestResult(t, s, i.ID)
	if state.AuthorityID != a.ID {
		t.Fatal("upgraded enrollment used a different issuer")
	}
}
