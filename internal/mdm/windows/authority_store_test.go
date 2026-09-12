package windows

import (
	"bytes"
	"context"
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

func authorityTestStore(t *testing.T) *Store {
	t.Helper()
	base := credentialTestStore(t)
	s, err := NewStoreWithMasterKey(base.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func initializeTestAuthority(t *testing.T, s *Store, tenant int) *EnrollmentAuthority {
	t.Helper()
	a, err := s.InitializeAuthority(context.Background(), "admin", tenant, authorityTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func loadTestAuthority(t *testing.T, s *Store, tenant int) (*authoritySigner, error) {
	t.Helper()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	return s.enrollmentAuthority(context.Background(), tx, tenant)
}

func authorityAuditCount(t *testing.T, s *Store, tenant int, action string) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_authority_audit WHERE tenant_id=$1 AND action=$2`, tenant, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAuthorityPersistenceScopeAndImmutability(t *testing.T) {
	s := authorityTestStore(t)
	ctx := context.Background()
	for _, actor := range []string{"operator", "viewer", "foreign", "missing", "", "bad\nactor"} {
		if a, err := s.InitializeAuthority(ctx, actor, 1, authorityTestOptions()); err == nil || a != nil {
			t.Fatal("unprivileged or foreign CA creation admitted")
		}
	}
	for _, tenant := range []int{0, -1, 3} {
		if a, err := s.InitializeAuthority(ctx, "admin", tenant, authorityTestOptions()); err == nil || a != nil {
			t.Fatal("invalid organization admitted")
		}
	}
	a := initializeTestAuthority(t, s, 1)
	if authorityAuditCount(t, s, 1, "authority.created") != 1 || len(a.FingerprintSHA256) != 64 || a.CreatedBy != "admin" || a.CreatedAt.IsZero() {
		t.Fatal("CA metadata or audit missing")
	}
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if got, err := s.EnrollmentAuthority(ctx, actor, 1); err == nil || got != nil {
			t.Fatal("unprivileged or foreign CA read admitted")
		}
	}
	if _, err := s.EnrollmentAuthority(ctx, "admin", 2); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.InitializeAuthority(ctx, "admin", 1, authorityTestOptions()); !errors.Is(err, ErrAuthorityExists) {
		t.Fatal("retry replaced CA")
	}
	readOnly, err := NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	read, err := readOnly.EnrollmentAuthority(ctx, "admin", 1)
	if err != nil || read.ID != a.ID || !bytes.Equal(read.Certificate, a.Certificate) || read.FingerprintSHA256 != a.FingerprintSHA256 {
		t.Fatal("public metadata did not survive restart")
	}
	if _, err := readOnly.InitializeAuthority(ctx, "admin", 2, authorityTestOptions()); !errors.Is(err, ErrMasterKey) {
		t.Fatal("CA initialized without encryption key")
	}
	if _, err := loadTestAuthority(t, readOnly, 1); !errors.Is(err, ErrMasterKey) {
		t.Fatal("private CA loaded without master key")
	}
	restarted, err := NewStoreWithMasterKey(s.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := loadTestAuthority(t, restarted, 1)
	if err != nil || signer.metadata.ID != a.ID {
		t.Fatal("protected CA did not survive restart")
	}
	private, err := x509.MarshalPKCS8PrivateKey(signer.key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	var encrypted []byte
	var state, audit string
	if err := s.db.QueryRow(`SELECT encrypted_key,row_to_json(a)::text FROM mdm_windows_authorities a WHERE id=$1`, a.ID).Scan(&encrypted, &state); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT json_agg(a)::text FROM mdm_windows_authority_audit a`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(read)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, private) || bytes.Contains(metadata, encrypted) || strings.Contains(string(metadata), "encrypted_key") {
		t.Fatal("private key exposed in public metadata")
	}
	for _, value := range []string{state, audit, string(metadata)} {
		if strings.Contains(value, base64.StdEncoding.EncodeToString(private)) || strings.Contains(value, authorityTestMasterKey) {
			t.Fatal("private key or master key leaked")
		}
	}
	wrong, err := NewStoreWithMasterKey(s.db, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadTestAuthority(t, wrong, 1); !errors.Is(err, ErrAuthoritySecret) {
		t.Fatal("incorrect restart key accepted")
	}
	for _, statement := range []string{
		`UPDATE mdm_windows_authorities SET tenant_id=2 WHERE id=$1`,
		`UPDATE mdm_windows_authorities SET minimum_key_bits=4096 WHERE id=$1`,
		`UPDATE mdm_windows_authorities SET encrypted_key=decode(repeat('00',32),'hex') WHERE id=$1`,
		`DELETE FROM mdm_windows_authorities WHERE id=$1`,
	} {
		if _, err := s.db.Exec(statement, a.ID); err == nil {
			t.Fatal("immutable authority changed")
		}
	}
	if _, err := s.db.Exec(`INSERT INTO mdm_windows_authority_audit(tenant_id,actor,action,authority_id) VALUES(2,'admin','authority.read',$1)`, a.ID); err == nil {
		t.Fatal("cross-organization audit reference admitted")
	}
	foreign, err := s.InitializeAuthority(ctx, "foreign", 2, authorityTestOptions())
	if err != nil || foreign.TenantID != 2 || foreign.ID == a.ID || bytes.Equal(foreign.Certificate, a.Certificate) {
		t.Fatal("organization administrator could not create separate CA")
	}
	if _, err := s.EnrollmentAuthority(ctx, "foreign", 2); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityConcurrentInitialization(t *testing.T) {
	s := authorityTestStore(t)
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.InitializeAuthority(context.Background(), "admin", 1, authorityTestOptions())
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	ok, duplicate := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrAuthorityExists) {
			duplicate++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || duplicate != 7 || authorityAuditCount(t, s, 1, "authority.created") != 1 {
		t.Fatal("concurrent initialization created multiple issuers")
	}
}

func TestAuthorityMigrationPreservesExistingCredentials(t *testing.T) {
	s := credentialTestStoreBeforeMigration(t)
	ctx := context.Background()
	// Reproduce the previously released native Windows schema and its ledger,
	// populate live credentials, then execute the ordinary upgrade path.
	initial, err := migrations.ReadFile("migrations/001_enrollment_credentials.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, string(initial)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE mdm_windows_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()); INSERT INTO mdm_windows_migrations(name) VALUES('migrations/001_enrollment_credentials.sql')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	i, c := createTestInvitation(t, s, "operator")
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := s.CheckPolicyCredential(ctx, *c)
	if err != nil || current.ID != i.ID || current.Scope != i.Scope || current.ConsumedAt != nil {
		t.Fatal("CA migration changed an existing credential")
	}
	if invitationEventCount(t, s, i.ID, "invitation.created") != 1 {
		t.Fatal("migration changed existing audit events")
	}
	protected, err := NewStoreWithMasterKey(s.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	initializeTestAuthority(t, protected, 1)
	if _, err := protected.EnrollmentPolicyResponse(ctx, &PolicyRequest{MessageID: discoveryTestID, Credential: *c}); err != nil {
		t.Fatal("upgraded credential cannot retrieve policy", err)
	}
}

func TestAuthorityAuditFailureRollsBack(t *testing.T) {
	s := authorityTestStore(t)
	ctx := context.Background()
	_, err := s.db.Exec(`CREATE FUNCTION reject_windows_authority_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END; $$; CREATE TRIGGER reject_windows_authority_audit BEFORE INSERT ON mdm_windows_authority_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_authority_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := s.InitializeAuthority(ctx, "admin", 1, authorityTestOptions()); err == nil || a != nil {
		t.Fatal("audit failure returned a CA")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_authorities`).Scan(&count); err != nil || count != 0 {
		t.Fatal("audit failure left a partial issuer")
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_windows_authority_audit ON mdm_windows_authority_audit`); err != nil {
		t.Fatal(err)
	}
	initializeTestAuthority(t, s, 1)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_windows_authority_audit BEFORE INSERT ON mdm_windows_authority_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_authority_audit()`); err != nil {
		t.Fatal(err)
	}
	if a, err := s.EnrollmentAuthority(ctx, "admin", 1); err == nil || a != nil {
		t.Fatal("read audit failure returned metadata")
	}
	if authorityAuditCount(t, s, 1, "authority.read") != 0 {
		t.Fatal("failed read left audit")
	}
}

func TestEnrollmentPolicyAuthorizationAndRollback(t *testing.T) {
	s := authorityTestStore(t)
	ctx := context.Background()
	i, credential := createTestInvitation(t, s, "operator")
	r := &PolicyRequest{MessageID: discoveryTestID, Credential: *credential}
	if got, err := s.EnrollmentPolicyResponse(ctx, r); !errors.Is(err, ErrAuthorityUnavailable) || got != nil {
		t.Fatal("policy returned without CA")
	}
	a := initializeTestAuthority(t, s, 1)
	for n := 0; n < 3; n++ {
		got, err := s.EnrollmentPolicyResponse(ctx, r)
		if err != nil || !bytes.Contains(got, []byte(a.ID)) || bytes.Contains(got, []byte(credential.Password)) || bytes.Contains(got, []byte(credential.Username)) {
			t.Fatal("authorized policy response is absent or leaks credentials")
		}
	}
	if invitationEventCount(t, s, i.ID, "policy.read") != 3 || invitationEventCount(t, s, i.ID, "invitation.consumed") != 0 {
		t.Fatal("policy read was not audited independently")
	}
	for _, invalid := range []*PolicyRequest{nil, {}, {MessageID: "invalid", Credential: *credential}, {MessageID: discoveryTestID, Credential: UsernameCredential{Username: credential.Username, Password: "wrong"}}} {
		if got, err := s.EnrollmentPolicyResponse(ctx, invalid); err == nil || got != nil {
			t.Fatal("invalid policy request returned data")
		}
	}
	readOnly, _ := NewStore(s.db)
	if got, err := readOnly.EnrollmentPolicyResponse(ctx, r); !errors.Is(err, ErrMasterKey) || got != nil {
		t.Fatal("policy advertised an unusable CA")
	}
	_, err := s.db.Exec(`CREATE FUNCTION reject_windows_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='policy.read' THEN RAISE EXCEPTION 'synthetic policy audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_windows_policy_audit BEFORE INSERT ON mdm_windows_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_policy_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.EnrollmentPolicyResponse(ctx, r); err == nil || got != nil {
		t.Fatal("policy audit failure returned a response")
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_windows_policy_audit ON mdm_windows_audit`); err != nil {
		t.Fatal(err)
	}
	if invitationEventCount(t, s, i.ID, "policy.read") != 3 {
		t.Fatal("failed request committed audit")
	}
	if err := s.RevokeEnrollmentInvitation(ctx, "operator", credentialTestScope, i.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := s.EnrollmentPolicyResponse(ctx, r); !errors.Is(err, ErrCredential) || got != nil {
		t.Fatal("revoked credential returned policy")
	}
	_, credential = createTestInvitation(t, s, "operator")
	r.Credential = *credential
	if err := s.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Viewer, Scope: credentialTestScope}}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.EnrollmentPolicyResponse(ctx, r); !errors.Is(err, ErrCredential) || got != nil {
		t.Fatal("revoked permissions returned policy")
	}
}

func TestEnrollmentPolicyExpiryDuringAudit(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var now time.Time
	if err := s.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	i, c := insertTimedInvitation(t, s, now.Add(-time.Minute), now.Add(2*time.Second))
	// Block the audit after credential and CA authorization. Expiration while
	// waiting must roll back the event and suppress the already-built response.
	blocker, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	var pid int
	if err := blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(ctx, `LOCK TABLE mdm_windows_audit IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		data, err := s.EnrollmentPolicyResponse(ctx, &PolicyRequest{MessageID: discoveryTestID, Credential: *c})
		if data != nil {
			result <- errors.New("expired policy returned data")
			return
		}
		result <- err
	}()
	waitForCredentialLock(t, s.db, pid, 1)
	if err := waitUntilDatabaseExpiry(ctx, blocker, i.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrCredential) {
		t.Fatal(err)
	}
	if invitationEventCount(t, s, i.ID, "policy.read") != 0 {
		t.Fatal("late policy expiry committed audit")
	}
}
