package windows

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var credentialTestScope = access.Scope{TenantID: 1, SiteID: 11}

func credentialTestStore(t *testing.T) *Store {
	t.Helper()
	s := credentialTestStoreBeforeMigration(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal("migration is not idempotent", err)
	}
	return s
}

func credentialTestStoreBeforeMigration(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("WINDOWS_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set WINDOWS_MDM_TEST_DATABASE_URL for isolated native Windows PostgreSQL tests")
	}
	u, err := url.Parse(dsn)
	port := "55440"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		port = "5432"
	}
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() != port || u.Path != "/openuem_test" || u.User == nil || u.User.Username() != "openuem_test" {
		t.Fatal("Windows integration tests require the reserved loopback test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open isolated PostgreSQL connection")
	}
	t.Cleanup(func() { admin.Close() })
	var database, user string
	var actualPort, version int
	if err := admin.QueryRowContext(ctx, `SELECT current_database(),current_user,inet_server_port(),current_setting('server_version_num')::integer`).Scan(&database, &user, &actualPort, &version); err != nil {
		t.Fatal(err)
	}
	if database != "openuem_test" || user != "openuem_test" || fmt.Sprint(actualPort) != port || version < 170000 || version >= 180000 {
		t.Fatal("unexpected test database identity or version")
	}
	schema := "mdm_windows_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal("open isolated schema connection")
	}
	db.SetMaxOpenConns(12)
	t.Cleanup(func() {
		db.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	})
	return initializeCredentialTestStore(t, db)
}

func initializeCredentialTestStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, `CREATE TABLE users(uid TEXT PRIMARY KEY); CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT REFERENCES tenants(id)); INSERT INTO users VALUES('admin'),('operator'),('viewer'),('foreign'),('second'); INSERT INTO tenants VALUES(1),(2); INSERT INTO sites VALUES(11,1),(12,1),(21,2); CREATE TABLE simulated_windows_issuance(id UUID PRIMARY KEY,tenant_id BIGINT NOT NULL,site_id BIGINT NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.permissions.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.permissions.Bootstrap(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	for actor, grant := range map[string]access.Grant{
		"operator": {Role: access.Operator, Scope: credentialTestScope},
		"viewer":   {Role: access.Viewer, Scope: credentialTestScope},
		"foreign":  {Role: access.TenantAdmin, Scope: access.Scope{TenantID: 2}},
		"second":   {Role: access.Operator, Scope: credentialTestScope},
	} {
		if err := s.permissions.ReplaceGrants(ctx, "admin", actor, 0, []access.Grant{grant}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func createTestInvitation(t *testing.T, s *Store, actor string) (*EnrollmentInvitation, *UsernameCredential) {
	t.Helper()
	i, c, err := s.CreateEnrollmentInvitation(context.Background(), actor, credentialTestScope, "synthetic@example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return i, c
}

func invitationEventCount(t *testing.T, s *Store, id, action string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_audit WHERE resource_id=$1 AND action=$2`, id, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWindowsCredentialPersistenceScopeAndPrivacy(t *testing.T) {
	s := credentialTestStore(t)
	ctx := context.Background()
	i, c := createTestInvitation(t, s, "operator")
	if i.Scope != credentialTestScope || i.CreatedBy != "operator" || i.CreatedByRevision != 1 || i.ExpiresAt.Sub(i.CreatedAt) != time.Hour || i.RevokedAt != nil || i.ConsumedAt != nil {
		t.Fatal("invitation scope, permission revision or lifetime changed")
	}
	id, secret, err := decodeEnrollmentPassword(c.Password)
	if err != nil || id != i.ID || len(secret) != 32 {
		t.Fatal("generated enrollment password is not canonical")
	}
	var storedDigest []byte
	if err := s.db.QueryRow(`SELECT credential_digest FROM mdm_windows_invitations WHERE id=$1`, i.ID).Scan(&storedDigest); err != nil {
		t.Fatal(err)
	}
	if len(storedDigest) != 32 || string(storedDigest) == string(secret) || string(storedDigest) == c.Password {
		t.Fatal("database stores the raw enrollment secret")
	}
	var state, audit string
	if err := s.db.QueryRow(`SELECT row_to_json(i)::text FROM mdm_windows_invitations i WHERE id=$1`, i.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT json_agg(a)::text FROM mdm_windows_audit a WHERE resource_id=$1`, i.ID).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{state, audit} {
		if strings.Contains(value, c.Password) || strings.Contains(value, base64.RawURLEncoding.EncodeToString(secret)) {
			t.Fatal("persisted state exposed an enrollment password")
		}
	}
	if strings.Contains(audit, i.Username) {
		t.Fatal("audit copied account hints")
	}
	restarted, err := NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		accepted, err := restarted.CheckPolicyCredential(ctx, *c)
		if err != nil || accepted.ID != i.ID || accepted.Scope != credentialTestScope {
			t.Fatal("policy authorization did not survive restart")
		}
	}
	if invitationEventCount(t, s, i.ID, "invitation.consumed") != 0 {
		t.Fatal("policy read consumed an invitation")
	}
	read, err := s.EnrollmentInvitation(ctx, "second", credentialTestScope, i.ID)
	if err != nil || read.ID != i.ID || read.ConsumedAt != nil {
		t.Fatal("authorized scoped metadata read failed")
	}
	for _, test := range []struct {
		actor string
		scope access.Scope
	}{
		{"viewer", credentialTestScope}, {"foreign", credentialTestScope}, {"operator", access.Scope{TenantID: 1, SiteID: 12}},
		{"admin", access.Scope{TenantID: 2, SiteID: 21}}, {"admin", access.Scope{TenantID: 1, SiteID: 21}}, {"admin", access.Scope{TenantID: 1}},
	} {
		if got, err := s.EnrollmentInvitation(ctx, test.actor, test.scope, i.ID); err == nil || got != nil {
			t.Fatal("foreign or unauthorized metadata read admitted")
		}
		if err := s.RevokeEnrollmentInvitation(ctx, test.actor, test.scope, i.ID); err == nil {
			t.Fatal("foreign or unauthorized revocation admitted")
		}
	}
	if invitationEventCount(t, s, i.ID, "invitation.read") != 1 || invitationEventCount(t, s, i.ID, "invitation.revoked") != 0 {
		t.Fatal("failed scoped operations changed audit/state")
	}
	if _, err := s.CheckPolicyCredential(ctx, *c); err != nil {
		t.Fatal("failed foreign operation invalidated a valid credential")
	}
}

func TestWindowsCredentialInputAndVerifierBinding(t *testing.T) {
	s := credentialTestStore(t)
	ctx := context.Background()
	i, c := createTestInvitation(t, s, "operator")
	_, changedSecret, err := decodeEnrollmentPassword(c.Password)
	if err != nil {
		t.Fatal(err)
	}
	changedSecret[0] ^= 0xff
	wrongPassword := "owin1." + i.ID + "." + base64.RawURLEncoding.EncodeToString(changedSecret)
	for _, credential := range []UsernameCredential{
		{}, {Username: c.Username, Password: "a real account password is not an enrollment token"},
		{Username: "other@example.test", Password: c.Password}, {Username: strings.ToUpper(c.Username), Password: c.Password},
		{Username: c.Username, Password: c.Password + " "}, {Username: c.Username, Password: strings.Replace(c.Password, i.ID, uuid.NewString(), 1)},
		{Username: c.Username, Password: wrongPassword},
	} {
		if got, err := s.CheckPolicyCredential(ctx, credential); !errors.Is(err, ErrCredential) || got != nil {
			t.Fatal("invalid credential returned scope or was accepted")
		}
	}
	_, secret, err := decodeEnrollmentPassword(c.Password)
	if err != nil {
		t.Fatal(err)
	}
	original := invitationDigest(secret, *i)
	for name, edit := range map[string]func(*EnrollmentInvitation){
		"id": func(i *EnrollmentInvitation) { i.ID = uuid.NewString() }, "organization": func(i *EnrollmentInvitation) { i.TenantID = 2 },
		"site": func(i *EnrollmentInvitation) { i.SiteID = 12 }, "username": func(i *EnrollmentInvitation) { i.Username = "other@example.test" },
		"issuer": func(i *EnrollmentInvitation) { i.CreatedBy = "second" }, "permission revision": func(i *EnrollmentInvitation) { i.CreatedByRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *i
			edit(&changed)
			if string(original) == string(invitationDigest(secret, changed)) {
				t.Fatal("verifier was not bound to immutable metadata")
			}
		})
	}
	for _, test := range []struct {
		actor, username string
		scope           access.Scope
		ttl             time.Duration
	}{
		{"viewer", c.Username, credentialTestScope, time.Hour}, {"foreign", c.Username, credentialTestScope, time.Hour},
		{"admin", c.Username, access.Scope{TenantID: 1, SiteID: 21}, time.Hour}, {"admin", c.Username, access.Scope{TenantID: 1}, time.Hour},
		{"operator", "", credentialTestScope, time.Hour}, {"operator", " leading", credentialTestScope, time.Hour},
		{"operator", "line\nbreak", credentialTestScope, time.Hour}, {"operator", strings.Repeat("a", 321), credentialTestScope, time.Hour},
		{"operator", c.Username, credentialTestScope, 59 * time.Second}, {"operator", c.Username, credentialTestScope, 25 * time.Hour},
		{"operator", c.Username, credentialTestScope, time.Minute + time.Nanosecond},
	} {
		got, secret, err := s.CreateEnrollmentInvitation(ctx, test.actor, test.scope, test.username, test.ttl)
		if err == nil || got != nil || secret != nil {
			t.Fatal("invalid creation disclosed a usable credential")
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_invitations`).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed creation changed stored invitations")
	}
}

func waitForCredentialLock(t *testing.T, db *sql.DB, blocker, expected int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count >= expected {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("transaction did not wait on the expected enrollment lock")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitUntilDatabaseExpiry(ctx context.Context, tx *sql.Tx, expires time.Time) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())),0)+0.03)`, expires)
	return err
}

func TestWindowsCredentialExpiryAfterLockAndDuringIssue(t *testing.T) {
	s := credentialTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var now time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	i, c := insertTimedInvitation(t, s, now.Add(-time.Hour), now.Add(2*time.Second))
	hold, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	var pid int
	if err := hold.QueryRowContext(ctx, `SELECT pg_backend_pid() FROM mdm_windows_invitations WHERE id=$1 FOR UPDATE`, i.ID).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := s.CheckPolicyCredential(ctx, *c); result <- err }()
	waitForCredentialLock(t, s.db, pid, 1)
	if err := waitUntilDatabaseExpiry(ctx, hold, i.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrCredential) {
		t.Fatal("credential expired while waiting for its row lock was accepted", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	i, c = insertTimedInvitation(t, s, now.Add(-time.Hour), now.Add(2*time.Second))
	err = s.withEnrollmentCredential(ctx, *c, func(ctx context.Context, tx *sql.Tx, i EnrollmentInvitation) error {
		if err := simulatedIssuance(ctx, tx, i); err != nil {
			return err
		}
		return waitUntilDatabaseExpiry(ctx, tx, i.ExpiresAt)
	})
	if !errors.Is(err, ErrCredential) {
		t.Fatal("issuance accepted expiry during the transaction", err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM simulated_windows_issuance WHERE id=$1`, i.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("late expiry left partial issuance state")
	}
	if invitationEventCount(t, s, i.ID, "invitation.consumed") != 0 {
		t.Fatal("late expiry consumed the invitation")
	}
}

func TestWindowsCredentialPermissionAndSiteLocksSpanIssue(t *testing.T) {
	s := credentialTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	i, c := createTestInvitation(t, s, "operator")
	_, pending := createTestInvitation(t, s, "operator")
	entered := make(chan int, 1)
	release := make(chan struct{})
	issued := make(chan error, 1)
	go func() {
		issued <- s.withEnrollmentCredential(ctx, *c, func(ctx context.Context, tx *sql.Tx, i EnrollmentInvitation) error {
			var pid int
			if err := tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			if err := simulatedIssuance(ctx, tx, i); err != nil {
				return err
			}
			entered <- pid
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		})
	}()
	var pid int
	select {
	case pid = <-entered:
	case err := <-issued:
		t.Fatal("issuance did not enter the protected transaction", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	demoted := make(chan error, 1)
	moved := make(chan error, 1)
	go func() { demoted <- s.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil) }()
	go func() { _, err := s.db.ExecContext(ctx, `UPDATE sites SET tenant_sites=2 WHERE id=11`); moved <- err }()
	waitForCredentialLock(t, s.db, pid, 2)
	close(release)
	for _, result := range []<-chan error{issued, demoted, moved} {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	var tenant, site int
	if err := s.db.QueryRowContext(ctx, `SELECT tenant_id,site_id FROM simulated_windows_issuance WHERE id=$1`, i.ID).Scan(&tenant, &site); err != nil || tenant != 1 || site != 11 {
		t.Fatal("concurrent mutation changed authorized issuance scope")
	}
	if got, err := s.CheckPolicyCredential(ctx, *pending); !errors.Is(err, ErrCredential) || got != nil {
		t.Fatal("permission/scope change left pending credentials valid")
	}
}

func TestWindowsCredentialAuditFailureAndCancellationRollback(t *testing.T) {
	s := credentialTestStore(t)
	ctx := context.Background()
	i, c := createTestInvitation(t, s, "operator")
	_, err := s.db.Exec(`CREATE FUNCTION reject_windows_test_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END; $$; CREATE TRIGGER reject_windows_test_audit BEFORE INSERT ON mdm_windows_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_test_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if got, secret, err := s.CreateEnrollmentInvitation(ctx, "operator", credentialTestScope, c.Username, time.Hour); err == nil || got != nil || secret != nil {
		t.Fatal("audit failure returned a new credential")
	}
	if got, err := s.EnrollmentInvitation(ctx, "operator", credentialTestScope, i.ID); err == nil || got != nil {
		t.Fatal("audit failure returned scoped metadata")
	}
	if err := s.RevokeEnrollmentInvitation(ctx, "operator", credentialTestScope, i.ID); err == nil {
		t.Fatal("revocation ignored audit failure")
	}
	if err := s.withEnrollmentCredential(ctx, *c, simulatedIssuance); err == nil {
		t.Fatal("consumption ignored audit failure")
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_windows_test_audit ON mdm_windows_audit`); err != nil {
		t.Fatal(err)
	}
	var invitations, issuances int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_invitations),(SELECT count(*) FROM simulated_windows_issuance)`).Scan(&invitations, &issuances); err != nil || invitations != 1 || issuances != 0 {
		t.Fatal("audit failure left partial state")
	}
	if _, err := s.CheckPolicyCredential(ctx, *c); err != nil {
		t.Fatal("audit failure changed the invitation lifecycle")
	}
	cancelled, cancel := context.WithCancel(ctx)
	err = s.withEnrollmentCredential(cancelled, *c, func(ctx context.Context, tx *sql.Tx, i EnrollmentInvitation) error {
		if err := simulatedIssuance(ctx, tx, i); err != nil {
			return err
		}
		cancel()
		return nil
	})
	cancel()
	if err == nil {
		t.Fatal("cancelled issuance committed")
	}
	if _, err := s.CheckPolicyCredential(ctx, *c); err != nil {
		t.Fatal("cancellation consumed the invitation")
	}
	if err := s.withEnrollmentCredential(ctx, *c, simulatedIssuance); err != nil {
		t.Fatal("clean retry after rollback failed", err)
	}
}

func TestWindowsCredentialRevokeAndPermissionRevisions(t *testing.T) {
	s := credentialTestStore(t)
	ctx := context.Background()
	i, c := createTestInvitation(t, s, "operator")
	for n := 0; n < 2; n++ {
		if err := s.RevokeEnrollmentInvitation(ctx, "second", credentialTestScope, i.ID); err != nil {
			t.Fatal(err)
		}
	}
	if invitationEventCount(t, s, i.ID, "invitation.revoked") != 1 {
		t.Fatal("retry duplicated revocation audit")
	}
	if got, err := s.CheckPolicyCredential(ctx, *c); !errors.Is(err, ErrCredential) || got != nil {
		t.Fatal("revoked credential authorized policy retrieval")
	}
	for _, statement := range []string{`UPDATE mdm_windows_invitations SET revoked_at=NULL WHERE id=$1`, `UPDATE mdm_windows_invitations SET site_id=12 WHERE id=$1`, `UPDATE mdm_windows_invitations SET expires_at=expires_at+INTERVAL '1 minute' WHERE id=$1`, `UPDATE mdm_windows_invitations SET created_by_revision=2 WHERE id=$1`} {
		if _, err := s.db.Exec(statement, i.ID); err == nil {
			t.Fatal("database allowed invitation reassignment, extension or rearming")
		}
	}
	_, pending := createTestInvitation(t, s, "operator")
	if err := s.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CheckPolicyCredential(ctx, *pending); !errors.Is(err, ErrCredential) || got != nil {
		t.Fatal("demoted issuer retained enrollment authority")
	}
	if err := s.permissions.ReplaceGrants(ctx, "admin", "operator", 2, []access.Grant{{Role: access.Operator, Scope: credentialTestScope}}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CheckPolicyCredential(ctx, *pending); !errors.Is(err, ErrCredential) || got != nil {
		t.Fatal("regrant revived an old enrollment credential")
	}
	i, fresh := createTestInvitation(t, s, "operator")
	if i.CreatedByRevision != 3 {
		t.Fatal("fresh credential did not bind the new permission revision")
	}
	if _, err := s.CheckPolicyCredential(ctx, *fresh); err != nil {
		t.Fatal("fresh invitation rejected after rights restored")
	}
}

func simulatedIssuance(ctx context.Context, tx *sql.Tx, i EnrollmentInvitation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO simulated_windows_issuance(id,tenant_id,site_id) VALUES($1,$2,$3)`, i.ID, i.TenantID, i.SiteID)
	return err
}

func TestWindowsCredentialConcurrentSingleConsumptionAndRollback(t *testing.T) {
	s := credentialTestStore(t)
	ctx := context.Background()
	i, c := createTestInvitation(t, s, "operator")
	var callbacks atomic.Int32
	results := make(chan error, 12)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- s.withEnrollmentCredential(ctx, *c, func(ctx context.Context, tx *sql.Tx, i EnrollmentInvitation) error {
				callbacks.Add(1)
				return simulatedIssuance(ctx, tx, i)
			})
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded, denied := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrCredential) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || denied != 11 || callbacks.Load() != 1 || invitationEventCount(t, s, i.ID, "invitation.consumed") != 1 {
		t.Fatal("concurrent requests did not consume exactly once")
	}
	if _, err := s.CheckPolicyCredential(ctx, *c); !errors.Is(err, ErrCredential) {
		t.Fatal("consumed credential remained active")
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_invitations SET consumed_at=NULL WHERE id=$1`, i.ID); err == nil {
		t.Fatal("consumed credential was rearmed")
	}
	failed, fresh := createTestInvitation(t, s, "operator")
	issueError := errors.New("synthetic issuer rejected CSR")
	err := s.withEnrollmentCredential(ctx, *fresh, func(ctx context.Context, tx *sql.Tx, i EnrollmentInvitation) error {
		if err := simulatedIssuance(ctx, tx, i); err != nil {
			return err
		}
		return issueError
	})
	if !errors.Is(err, issueError) {
		t.Fatal("issuer failure was swallowed")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM simulated_windows_issuance WHERE id=$1`, failed.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("issuer state was not rolled back")
	}
	if invitationEventCount(t, s, failed.ID, "invitation.consumed") != 0 {
		t.Fatal("failed issuer left consumption audit")
	}
	if _, err := s.CheckPolicyCredential(ctx, *fresh); err != nil {
		t.Fatal("failed issuer consumed the invitation")
	}
	if err := s.withEnrollmentCredential(ctx, *fresh, simulatedIssuance); err != nil {
		t.Fatal("retry after rollback failed", err)
	}
}

// Direct synthetic insertion controls database times without changing host time
// or bypassing the production immutable-update trigger.
func insertTimedInvitation(t *testing.T, s *Store, created, expires time.Time) (*EnrollmentInvitation, *UsernameCredential) {
	t.Helper()
	i := EnrollmentInvitation{ID: uuid.NewString(), Scope: credentialTestScope, Username: "timing@example.test", CreatedBy: "operator", CreatedByRevision: 1}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	digest := invitationDigest(secret, i)
	stored, err := scanInvitation(s.db.QueryRow(`INSERT INTO mdm_windows_invitations(id,tenant_id,site_id,username,credential_digest,created_by,created_by_revision,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+invitationColumns, i.ID, i.TenantID, i.SiteID, i.Username, digest, i.CreatedBy, i.CreatedByRevision, created, expires))
	if err != nil {
		t.Fatal(err)
	}
	return stored, &UsernameCredential{Username: i.Username, Password: "owin1." + i.ID + "." + base64.RawURLEncoding.EncodeToString(secret)}
}

func TestWindowsCredentialDatabaseTimeAndScopeChanges(t *testing.T) {
	s := credentialTestStore(t)
	ctx := context.Background()
	var now time.Time
	if err := s.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	for _, times := range [][2]time.Time{{now.Add(-time.Hour), now.Add(-time.Second)}, {now.Add(time.Hour), now.Add(2 * time.Hour)}} {
		_, c := insertTimedInvitation(t, s, times[0], times[1])
		if got, err := s.CheckPolicyCredential(ctx, *c); !errors.Is(err, ErrCredential) || got != nil {
			t.Fatal("expired or future-created credential admitted")
		}
	}
	_, c := createTestInvitation(t, s, "operator")
	if _, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CheckPolicyCredential(ctx, *c); !errors.Is(err, ErrCredential) || got != nil {
		t.Fatal("site reparenting transferred enrollment authority")
	}
}

func TestWindowsCredentialCreationBoundaries(t *testing.T) {
	s := credentialTestStore(t)
	ctx := context.Background()
	for _, test := range []struct {
		username string
		ttl      time.Duration
	}{
		{`EXAMPLE\synthetic`, time.Minute}, {strings.Repeat("a", MaxEnrollmentUsernameBytes), 24 * time.Hour},
	} {
		i, c, err := s.CreateEnrollmentInvitation(ctx, "operator", credentialTestScope, test.username, test.ttl)
		if err != nil || i.ExpiresAt.Sub(i.CreatedAt) != test.ttl {
			t.Fatal("valid invitation boundary rejected", err)
		}
		accepted, err := s.CheckPolicyCredential(ctx, *c)
		if err != nil || accepted.Username != test.username {
			t.Fatal("valid boundary credential could not authorize a policy check", err)
		}
	}
}
