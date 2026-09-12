package sessions_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/utils"
)

type sessionFixture struct {
	store *sessions.PostgresStore
	model *models.Model
	pool  *pgxpool.Pool
	key   string
}

func blockedCleanup(t *testing.T, f sessionFixture) *sessions.PostgresStore {
	t.Helper()
	store := sessions.NewWithConfig(f.pool, sessions.Config{CleanUpInterval: time.Millisecond, EncryptionMasterKey: f.key})
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx, err := f.model.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err = tx.ExecContext(t.Context(), `LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE 'DELETE FROM %')`, f.pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting); err != nil {
			store.StopCleanup()
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			store.StopCleanup()
			t.Fatal("cleanup never reached its blocked database attempt")
		}
		time.Sleep(time.Millisecond)
	}
	return store
}

func TestSessionCleanupStopCancelsAndJoinsConcurrently(t *testing.T) {
	f := newSessionFixture(t, false)
	store := blockedCleanup(t, f)
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(store.StopCleanup)
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup shutdown did not cancel and join its blocked query")
	}
	store.StopCleanup()
	// pgx releases the lease before returning, but destroys a canceled connection
	// asynchronously. The locked query must disappear without releasing our lock.
	deadline := time.Now().Add(2 * time.Second)
	for f.pool.Stat().AcquiredConns() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.pool.Stat().AcquiredConns() != 0 {
		t.Fatal("cleanup retained a database connection after shutdown")
	}
	f.store.StopCleanup() // Cleanup is disabled for this store.
}

func TestSessionManagerCloseJoinsCleanupBeforePoolClose(t *testing.T) {
	f := newSessionFixture(t, false)
	store := blockedCleanup(t, f)
	sm := &sessions.SessionManager{Manager: scs.New(), Pool: f.pool}
	sm.Manager.Store = store
	done := make(chan struct{})
	go func() { sm.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("manager closed the pool before stopping its blocked cleanup worker")
	}
	sm.Close()
	var absent *sessions.SessionManager
	absent.Close()
	(&sessions.SessionManager{Manager: scs.New()}).Close()
}

func newSessionFixture(t *testing.T, encrypted bool, connections ...int32) sessionFixture {
	t.Helper()
	f := newLegacySessionFixture(t, encrypted, connections...)
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return f
}

func newLegacySessionFixture(t *testing.T, encrypted bool, connections ...int32) sessionFixture {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for session storage integration")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "session_store_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	t.Setenv("ENV", "test")
	m, err := models.New(u.String(), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["application_name"] = schema
	// Store transactions must explicitly select the isolation they need, rather
	// than inherit a deployment's stronger default and its older read snapshot.
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	if len(connections) > 0 {
		config.MaxConns = connections[0]
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		m.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	key := ""
	if encrypted {
		key = strings.Repeat("k", 32)
	}
	return sessionFixture{sessions.NewWithConfig(pool, sessions.Config{EncryptionMasterKey: key}), m, pool, key}
}

func TestEncryptedLegacyDuplicateDeletionAndSingleConnection(t *testing.T) {
	f := newLegacySessionFixture(t, true, 1)
	token := strings.Repeat("a", 43)
	for i := range 3 {
		record, err := utils.EncryptSensitiveField(token, f.key)
		if err != nil {
			t.Fatal(err)
		}
		expiry := time.Now().Add(time.Hour)
		if i == 2 {
			expiry = time.Now().Add(-time.Hour)
		}
		if _, err = f.model.DB.Exec(`INSERT INTO sessions(token,data,expiry) VALUES($1,$2,$3)`, record, []byte("owned duplicate"), expiry); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.model.DB.Exec(`INSERT INTO sessions(token,data,expiry) VALUES('00',$1,$2)`, []byte("malformed legacy"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CommitCtx(t.Context(), token, []byte("replacement"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("retired duplicate credential was recreated")
	}
	if _, found, err := f.store.FindCtx(t.Context(), token); err != nil || found {
		t.Fatal("ambiguous old session survived migration", found, err)
	}
	var count int
	if err := f.model.DB.QueryRow(`SELECT count(*) FROM sessions`).Scan(&count); err != nil || count != 1 {
		t.Fatal("expired duplicate remained after migration", count, err)
	}
	if err := f.store.DeleteCtx(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	token = strings.Repeat("b", 43)
	deadline, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for range 2 {
		if err := f.store.CommitCtx(deadline, token, []byte("current"), time.Now().Add(time.Hour)); err != nil {
			t.Fatal("single-connection update failed", err)
		}
	}
	if data, found, err := f.store.FindCtx(deadline, token); err != nil || !found || string(data) != "current" {
		t.Fatal("malformed unrelated record broke lookup", found, err)
	}
	if err := f.store.DeleteCtx(deadline, token); err != nil {
		t.Fatal(err)
	}
}

func TestSessionTokenMigrationPreservesOneOwnedRecord(t *testing.T) {
	f := newLegacySessionFixture(t, true)
	ctx := t.Context()
	token := strings.Repeat("z", 43)
	if err := f.model.Client.User.Create().SetID("owner").SetName("Owned user").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.model.Client.Sessions.Create().SetID(token).SetData([]byte("old")).SetExpiry(time.Now().Add(time.Hour)).SetOwnerID("owner").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	candidates := make([]string, 2)
	for i := range candidates {
		record, err := utils.EncryptSensitiveField(token, f.key)
		if err != nil {
			t.Fatal(err)
		}
		candidates[i] = record
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, record := range candidates {
		wg.Go(func() { <-start; results <- f.model.UpdateSessionToken(token, record) })
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent migrations did not select one replacement", success)
	}
	if err := f.store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CommitCtx(ctx, token, []byte("new"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var count int
	var owner string
	if err := f.model.DB.QueryRow(`SELECT count(*),min(user_sessions) FROM sessions`).Scan(&count, &owner); err != nil || count != 1 || owner != "owner" {
		t.Fatal("token migration lost ownership or duplicated data", count, owner, err)
	}
	if data, found, err := f.store.FindCtx(ctx, token); err != nil || !found || string(data) != "new" {
		t.Fatal("migrated token unavailable", found, err)
	}
	var cipher string
	if err := f.model.DB.QueryRow(`SELECT token FROM sessions`).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.store.FindCtx(ctx, cipher); err != nil || found {
		t.Fatal("database ciphertext accepted as browser credential", found, err)
	}
}

func TestEncryptedSessionConcurrentCommitAndDelete(t *testing.T) {
	f := newSessionFixture(t, true)
	ctx := t.Context()
	// Ensure concurrent first inserts overlap after each read has seen no row.
	if _, err := f.model.DB.Exec(`CREATE FUNCTION slow_owned_session_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.08); RETURN NEW; END $$; CREATE TRIGGER slow_owned_session_insert BEFORE INSERT ON sessions FOR EACH ROW EXECUTE FUNCTION slow_owned_session_insert()`); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 43)
	start := make(chan struct{})
	results := make(chan error, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			<-start
			results <- f.store.CommitCtx(ctx, token, []byte("owned session"), time.Now().Add(time.Hour))
		})
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := f.model.DB.QueryRow(`SELECT count(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("concurrent commits created %d physical rows for one browser token", count)
	}
	if err := f.store.DeleteCtx(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.store.FindCtx(ctx, token); err != nil || found {
		t.Fatal("deleted session remained usable", found, err)
	}
}

func TestEncryptedSessionReportsStorageErrors(t *testing.T) {
	f := newSessionFixture(t, true)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := f.store.FindCtx(canceled, strings.Repeat("a", 43)); err == nil {
		t.Fatal("session lookup hid a canceled database operation")
	}
	if err := f.model.AddUserToSession(t.Context(), strings.Repeat("a", 43), "nonexistent-owner", f.key); err == nil {
		t.Fatal("missing encrypted session reported successful ownership")
	}
}

func TestMixedSessionOwnerAssociation(t *testing.T) {
	f := newLegacySessionFixture(t, true)
	ctx := t.Context()
	if err := f.model.Client.User.Create().SetID("session-user").SetName("Owned user").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	// Preserve insertion order so an unrelated legacy plaintext row is first.
	if err := f.model.Client.Sessions.Create().SetID(strings.Repeat("z", 43)).SetData([]byte("legacy")).SetExpiry(time.Now().Add(time.Hour)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 43)
	encrypted, err := utils.EncryptSensitiveField(token, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.Client.Sessions.Create().SetID(encrypted).SetData([]byte("owned")).SetExpiry(time.Now().Add(time.Hour)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.model.AddUserToSession(t.Context(), token, "session-user", f.key); err != nil {
		t.Fatal("unrelated plaintext session prevented owner association", err)
	}
	var owner string
	if err = f.model.DB.QueryRow(`SELECT user_sessions FROM sessions WHERE token=$1`, encrypted).Scan(&owner); err != nil || owner != "session-user" {
		t.Fatal("wrong session ownership", owner, err)
	}
}
