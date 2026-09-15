package preferences

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for account language persistence integration tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "preferences_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if _, err = db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY);CREATE TABLE tenants(id BIGINT PRIMARY KEY);CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT REFERENCES tenants(id));INSERT INTO users VALUES('admin'),('other'),('viewer'),('operator'),('new_user');INSERT INTO tenants VALUES(1),(2);INSERT INTO sites VALUES(11,1),(12,1),(21,2)`); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal("non-idempotent migration", err)
	}
	return s
}

func TestAccountLanguagePersistenceIsolationAndDeletion(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	if got, err := s.Language(ctx, "viewer"); got != "" || err != nil {
		t.Fatal("new account must follow browser", got, err)
	}
	for _, code := range []string{"en", "de", "es", "ca", "fr", "no", "pt", ""} {
		if err := s.SetLanguage(ctx, "viewer", code); err != nil {
			t.Fatal(err)
		}
		reopened, err := NewStore(s.db)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := reopened.Language(ctx, "viewer"); got != code || err != nil {
			t.Fatal("language did not persist", got, err)
		}
		if got, err := reopened.Language(ctx, "operator"); got != "" || err != nil {
			t.Fatal("preference crossed account", got, err)
		}
	}
	if err := s.SetLanguage(ctx, "viewer", "de"); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"DE", "de-DE", "en, de;q=0.8", " en ", "xx", "../en", string([]byte{0xff}), "en\n", "<img src=x>", strings.Repeat("x", 8193)} {
		if err := s.SetLanguage(ctx, "viewer", code); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid preference accepted", err)
		}
	}
	if got, err := s.Language(ctx, "viewer"); got != "de" || err != nil {
		t.Fatal("invalid save changed language", got, err)
	}
	if err := s.SetLanguage(ctx, "missing", "en"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing account received preference", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.SetLanguage(cancelled, "viewer", "en"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled write continued", err)
	}
	if _, err := s.Language(cancelled, "viewer"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", err)
	}
	if _, err := s.db.Exec(`DELETE FROM users WHERE uid='viewer'`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_user_preferences WHERE user_id='viewer'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("deleted account preference retained", count, err)
	}
	if _, err := s.Language(ctx, "viewer"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted account readable", err)
	}
}

func TestAccountLanguageConcurrentMigrationAndFailure(t *testing.T) {
	s := testStore(t)
	if _, err := s.db.Exec(`DROP TABLE uem_user_preferences; DROP TABLE uem_preference_migrations`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := s.Migrate(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := s.SetLanguage(t.Context(), "viewer", "de"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE uem_user_preferences ADD CONSTRAINT reject_language_change CHECK(locale<>'en') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLanguage(t.Context(), "viewer", "en"); err == nil {
		t.Fatal("failed write reported success")
	}
	if got, err := s.Language(t.Context(), "viewer"); got != "de" || err != nil {
		t.Fatal("failed save changed preference", got, err)
	}
}
