package notifications

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestSMTPOrganizationConfigurationWithPostgres(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for SMTP configuration integration")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "smtp_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	if _, err = db.Exec(`CREATE TABLE settings(smtp_server TEXT,smtp_port INTEGER,smtp_user TEXT,smtp_password TEXT,smtp_auth TEXT,message_from TEXT,smtp_encryption_type TEXT,tenant_settings BIGINT)`); err != nil {
		t.Fatal(err)
	}
	if _, err = readSettings(t.Context(), db, 1); err == nil {
		t.Fatal("missing configuration accepted")
	}
	if _, err = db.Exec(`INSERT INTO settings(smtp_server,tenant_settings) VALUES('global.example.test',NULL),('org.example.test',1),('other.example.test',2)`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant int
		host   string
	}{{1, "org.example.test"}, {2, "other.example.test"}, {3, "global.example.test"}} {
		cfg, err := readSettings(t.Context(), db, tc.tenant)
		if err != nil || cfg.host != tc.host {
			t.Fatal("incorrect SMTP scope", cfg.host, err)
		}
	}
	if _, err = db.Exec(`UPDATE settings SET smtp_server='' WHERE tenant_settings=1`); err != nil {
		t.Fatal(err)
	}
	cfg, err := readSettings(t.Context(), db, 1)
	if err != nil || cfg.host != "" {
		t.Fatal("incomplete organization config fell back to global", err)
	}
	if _, err = db.Exec(`INSERT INTO settings(smtp_server) VALUES('duplicate-global.example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err = readSettings(t.Context(), db, 3); err == nil {
		t.Fatal("ambiguous global configuration selected arbitrarily")
	}
	if _, err = readSettings(t.Context(), db, 2); err != nil {
		t.Fatal("specific organization affected by ambiguous global row", err)
	}
	// Exercise the production Send entry point with a real local SMTP peer and a
	// transaction, just as the durable worker does. No external mail is sent.
	f := smtpPeer(t, "none", "")
	if _, err = db.Exec(`UPDATE settings SET smtp_server=$1,smtp_port=$2,smtp_auth='NOAUTH',message_from='from@example.test',smtp_encryption_type='none' WHERE tenant_settings=1`, f.config.host, f.config.port); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = Send(t.Context(), tx, 1, "", fixtureMessage()); err != nil {
		t.Fatal(err)
	}
	if body := <-f.message; !strings.Contains(body, "Certificate reminder") {
		t.Fatal("message missing")
	}
}
