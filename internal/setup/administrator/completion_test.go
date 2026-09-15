package administrator

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func TestProtectedAdministratorCompletion(t *testing.T) {
	m := accountModel(t)
	ctx := t.Context()
	credentials := installationCredentials()
	config := Config{UserID: "first-admin", PasswordFile: passwordFile(t, testPassword)}
	if secrets.CheckBinding(ctx, m.DB, credentials) != nil {
		t.Fatal("cannot bind the synthetic installation")
	}
	if created, err := Initialize(ctx, m.DB, config); err != nil || !created {
		t.Fatal("cannot initialize the synthetic administrator")
	}
	if err := CheckCompletion(ctx, m.DB, config, credentials); !errors.Is(err, ErrIncomplete) {
		t.Fatal("unreplaced initial password completed setup")
	}
	if _, err := m.DB.ExecContext(ctx, `UPDATE users SET register=$1 WHERE uid=$2`, openuem.REGISTER_COMPLETE, config.UserID); err != nil {
		t.Fatal(err)
	}
	if err := CheckCompletion(ctx, m.DB, config, credentials); !errors.Is(err, ErrIncomplete) {
		t.Fatal("a status-only change bypassed initial-password replacement")
	}
	hash, err := argon2id.CreateHash("Replacement-Password_123456789!", argon2id.DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.DB.ExecContext(ctx, `UPDATE users SET hash=$1 WHERE uid=$2`, hash, config.UserID); err != nil {
		t.Fatal(err)
	}
	// Database write triggers reject any attempted changes during inspection.
	// Completion must read existing state without initializing or repairing it.
	if _, err := m.DB.ExecContext(ctx, `CREATE FUNCTION forbid_setup_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'completion cannot mutate setup state'; END $$`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"users", "uem_access_grants", "uem_access_bootstrap_account", "uem_access_migrations", "uem_installation_secrets"} {
		if _, err := m.DB.ExecContext(ctx, `CREATE TRIGGER forbid_setup_write BEFORE INSERT OR UPDATE OR DELETE ON `+table+` FOR EACH STATEMENT EXECUTE FUNCTION forbid_setup_write()`); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckCompletion(ctx, m.DB, config, credentials); err != nil {
		t.Fatal("completed account did not pass read-only verification", err)
	}
	for _, table := range []string{"users", "uem_access_grants", "uem_access_bootstrap_account", "uem_access_migrations", "uem_installation_secrets"} {
		if _, err := m.DB.ExecContext(ctx, `DROP TRIGGER forbid_setup_write ON `+table); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []struct{ name, alter, restore string }{
		{"registration", `UPDATE users SET register='users.force_change_password'`, `UPDATE users SET register='users.completed'`},
		{"password disabled", `UPDATE users SET passwd=false`, `UPDATE users SET passwd=true`},
		{"openid", `UPDATE users SET openid=true`, `UPDATE users SET openid=false`},
		{"bootstrap marker", `DELETE FROM uem_access_migrations WHERE name='bootstrap'`, `INSERT INTO uem_access_migrations(name) VALUES('bootstrap')`},
		{"secret marker", `DELETE FROM uem_access_migrations WHERE name='installation-secrets'`, `INSERT INTO uem_access_migrations(name) VALUES('installation-secrets')`},
		{"bootstrap account", `DELETE FROM uem_access_bootstrap_account`, `INSERT INTO uem_access_bootstrap_account(singleton,user_id) VALUES(true,'first-admin')`},
		{"administrator grant", `DELETE FROM uem_access_grants`, `INSERT INTO uem_access_grants(user_id,role) VALUES('first-admin','administrator')`},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := m.DB.ExecContext(ctx, change.alter); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := m.DB.ExecContext(ctx, change.restore); err != nil {
					t.Fatal(err)
				}
			}()
			if err := CheckCompletion(ctx, m.DB, config, credentials); !errors.Is(err, ErrIncomplete) {
				t.Fatal("incomplete account or binding was accepted")
			}
		})
	}
	for _, kind := range []string{"installation", "JWT", "master"} {
		changed := credentials
		switch kind {
		case "installation":
			changed.Installation = strings.Repeat("2", 32)
		case "JWT":
			changed.JWT = strings.Repeat("k", 43)
		case "master":
			changed.Master = strings.Repeat("n", 32)
		}
		if err := CheckCompletion(ctx, m.DB, config, changed); !errors.Is(err, ErrIncomplete) {
			t.Fatal("different installation credentials passed completion")
		}
	}
	other := config
	other.UserID = "different-administrator"
	if CheckCompletion(ctx, m.DB, other, credentials) == nil {
		t.Fatal("a different bootstrap account passed completion")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if CheckCompletion(canceled, m.DB, config, credentials) == nil {
		t.Fatal("canceled completion passed")
	}
	if _, err := m.DB.ExecContext(ctx, `DROP TABLE uem_installation_secrets`); err != nil {
		t.Fatal(err)
	}
	if CheckCompletion(ctx, m.DB, config, credentials) == nil {
		t.Fatal("missing binding schema passed completion")
	}
	var recreated sql.NullString
	if err := m.DB.QueryRowContext(ctx, `SELECT to_regclass('uem_installation_secrets')::text`).Scan(&recreated); err != nil || recreated.Valid {
		t.Fatal("completion repaired missing installation schema")
	}
}

func TestProtectedAdministratorCompletionHashBounds(t *testing.T) {
	hash, err := argon2id.CreateHash("Synthetic-Password_123456789!", argon2id.DefaultParams)
	if err != nil || !boundedPasswordHash(hash) {
		t.Fatal("default password hash rejected")
	}
	for _, invalid := range []string{"", "invalid", strings.Repeat("x", 1025), strings.Replace(hash, "m=65536", "m=4294967295", 1), strings.Replace(hash, "t=1", "t=0", 1), strings.Replace(hash, "t=1", "t=999", 1)} {
		if boundedPasswordHash(invalid) {
			t.Fatal("unbounded or invalid password hash accepted")
		}
	}
}
