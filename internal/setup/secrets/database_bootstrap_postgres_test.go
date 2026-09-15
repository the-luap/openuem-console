//go:build linux

package secrets_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

var interruptedDatabaseBootstrap = errors.New("synthetic durable interruption")

func bootstrapState(f databaseFixture) string { return filepath.Join(f.root, "bootstrap") }

func bootstrapFixture(t *testing.T, f databaseFixture) {
	t.Helper()
	result, err := secrets.BootstrapDatabase(f.ctx, f.directory, bootstrapState(f), f.config)
	if err != nil || result.Installation != f.config.Installation {
		t.Fatal("bound database bootstrap failed", err)
	}
}

func bootstrapSQL(t *testing.T, f databaseFixture, statements ...string) {
	t.Helper()
	for _, statement := range statements {
		if _, err := f.admin.ExecContext(f.ctx, statement); err != nil {
			t.Fatal("synthetic catalog mutation failed")
		}
	}
}

func bootstrapFiles(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal("cannot inspect protected fixture inventory")
	}
	result := map[string][32]byte{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal("cannot inspect protected fixture file")
		}
		result[entry.Name()] = sha256.Sum256(data)
		clear(data)
	}
	return result
}

// Snapshots stay in memory; failure messages must never print authentication
// state, even hashed synthetic verifiers or stored database connection URLs.
func bootstrapCatalog(t *testing.T, f databaseFixture) string {
	t.Helper()
	var result, rows string
	if err := f.admin.QueryRowContext(f.ctx, `SELECT jsonb_build_object(
	 'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY oid) FROM pg_authid r),
	 'databases',(SELECT jsonb_agg(to_jsonb(d) ORDER BY oid) FROM pg_database d),
	 'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY oid) FROM pg_auth_members m),
	 'schema',(SELECT to_jsonb(n) FROM pg_namespace n WHERE nspname='openuem_bootstrap'),
	 'table',(SELECT to_jsonb(c) FROM pg_class c WHERE oid=to_regclass('openuem_bootstrap.installations')))::text`).Scan(&result); err != nil {
		t.Fatal("cannot inspect synthetic catalog")
	}
	var exists bool
	if err := f.admin.QueryRowContext(f.ctx, `SELECT to_regclass('openuem_bootstrap.installations') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal("cannot inspect control table")
	}
	if exists {
		if err := f.admin.QueryRowContext(f.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(i) ORDER BY installation),'[]'::jsonb)::text FROM openuem_bootstrap.installations i`).Scan(&rows); err != nil {
			t.Fatal("cannot inspect synthetic binding")
		}
	}
	return result + rows
}

func TestInstallationSecretsDatabasePostgresInterruptions(t *testing.T) {
	for _, point := range []string{"binding.json", "role-committed", "role.json", "database-created", "database-bound", "database.json", "ready-precommit", "ready-committed", "ready.json"} {
		t.Run(point, func(t *testing.T) {
			f := startDatabaseFixture(t)
			_, err := secrets.BootstrapDatabaseWithStepForTest(f.ctx, f.directory, bootstrapState(f), f.config, func(step string) error {
				if step == point {
					return interruptedDatabaseBootstrap
				}
				return nil
			})
			if !errors.Is(err, interruptedDatabaseBootstrap) {
				t.Fatal("durable interruption was not reached", err)
			}
			files := bootstrapFiles(t, bootstrapState(f))
			var roleOID, databaseOID int64
			var login bool
			err = f.admin.QueryRowContext(f.ctx, `SELECT oid::bigint,rolcanlogin FROM pg_roles WHERE rolname='console'`).Scan(&roleOID, &login)
			if point == "binding.json" {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("role was created before its durable binding")
				}
			} else if err != nil || login != (point == "ready-committed" || point == "ready.json") {
				t.Fatal("pending role became usable or committed role disappeared")
			}
			var allowed bool
			err = f.admin.QueryRowContext(f.ctx, `SELECT oid::bigint,datallowconn FROM pg_database WHERE datname='openuem' OR starts_with(datname,'openuem_stage_')`).Scan(&databaseOID, &allowed)
			if err != nil && !errors.Is(err, sql.ErrNoRows) || err == nil && allowed != login {
				t.Fatal("pending database became connectable")
			}
			if point == "ready-precommit" {
				var pending bool
				if err := f.admin.QueryRowContext(f.ctx, `SELECT NOT ready AND EXISTS(SELECT 1 FROM pg_database WHERE datname=stage_name AND NOT datallowconn) AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=database_name) FROM openuem_bootstrap.installations`).Scan(&pending); err != nil || !pending {
					t.Fatal("finalization did not roll back name, connections and binding together")
				}
			}
			bootstrapFixture(t, f)
			for name, digest := range files {
				if bootstrapFiles(t, bootstrapState(f))[name] != digest {
					t.Fatal("resume replaced a durable journal file")
				}
			}
			var original bool
			if err := f.admin.QueryRowContext(f.ctx, `SELECT ($1::bigint=0 OR role_oid=$1) AND ($2::bigint=0 OR database_oid=$2) AND ready FROM openuem_bootstrap.installations`, roleOID, databaseOID).Scan(&original); err != nil || !original {
				t.Fatal("resume replaced a bound role or database")
			}
			app, err := sql.Open("pgx", f.connection)
			if err != nil {
				t.Fatal("cannot open application fixture")
			}
			defer app.Close()
			if _, err := app.ExecContext(f.ctx, `CREATE TABLE retained_data(value text); INSERT INTO retained_data VALUES('durable fixture')`); err != nil {
				t.Fatal("resumed application role cannot use its database")
			}
			bootstrapFixture(t, f)
			var retained bool
			if err := app.QueryRowContext(f.ctx, `SELECT value='durable fixture' FROM retained_data`).Scan(&retained); err != nil || !retained {
				t.Fatal("restart lost application data")
			}
		})
	}
}

func TestInstallationSecretsDatabasePostgresDrift(t *testing.T) {
	cases := []struct {
		name   string
		sql    []string
		file   string
		remove bool
	}{
		{name: "role-password", sql: []string{`ALTER ROLE console PASSWORD 'different-synthetic-password'`}},
		{name: "role-createdb", sql: []string{`ALTER ROLE console CREATEDB`}},
		{name: "role-createrole", sql: []string{`ALTER ROLE console CREATEROLE`}},
		{name: "role-replication", sql: []string{`ALTER ROLE console REPLICATION`}},
		{name: "role-bypassrls", sql: []string{`ALTER ROLE console BYPASSRLS`}},
		{name: "role-inherit", sql: []string{`ALTER ROLE console NOINHERIT`}},
		{name: "role-superuser", sql: []string{`ALTER ROLE console SUPERUSER`}},
		{name: "role-login", sql: []string{`ALTER ROLE console NOLOGIN`}},
		{name: "role-setting", sql: []string{`ALTER ROLE console SET search_path=public`}},
		{name: "role-limit", sql: []string{`ALTER ROLE console CONNECTION LIMIT 1`}},
		{name: "role-expiry", sql: []string{`ALTER ROLE console VALID UNTIL 'infinity'`}},
		{name: "role-membership", sql: []string{`CREATE ROLE unexpected_group`, `GRANT unexpected_group TO console`}},
		{name: "role-grantee", sql: []string{`CREATE ROLE unexpected_member`, `GRANT console TO unexpected_member`}},
		{name: "database-owner", sql: []string{`ALTER DATABASE openuem OWNER TO postgres`}},
		{name: "database-public", sql: []string{`GRANT CONNECT ON DATABASE openuem TO PUBLIC`}},
		{name: "database-owner-acl", sql: []string{`REVOKE CONNECT ON DATABASE openuem FROM console`}},
		{name: "catalog-table-access", sql: []string{`GRANT SELECT ON openuem_bootstrap.installations TO PUBLIC`}},
		{name: "database-template", sql: []string{`ALTER DATABASE openuem IS_TEMPLATE true`}},
		{name: "database-connections", sql: []string{`ALTER DATABASE openuem ALLOW_CONNECTIONS false`}},
		{name: "database-limit", sql: []string{`ALTER DATABASE openuem CONNECTION LIMIT 1`}},
		{name: "database-rename", sql: []string{`ALTER DATABASE openuem RENAME TO changed_database`}},
		{name: "database-missing", sql: []string{`DROP DATABASE openuem`}},
		{name: "database-replaced", sql: []string{`DROP DATABASE openuem`, `CREATE DATABASE openuem OWNER console`}},
		{name: "role-missing", sql: []string{`DROP DATABASE openuem`, `DROP ROLE console`}},
		{name: "role-replaced", sql: []string{`DROP DATABASE openuem`, `DROP ROLE console`, `CREATE ROLE console LOGIN`}},
		{name: "binding-row", sql: []string{`DELETE FROM openuem_bootstrap.installations`}},
		{name: "binding-operation", sql: []string{`UPDATE openuem_bootstrap.installations SET operation=repeat('0',32)`}},
		{name: "binding-oid", sql: []string{`UPDATE openuem_bootstrap.installations SET database_oid=database_oid+1`}},
		{name: "binding-ready", sql: []string{`UPDATE openuem_bootstrap.installations SET ready=false`}},
		{name: "catalog-table", sql: []string{`DROP TABLE openuem_bootstrap.installations`}},
		{name: "catalog-schema", sql: []string{`DROP SCHEMA openuem_bootstrap CASCADE`}},
		{name: "catalog-access", sql: []string{`GRANT USAGE ON SCHEMA openuem_bootstrap TO PUBLIC`}},
		{name: "catalog-comment", sql: []string{`COMMENT ON SCHEMA openuem_bootstrap IS 'changed'`}},
		{name: "binding-file", file: "binding.json", remove: true},
		{name: "binding-corrupt", file: "binding.json"},
		{name: "role-corrupt", file: "role.json"},
		{name: "database-corrupt", file: "database.json"},
		{name: "ready-corrupt", file: "ready.json"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := startDatabaseFixture(t)
			bootstrapFixture(t, f)
			bootstrapSQL(t, f, test.sql...)
			if test.file != "" {
				path := filepath.Join(bootstrapState(f), test.file)
				var err error
				if test.remove {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, []byte("partial"), 0600)
				}
				if err != nil {
					t.Fatal("cannot damage synthetic state")
				}
			}
			catalog, files := bootstrapCatalog(t, f), bootstrapFiles(t, bootstrapState(f))
			if _, err := secrets.BootstrapDatabase(f.ctx, f.directory, bootstrapState(f), f.config); err == nil {
				t.Fatal("changed installation was accepted")
			}
			if catalog != bootstrapCatalog(t, f) || !reflect.DeepEqual(files, bootstrapFiles(t, bootstrapState(f))) {
				t.Fatal("rejected bootstrap changed retained objects or files")
			}
		})
	}
}

func TestInstallationSecretsDatabasePostgresConcurrency(t *testing.T) {
	f := startDatabaseFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	reached, done := make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := secrets.BootstrapDatabaseWithStepForTest(ctx, f.directory, bootstrapState(f), f.config, func(step string) error {
			if step == "database-created" {
				close(reached)
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		})
		done <- err
	}()
	select {
	case <-reached:
	case err := <-done:
		t.Fatal("writer stopped before concurrency gate", err)
	case <-f.ctx.Done():
		t.Fatal("writer did not reach concurrency gate")
	}
	if _, err := secrets.BootstrapDatabase(f.ctx, f.directory, bootstrapState(f), f.config); !errors.Is(err, secrets.ErrDatabaseBootstrapBusy) {
		t.Fatal("competing writer did not stop at the cluster lock", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation did not stop the active writer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled writer retained its database session")
	}
	bootstrapFixture(t, f)
}

func TestInstallationSecretsDatabasePostgresSuppressedWrites(t *testing.T) {
	for _, event := range []string{"INSERT", "UPDATE OF database_oid", "UPDATE OF ready"} {
		t.Run(strings.ReplaceAll(event, " ", "_"), func(t *testing.T) {
			f := startDatabaseFixture(t)
			_, err := secrets.BootstrapDatabaseWithStepForTest(f.ctx, f.directory, bootstrapState(f), f.config, func(step string) error {
				if step == "binding.json" {
					return interruptedDatabaseBootstrap
				}
				return nil
			})
			if !errors.Is(err, interruptedDatabaseBootstrap) {
				t.Fatal("cannot establish control catalog", err)
			}
			bootstrapSQL(t, f, `CREATE FUNCTION openuem_bootstrap.suppress_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`, `CREATE TRIGGER suppress_write BEFORE `+event+` ON openuem_bootstrap.installations FOR EACH ROW EXECUTE FUNCTION openuem_bootstrap.suppress_write()`)
			if _, err := secrets.BootstrapDatabase(f.ctx, f.directory, bootstrapState(f), f.config); !errors.Is(err, secrets.ErrDatabaseBootstrap) {
				t.Fatal("suppressed binding write reported readiness", err)
			}
			var usable bool
			if err := f.admin.QueryRowContext(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='console' AND rolcanlogin) OR EXISTS(SELECT 1 FROM pg_database WHERE datname='openuem')`).Scan(&usable); err != nil || usable {
				t.Fatal("suppressed transaction exposed an unbound application")
			}
			if event == "INSERT" {
				var exists bool
				if err := f.admin.QueryRowContext(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='console')`).Scan(&exists); err != nil || exists {
					t.Fatal("role escaped its failed binding transaction")
				}
			}
			bootstrapSQL(t, f, `DROP TRIGGER suppress_write ON openuem_bootstrap.installations`)
			bootstrapFixture(t, f)
		})
	}
}
