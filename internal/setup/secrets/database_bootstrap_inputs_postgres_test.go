//go:build linux

package secrets_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func TestInstallationSecretsDatabasePostgresInputs(t *testing.T) {
	for _, mode := range []string{"missing-password", "missing-source", "missing-manifest", "changed-url", "unrelated-file", "public-file", "symlink", "absent-directory", "occupied-role", "occupied-database", "catalog-default-grant"} {
		t.Run(mode, func(t *testing.T) {
			f := startDatabaseFixture(t)
			path := filepath.Join(f.directory, secrets.DatabasePasswordFile)
			var err error
			switch mode {
			case "missing-password":
				err = os.Remove(path)
			case "missing-source":
				err = os.Remove(filepath.Join(f.directory, "credentials.json"))
			case "missing-manifest":
				err = os.Remove(filepath.Join(f.directory, "manifest.json"))
			case "changed-url":
				err = os.WriteFile(filepath.Join(f.directory, secrets.DatabaseURLFile), []byte("synthetic-secret"), 0600)
			case "unrelated-file":
				err = os.WriteFile(filepath.Join(f.directory, "unexpected"), []byte("fixture"), 0600)
			case "public-file":
				err = os.Chmod(path, 0644)
			case "symlink":
				err = os.Rename(path, filepath.Join(f.root, "moved-password"))
				if err == nil {
					err = os.Symlink(filepath.Join(f.root, "moved-password"), path)
				}
			case "absent-directory":
				f.directory = filepath.Join(f.root, "absent-credentials")
			case "occupied-role":
				bootstrapSQL(t, f, `CREATE ROLE console`)
			case "occupied-database":
				bootstrapSQL(t, f, `CREATE DATABASE openuem`)
			case "catalog-default-grant":
				bootstrapSQL(t, f, `CREATE ROLE unexpected_reader`, `ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT SELECT ON TABLES TO unexpected_reader`)
			}
			if err != nil {
				t.Fatal("cannot modify synthetic credential fixture")
			}
			catalog, files := bootstrapCatalog(t, f), bootstrapFiles(t, f.directory)
			_, err = secrets.BootstrapDatabase(f.ctx, f.directory, bootstrapState(f), f.config)
			if err == nil || bytes.Contains([]byte(err.Error()), []byte("synthetic-secret")) {
				t.Fatal("invalid input was accepted or exposed")
			}
			if catalog != bootstrapCatalog(t, f) || !reflect.DeepEqual(files, bootstrapFiles(t, f.directory)) {
				t.Fatal("invalid bootstrap input changed existing state")
			}
			if mode == "absent-directory" {
				if _, err := os.Lstat(f.directory); !os.IsNotExist(err) {
					t.Fatal("online bootstrap generated missing credentials")
				}
			}
		})
	}
}

func TestInstallationSecretsDatabasePostgresJournalRecovery(t *testing.T) {
	for _, mode := range []string{"phase-files", "state-lost", "cluster-changed", "pending-database-changed", "pending-final-name-occupied"} {
		t.Run(mode, func(t *testing.T) {
			f := startDatabaseFixture(t)
			if mode == "pending-database-changed" || mode == "pending-final-name-occupied" {
				_, err := secrets.BootstrapDatabaseWithStepForTest(f.ctx, f.directory, bootstrapState(f), f.config, func(step string) error {
					if step == "database-created" {
						return interruptedDatabaseBootstrap
					}
					return nil
				})
				if !errors.Is(err, interruptedDatabaseBootstrap) {
					t.Fatal("cannot establish pending database", err)
				}
				if mode == "pending-database-changed" {
					bootstrapSQL(t, f, `DO $$ DECLARE stage text; BEGIN SELECT stage_name INTO stage FROM openuem_bootstrap.installations; EXECUTE format('ALTER DATABASE %I ALLOW_CONNECTIONS true',stage); END $$`)
				} else {
					bootstrapSQL(t, f, `CREATE DATABASE openuem`)
				}
			} else {
				bootstrapFixture(t, f)
			}
			state := bootstrapState(f)
			switch mode {
			case "phase-files":
				for _, name := range []string{"role.json", "database.json", "ready.json"} {
					if os.Remove(filepath.Join(state, name)) != nil {
						t.Fatal("cannot remove phase fixture")
					}
				}
				before := bootstrapCatalog(t, f)
				bootstrapFixture(t, f)
				if before != bootstrapCatalog(t, f) || len(bootstrapFiles(t, state)) != 4 {
					t.Fatal("phase reconstruction changed bound objects")
				}
				return
			case "state-lost":
				state = filepath.Join(f.root, "replacement-state")
			case "cluster-changed":
				path := filepath.Join(state, "binding.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal("cannot read binding fixture")
				}
				defer clear(data)
				var cluster string
				if f.admin.QueryRowContext(f.ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&cluster) != nil {
					t.Fatal("cannot inspect fixture cluster")
				}
				changed := bytes.Replace(data, []byte(`"cluster":"`+cluster+`"`), []byte(`"cluster":"1"`), 1)
				defer clear(changed)
				if bytes.Equal(data, changed) || os.WriteFile(path, changed, 0600) != nil {
					t.Fatal("cannot change fixture cluster binding")
				}
			}
			catalog, files := bootstrapCatalog(t, f), bootstrapFiles(t, state)
			if _, err := secrets.BootstrapDatabase(f.ctx, f.directory, state, f.config); err == nil {
				t.Fatal("unbound recovery was accepted")
			}
			if catalog != bootstrapCatalog(t, f) || !reflect.DeepEqual(files, bootstrapFiles(t, state)) {
				t.Fatal("rejected recovery changed retained state")
			}
		})
	}
}
