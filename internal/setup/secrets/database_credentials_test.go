//go:build linux || darwin

package secrets

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func databaseSnapshot(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, name := range append([]string{"credentials.json", "manifest.json"}, databaseArtifacts...) {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		result[name] = data
	}
	return result
}

func TestInstallationSecretsDatabaseCredentials(t *testing.T) {
	config := databaseConfig()
	directory := filepath.Join(t.TempDir(), "credentials")
	result, err := InitializeDatabaseCredentials(t.Context(), directory, config)
	if err != nil || result.Installation != config.Installation {
		t.Fatal("database generation failed", err)
	}
	original := databaseSnapshot(t, directory)
	if len(original) != 5 {
		t.Fatal("missing database credential files")
	}
	password, administrator := string(original[DatabasePasswordFile]), string(original[DatabaseAdministratorPasswordFile])
	if !validDatabasePassword(password) || !validDatabasePassword(administrator) || password == administrator {
		t.Fatal("database roles share or lack independent random credentials")
	}
	connection, err := DatabaseURL("", filepath.Join(directory, DatabaseURLFile))
	if err != nil {
		t.Fatal("generated database URL is not a valid runtime input", err)
	}
	parsed, err := url.Parse(connection)
	if err != nil {
		t.Fatal("could not parse generated URL")
	}
	actual, _ := parsed.User.Password()
	if actual != password || parsed.User.Username() != config.User || parsed.Host != config.Host+":5432" || parsed.Path != "/openuem" || parsed.Query().Get("sslmode") != "verify-full" || parsed.Query().Get("sslrootcert") != config.TrustFile {
		t.Fatal("connection URL lost intended identity, database or TLS requirements")
	}
	for range 3 {
		again, err := InitializeDatabaseCredentials(t.Context(), directory, config)
		if err != nil || again != result {
			t.Fatal("database credential restart failed", err)
		}
		same(t, original, directory)
	}
	for _, change := range []func(*DatabaseConfig){func(c *DatabaseConfig) { c.Installation = strings.Repeat("2", 32) }, func(c *DatabaseConfig) { c.Host = "other.internal" }, func(c *DatabaseConfig) { c.Port = 5433 }, func(c *DatabaseConfig) { c.Database = "other" }, func(c *DatabaseConfig) { c.User = "other" }, func(c *DatabaseConfig) { c.TrustFile = "/different/root.pem" }} {
		changed := config
		change(&changed)
		if _, err := InitializeDatabaseCredentials(t.Context(), directory, changed); !errors.Is(err, ErrState) {
			t.Fatal("changed deployment silently adopted existing credentials", err)
		}
		same(t, original, directory)
	}
}

func TestInstallationSecretsDatabaseCredentialInterruptions(t *testing.T) {
	for _, stop := range append([]string{"credentials.json"}, append(append([]string{}, databaseArtifacts...), "manifest.json")...) {
		t.Run(stop, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "credentials")
			interrupted := errors.New("synthetic interruption")
			if _, err := initializeDatabaseCredentials(t.Context(), directory, databaseConfig(), func(name string) error {
				if name == stop {
					return interrupted
				}
				return nil
			}); !errors.Is(err, interrupted) {
				t.Fatal("interruption was not exercised", err)
			}
			original := databaseSnapshot(t, directory)
			if _, err := InitializeDatabaseCredentials(t.Context(), directory, databaseConfig()); err != nil {
				t.Fatal("completed writes could not resume", err)
			}
			same(t, original, directory)
		})
	}
}

func TestInstallationSecretsDatabaseCredentialDamage(t *testing.T) {
	for _, kind := range []string{"missing source", "partial source", "changed source", "missing password", "changed password", "missing administrator", "changed URL", "changed manifest", "extra entry", "symlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "credentials")
			if _, err := InitializeDatabaseCredentials(t.Context(), directory, databaseConfig()); err != nil {
				t.Fatal(err)
			}
			write := func(name string, data []byte) {
				if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(name string) {
				if err := os.Remove(filepath.Join(directory, name)); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "missing source":
				remove("credentials.json")
			case "partial source":
				write("credentials.json", []byte(`{"config":`))
			case "changed source":
				write("credentials.json", []byte(`{}`))
			case "missing password":
				remove(DatabasePasswordFile)
			case "changed password":
				write(DatabasePasswordFile, bytes.Repeat([]byte("x"), 43))
			case "missing administrator":
				remove(DatabaseAdministratorPasswordFile)
			case "changed URL":
				write(DatabaseURLFile, []byte("postgres://other/different"))
			case "changed manifest":
				write("manifest.json", []byte(`{}`))
			case "extra entry":
				write("unrelated", []byte("preserve"))
			case "symlink":
				remove(DatabasePasswordFile)
				if err := os.Symlink(filepath.Join(directory, DatabaseAdministratorPasswordFile), filepath.Join(directory, DatabasePasswordFile)); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(filepath.Join(directory, DatabaseURLFile), 0644); err != nil {
					t.Fatal(err)
				}
			}
			original := databaseSnapshot(t, directory)
			if _, err := InitializeDatabaseCredentials(t.Context(), directory, databaseConfig()); !errors.Is(err, ErrState) {
				t.Fatal("damaged database credentials were accepted", err)
			}
			same(t, original, directory)
		})
	}
}

func TestInstallationSecretsDatabaseCredentialConcurrency(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := InitializeDatabaseCredentials(t.Context(), directory, databaseConfig()); err != nil && !errors.Is(err, ErrState) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := InitializeDatabaseCredentials(t.Context(), directory, databaseConfig()); err != nil {
		t.Fatal("concurrent provisioners corrupted state", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	missing := filepath.Join(t.TempDir(), "cancelled")
	if _, err := InitializeDatabaseCredentials(ctx, missing, databaseConfig()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled provisioning proceeded", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled provisioning wrote state")
	}
}
