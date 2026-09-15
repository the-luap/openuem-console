//go:build linux || windows

package common

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func TestInstallationSecretsInstalledService(t *testing.T) {
	jwt, master := strings.Repeat("j", 43), strings.Repeat("m", 32)
	jwtPath, masterPath := filepath.Join(t.TempDir(), "jwt"), filepath.Join(t.TempDir(), "master")
	if keyfile.Create(jwtPath, []byte(jwt)) != nil || keyfile.Create(masterPath, []byte(master)) != nil {
		t.Fatal("fixture failed")
	}
	for _, name := range []string{"JWT_KEY", "JWT_KEY_FILE", "ENCRYPTION_MASTER_KEY", "ENCRYPTION_MASTER_KEY_FILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("OPENUEM_INSTALLATION_ID", strings.Repeat("1", 32))
	t.Setenv("JWT_KEY_FILE", jwtPath)
	t.Setenv("ENCRYPTION_MASTER_KEY_FILE", masterPath)
	called := false
	unavailable := errors.New("synthetic unavailable legacy credential store")
	legacy := func() (string, error) { called = true; return "", unavailable }
	credentials, err := installedSecrets(true, legacy)
	if err != nil || called || credentials.JWT != jwt || credentials.Master != master || credentials.Installation != strings.Repeat("1", 32) {
		t.Fatal("installed service did not use mounted credentials", err)
	}
	t.Setenv("JWT_KEY", "ambiguous")
	if _, err := installedSecrets(true, legacy); !errors.Is(err, secrets.ErrConfiguration) || called {
		t.Fatal("ambiguous installed credentials accepted", err)
	}
	t.Setenv("JWT_KEY", "")
	t.Setenv("JWT_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := installedSecrets(true, legacy); !errors.Is(err, secrets.ErrConfiguration) || called {
		t.Fatal("missing file fell back to legacy credentials", err)
	}
	t.Setenv("JWT_KEY_FILE", "")
	if _, err := installedSecrets(false, legacy); !errors.Is(err, unavailable) || !called {
		t.Fatal("legacy credential failure ignored", err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY_FILE", "")
	t.Setenv("OPENUEM_INSTALLATION_ID", "")
	credentials, err = installedSecrets(false, func() (string, error) { return "legacy-jwt", nil })
	if err != nil || credentials.JWT != "legacy-jwt" || credentials.Master != "" {
		t.Fatal("legacy configuration changed", err)
	}
}

func TestInstallationSecretsInstalledDatabase(t *testing.T) {
	value := "postgres://console:synthetic-password@db.internal/openuem?sslmode=verify-full"
	path := filepath.Join(t.TempDir(), "database.url")
	if err := keyfile.Create(path, []byte(value)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATABASE_URL_FILE", path)
	called := false
	unavailable := errors.New("synthetic unavailable legacy database credentials")
	legacy := func() (string, error) { called = true; return "", unavailable }
	actual, err := installedDatabaseURL(legacy)
	if err != nil || actual != value || called {
		t.Fatal("mounted database credentials required the legacy store", err)
	}
	t.Setenv("DATABASE_URL", value)
	if _, err := installedDatabaseURL(legacy); !errors.Is(err, secrets.ErrConfiguration) || called {
		t.Fatal("ambiguous installed database credentials accepted", err)
	}
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATABASE_URL_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := installedDatabaseURL(legacy); !errors.Is(err, secrets.ErrConfiguration) || called {
		t.Fatal("missing database file fell back to legacy storage", err)
	}
	t.Setenv("DATABASE_URL_FILE", "")
	if _, err := installedDatabaseURL(legacy); !errors.Is(err, unavailable) || !called {
		t.Fatal("legacy database failure ignored", err)
	}
	if actual, err := installedDatabaseURL(func() (string, error) { return value, nil }); err != nil || actual != value {
		t.Fatal("legacy database configuration changed", err)
	}
}
