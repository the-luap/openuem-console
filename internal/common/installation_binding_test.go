//go:build linux || windows

package common_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/common"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/setup/administrator"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func TestInstallationSecretsWorkerRejectsConfigurationDowngrade(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for installation startup binding")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "worker_installation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	t.Setenv("ENV", "test")
	model, err := models.New(u.String(), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { model.Close() })
	password := filepath.Join(t.TempDir(), "password")
	if err := keyfile.Create(password, []byte("Synthetic-Initial-Password-0123456789!")); err != nil {
		t.Fatal(err)
	}
	w := &common.Worker{Model: model, InstallationID: strings.Repeat("1", 32), JWTKey: strings.Repeat("j", 43), EncryptionMasterKey: strings.Repeat("m", 32), ProtectedAdministrator: &administrator.Config{UserID: "first-admin", PasswordFile: password}}
	if err := w.InitializeAdministrator(); err != nil {
		t.Fatal("first worker startup failed", err)
	}
	ctx := context.Background()
	original, err := model.Client.User.Get(ctx, "first-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(password); err != nil {
		t.Fatal(err)
	}
	if err := w.InitializeAdministrator(); err != nil {
		t.Fatal("worker restart without bootstrap mount failed", err)
	}
	w.EncryptionMasterKey = strings.Repeat("n", 32)
	if err := w.InitializeAdministrator(); !errors.Is(err, secrets.ErrBinding) {
		t.Fatal("worker accepted changed encryption material", err)
	}
	w.EncryptionMasterKey = strings.Repeat("m", 32)
	w.InstallationID = ""
	w.ProtectedAdministrator = nil
	w.ResetOpenUEMUser = true
	if err := w.InitializeAdministrator(); !errors.Is(err, secrets.ErrBinding) {
		t.Fatal("legacy mode/reset bypassed a permanent binding", err)
	}
	current, err := model.Client.User.Get(ctx, "first-admin")
	if err != nil || current.Hash != original.Hash || current.Register != original.Register {
		t.Fatal("rejected startup changed credentials", err)
	}
}
