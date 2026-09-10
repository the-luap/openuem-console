package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/recovery"
	"github.com/open-uem/openuem-console/internal/testsupport/recoverydb"
)

func cliDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := keyfile.CreateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRecoveryCLIRejectsAmbiguousAndPrivateArguments(t *testing.T) {
	dir := cliDirectory(t)
	output := filepath.Join(dir, "must-not-exist.key")
	for _, args := range [][]string{
		{"--action", "keygen", "--action", "restore", "--output", output},
		{"--action", "keygen", "--output", output, "--confirm-database", "unrelated"},
		{"--action", "keygen", "--output", output, "--timeout", "private-diagnostic-sentinel"},
		{"--private-diagnostic-sentinel=secret"},
		{"--timeout", "0s"}, {"--action", "unknown"}, {"unexpected argument"},
	} {
		var out, diagnostics bytes.Buffer
		if err := run(t.Context(), args, &out, &diagnostics); !errors.Is(err, recovery.ErrConfig) {
			t.Fatal("invalid CLI accepted", err)
		}
		if out.Len() != 0 || diagnostics.Len() != 0 {
			t.Fatal("invalid CLI exposed arguments or reported success")
		}
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid CLI wrote a private identity")
	}
	var out, help bytes.Buffer
	if err := run(t.Context(), []string{"--help"}, &out, &help); err != nil || !strings.Contains(help.String(), "confirm-backup-id") || out.Len() != 0 {
		t.Fatal("help failed", err)
	}
}

func TestRecoveryCLIKeyGenerationProtectsIdentity(t *testing.T) {
	dir := cliDirectory(t)
	path := filepath.Join(dir, "identity.key")
	var out, diagnostics bytes.Buffer
	args := []string{"--action", "keygen", "--output", path}
	if err := run(t.Context(), args, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "age1") || strings.Contains(out.String(), "SECRET") || diagnostics.Len() != 0 {
		t.Fatal("keygen did not return only a public recipient")
	}
	f, err := keyfile.Open(path, 64<<10)
	if err != nil {
		t.Fatal("keygen identity is not protected", err)
	}
	f.Close()
	out.Reset()
	if err := run(t.Context(), args, &out, &diagnostics); !errors.Is(err, recovery.ErrFile) || out.Len() != 0 {
		t.Fatal("keygen replaced an existing identity", err)
	}
}

func TestRecoveryCLIDatabaseRestore(t *testing.T) {
	db, source := recoverydb.New(t)
	if _, err := db.Exec(`CREATE TABLE cli_identity(id INTEGER PRIMARY KEY, identity TEXT); INSERT INTO cli_identity VALUES(1,'synthetic original identity')`); err != nil {
		t.Fatal(err)
	}
	dir := cliDirectory(t)
	identity, recoveryIdentity := filepath.Join(dir, "database.key"), filepath.Join(dir, "recovery.key")
	public, err := recovery.GenerateIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	publicRecovery, err := recovery.GenerateIdentity(recoveryIdentity)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYNTHETIC_CLI_KEY", "synthetic separately restored secret")
	spec := filepath.Join(dir, "spec.json")
	if err := keyfile.Create(spec, []byte(`{"environment":["SYNTHETIC_CLI_KEY"],"files":[]}`)); err != nil {
		t.Fatal(err)
	}
	data, keys := filepath.Join(dir, "database.age"), filepath.Join(dir, "recovery.age")
	t.Setenv("OPENUEM_RECOVERY_DATABASE_URL", source)
	invoke := func(args ...string) recovery.Report {
		t.Helper()
		var out, diagnostics bytes.Buffer
		if err := run(t.Context(), args, &out, &diagnostics); err != nil {
			t.Fatal(err)
		}
		if diagnostics.Len() != 0 || strings.Contains(out.String(), "synthetic") || strings.Contains(out.String(), source) {
			t.Fatal("CLI exposed private data")
		}
		var report recovery.Report
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.ID == "" {
			t.Fatal("CLI omitted success metadata", err)
		}
		return report
	}
	created := invoke("--action", "create", "--specification", spec, "--output", data, "--recovery-output", keys, "--recipient", public, "--recovery-recipient", publicRecovery, "--pg-dump", os.Getenv("OPENUEM_RECOVERY_TEST_PG_DUMP"))
	common := []string{"--input", data, "--recovery-input", keys, "--identity", identity, "--recovery-identity", recoveryIdentity, "--work-directory", dir}
	verified := invoke(append([]string{"--action", "verify"}, common...)...)
	if verified.ID != created.ID {
		t.Fatal("CLI verified a different backup")
	}
	target, targetURL := recoverydb.New(t)
	var name string
	if err := target.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	target.Close()
	t.Setenv("OPENUEM_RECOVERY_DATABASE_URL", targetURL)
	extract := filepath.Join(dir, "restored")
	restored := invoke(append([]string{"--action", "restore", "--confirm-database", name, "--confirm-backup-id", verified.ID, "--recovery-directory", extract, "--pg-restore", os.Getenv("OPENUEM_RECOVERY_TEST_PG_RESTORE")}, common...)...)
	if restored.ID != created.ID {
		t.Fatal("CLI restored a different backup")
	}
	reopened, err := sql.Open("pgx", targetURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var value string
	if err := reopened.QueryRow(`SELECT identity FROM cli_identity WHERE id=1`).Scan(&value); err != nil || value != "synthetic original identity" {
		t.Fatal("CLI lost original database identity", err)
	}
	if _, err := os.Stat(filepath.Join(extract, "completed.json")); err != nil {
		t.Fatal("CLI omitted completion receipt", err)
	}
}
