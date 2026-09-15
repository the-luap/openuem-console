// Package recoveryfixture runs actual encrypted backup/restore drills for platform tests.
package recoveryfixture

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/recovery"
	"github.com/open-uem/openuem-console/internal/testsupport/recoverydb"
)

func Cycle(t *testing.T, source string, environment map[string]string) (*sql.DB, map[string]string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := keyfile.CreateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	dataKey, rootKey := filepath.Join(dir, "data.key"), filepath.Join(dir, "recovery.key")
	dataRecipient, err := recovery.GenerateIdentity(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	rootRecipient, err := recovery.GenerateIdentity(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for name, value := range environment {
		t.Setenv(name, value)
		names = append(names, name)
	}
	sort.Strings(names)
	c := recovery.CreateConfig{DatabaseURL: source, DatabaseOutput: filepath.Join(dir, "database.age"), RecoveryOutput: filepath.Join(dir, "recovery.age"), DatabaseRecipient: dataRecipient, RecoveryRecipient: rootRecipient, Specification: recovery.Specification{Environment: names, Files: []recovery.FileSource{}}, PGDump: os.Getenv("OPENUEM_RECOVERY_TEST_PG_DUMP")}
	report, err := recovery.Create(t.Context(), c)
	if err != nil {
		t.Fatal("encrypted backup failed", err)
	}
	o := recovery.OpenConfig{DatabaseInput: c.DatabaseOutput, RecoveryInput: c.RecoveryOutput, DatabaseIdentity: dataKey, RecoveryIdentity: rootKey, WorkDirectory: dir}
	verified, err := recovery.Verify(t.Context(), o)
	if err != nil || verified.ID != report.ID {
		t.Fatal("backup verification failed", err)
	}
	target, targetURL := recoverydb.New(t)
	var name string
	if err := target.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	target.Close()
	r := recovery.RestoreConfig{OpenConfig: o, DatabaseURL: targetURL, ConfirmDatabase: name, ConfirmBackupID: report.ID, RecoveryDirectory: filepath.Join(dir, "restored"), PGRestore: os.Getenv("OPENUEM_RECOVERY_TEST_PG_RESTORE")}
	if _, err := recovery.Restore(t.Context(), r); err != nil {
		t.Fatal("isolated restore failed", err)
	}
	data, err := os.ReadFile(filepath.Join(r.RecoveryDirectory, "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	var restored map[string]string
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", targetURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, restored
}
