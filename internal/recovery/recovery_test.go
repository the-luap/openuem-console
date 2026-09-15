package recovery

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/testsupport/recoverydb"
)

func privateDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := keyfile.CreateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func recoveryDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	return recoverydb.New(t)
}

func recoveryFixture(t *testing.T, dsn string) (CreateConfig, OpenConfig) {
	t.Helper()
	dir := privateDirectory(t)
	dataIdentity, keyIdentity := filepath.Join(dir, "data.key"), filepath.Join(dir, "recovery.key")
	dataRecipient, err := GenerateIdentity(dataIdentity)
	if err != nil {
		t.Fatal(err)
	}
	keyRecipient, err := GenerateIdentity(keyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", "synthetic-restorable-master-key-32-bytes")
	t.Setenv("WINDOWS_MDM_MASTER_KEY", "synthetic-windows-master-key")
	t.Setenv("JWT_KEY", "synthetic-jwt-key")
	certFile := filepath.Join(dir, "source.pem")
	if err := keyfile.Create(certFile, []byte("synthetic private certificate\n")); err != nil {
		t.Fatal(err)
	}
	c := CreateConfig{DatabaseURL: dsn, DatabaseOutput: filepath.Join(dir, "database.age"), RecoveryOutput: filepath.Join(dir, "recovery.age"), DatabaseRecipient: dataRecipient, RecoveryRecipient: keyRecipient, Specification: Specification{Environment: []string{"ENCRYPTION_MASTER_KEY", "WINDOWS_MDM_MASTER_KEY", "JWT_KEY"}, Files: []FileSource{{Name: "console.pem", Path: certFile}}}, PGDump: os.Getenv("OPENUEM_RECOVERY_TEST_PG_DUMP")}
	o := OpenConfig{DatabaseInput: c.DatabaseOutput, RecoveryInput: c.RecoveryOutput, DatabaseIdentity: dataIdentity, RecoveryIdentity: keyIdentity, WorkDirectory: dir}
	return c, o
}

func TestRecoveryEncryptedDatabaseRoundTrip(t *testing.T) {
	db, source := recoveryDatabase(t)
	if _, err := db.Exec(`CREATE TABLE device_evidence(id BIGSERIAL PRIMARY KEY,secret TEXT NOT NULL); INSERT INTO device_evidence(secret) VALUES('synthetic retained identity'),('Unicode ✓'); CREATE FUNCTION immutable_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable evidence'; END $$; CREATE TRIGGER evidence_guard BEFORE UPDATE OR DELETE ON device_evidence FOR EACH ROW EXECUTE FUNCTION immutable_evidence()`); err != nil {
		t.Fatal(err)
	}
	var largeObject uint32
	if err := db.QueryRow(`SELECT lo_from_bytea(0,decode('000102feff','hex'))`).Scan(&largeObject); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE SCHEMA native; CREATE TABLE native.external_schema_identity(id INTEGER); INSERT INTO native.external_schema_identity VALUES(7)`); err != nil {
		t.Fatal(err)
	}
	c, o := recoveryFixture(t, source)
	empty := filepath.Join(o.WorkDirectory, "source-empty.conf")
	f, err := keyfile.CreateFile(empty)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	c.Specification.Files = append(c.Specification.Files, FileSource{Name: "empty.conf", Path: empty})
	report, err := Create(t.Context(), c)
	if err != nil {
		t.Fatal("create", err)
	}
	for _, path := range []string{c.DatabaseOutput, c.RecoveryOutput} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if path == c.RecoveryOutput {
			digest := sha256.Sum256(data)
			if report.RecoverySHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("public report must bind ciphertext without a hash of recovery secrets")
			}
		}
		if bytes.Contains(data, []byte("synthetic")) || bytes.Contains(data, []byte("ENCRYPTION_MASTER_KEY")) {
			t.Fatal("backup contains plaintext recovery data")
		}
	}
	verified, err := Verify(t.Context(), o)
	if err != nil || verified.ID != report.ID {
		t.Fatal("verify", err)
	}
	target, targetURL := recoveryDatabase(t)
	var name string
	if err := target.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	// The restore preflight requires this test connection to be closed as well.
	target.Close()
	restore := RestoreConfig{OpenConfig: o, DatabaseURL: targetURL, ConfirmDatabase: name, ConfirmBackupID: report.ID, RecoveryDirectory: filepath.Join(o.WorkDirectory, "restored"), PGRestore: os.Getenv("OPENUEM_RECOVERY_TEST_PG_RESTORE")}
	if _, err := Restore(t.Context(), restore); err != nil {
		t.Fatal("restore", err)
	}
	reopened, err := sql.Open("pgx", targetURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var blob string
	if err := reopened.QueryRow(`SELECT encode(lo_get($1),'hex')`, largeObject).Scan(&blob); err != nil || blob != "000102feff" {
		t.Fatal("restore lost large object", err)
	}
	var otherID int
	if err := reopened.QueryRow(`SELECT id FROM native.external_schema_identity`).Scan(&otherID); err != nil || otherID != 7 {
		t.Fatal("restore omitted another schema", err)
	}
	var count int
	if err := reopened.QueryRow(`SELECT count(*) FROM device_evidence`).Scan(&count); err != nil || count != 2 {
		t.Fatal("restore lost device evidence", err)
	}
	if _, err := reopened.Exec(`DELETE FROM device_evidence`); err == nil {
		t.Fatal("restore lost immutable trigger")
	}
	if _, err := reopened.Exec(`INSERT INTO device_evidence(secret) VALUES('continued management')`); err != nil {
		t.Fatal("restored sequence failed", err)
	}
	data, err := readPrivate(filepath.Join(restore.RecoveryDirectory, "environment.json"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	var environment map[string]string
	if json.Unmarshal(data, &environment) != nil || environment["ENCRYPTION_MASTER_KEY"] != os.Getenv("ENCRYPTION_MASTER_KEY") {
		t.Fatal("restore changed application master key")
	}
	emptyData, err := readPrivate(filepath.Join(restore.RecoveryDirectory, "empty.conf"), maxFileBytes)
	if err != nil || len(emptyData) != 0 {
		t.Fatal("empty recovery file was not preserved", err)
	}
	if _, err := os.Stat(filepath.Join(restore.RecoveryDirectory, "completed.json")); err != nil {
		t.Fatal("successful restore omitted receipt")
	}
	if _, err := Restore(t.Context(), restore); !errors.Is(err, ErrFile) {
		t.Fatal("restore overwrote prepared recovery files", err)
	}
	restore.RecoveryDirectory = filepath.Join(o.WorkDirectory, "second-restore")
	if _, err := Restore(t.Context(), restore); !errors.Is(err, ErrTarget) {
		t.Fatal("restore accepted occupied destination", err)
	}
	entries, err := os.ReadDir(o.WorkDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".dump") || strings.HasSuffix(entry.Name(), ".partial") || strings.HasPrefix(entry.Name(), ".pgpass-") {
			t.Fatal("temporary plaintext or password file survived")
		}
	}
}
