package recovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestRecoveryRejectsDamageAndMismatchedPairsBeforeDestinationAccess(t *testing.T) {
	db, dsn := recoveryDatabase(t)
	if _, err := db.Exec(`CREATE TABLE evidence(id INTEGER PRIMARY KEY); INSERT INTO evidence VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	c, o := recoveryFixture(t, dsn)
	report, err := Create(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(c.DatabaseOutput)
	if err != nil {
		t.Fatal(err)
	}
	originalKeys, err := os.ReadFile(c.RecoveryOutput)
	if err != nil {
		t.Fatal(err)
	}
	second := c
	second.DatabaseOutput = filepath.Join(o.WorkDirectory, "other-data.age")
	second.RecoveryOutput = filepath.Join(o.WorkDirectory, "other-keys.age")
	if _, err := Create(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"database truncated", "database modified", "database trailing bytes", "keys truncated", "keys modified", "keys trailing bytes", "different pair", "wrong identity"} {
		t.Run(name, func(t *testing.T) {
			data, keys := bytes.Clone(original), bytes.Clone(originalKeys)
			input := o
			switch name {
			case "database truncated":
				data = data[:len(data)-1]
			case "database modified":
				data[len(data)-20] ^= 1
			case "database trailing bytes":
				data = append(data, 1)
			case "keys truncated":
				keys = keys[:len(keys)-1]
			case "keys modified":
				keys[len(keys)-20] ^= 1
			case "keys trailing bytes":
				keys = append(keys, 1)
			case "different pair":
				keys, err = os.ReadFile(second.RecoveryOutput)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong identity":
				input.DatabaseIdentity = o.RecoveryIdentity
			}
			input.DatabaseInput = filepath.Join(o.WorkDirectory, strings.ReplaceAll(name, " ", "-")+"-data.age")
			input.RecoveryInput = filepath.Join(o.WorkDirectory, strings.ReplaceAll(name, " ", "-")+"-keys.age")
			if err := keyfile.Create(input.DatabaseInput, data); err != nil {
				t.Fatal(err)
			}
			if err := keyfile.Create(input.RecoveryInput, keys); err != nil {
				t.Fatal(err)
			}
			if got, err := Verify(t.Context(), input); !errors.Is(err, ErrArchive) || got != nil {
				t.Fatal("damaged backup accepted", err)
			}
			// Even an unusable destination must not be consulted before the
			// complete encrypted input and recovery pair have authenticated.
			if got, err := Restore(t.Context(), RestoreConfig{OpenConfig: input, DatabaseURL: "invalid destination", ConfirmBackupID: report.ID}); !errors.Is(err, ErrArchive) || got != nil {
				t.Fatal("restore consulted target before authentication", err)
			}
		})
	}
	entries, err := os.ReadDir(o.WorkDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".dump") {
			t.Fatal("failed authentication left plaintext staging")
		}
	}
}

func TestRecoveryCancellationRemovesUnpublishedArtifacts(t *testing.T) {
	db, dsn := recoveryDatabase(t)
	if _, err := db.Exec(`CREATE TABLE blocked_evidence(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	c, o := recoveryFixture(t, dsn)
	hold, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := hold.Exec(`LOCK TABLE blocked_evidence IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	if got, err := Create(ctx, c); !errors.Is(err, context.DeadlineExceeded) || got != nil {
		t.Fatal("backup did not cancel its database wait", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("backup failed to join canceled child process")
	}
	for _, path := range []string{c.DatabaseOutput, c.RecoveryOutput} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("canceled backup published an artifact")
		}
	}
	entries, err := os.ReadDir(o.WorkDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".partial") || strings.HasPrefix(e.Name(), ".pgpass-") {
			t.Fatal("canceled backup left staging or credentials")
		}
	}
}

func TestRecoverySpecificationAndPrivateFileBoundaries(t *testing.T) {
	dir := privateDirectory(t)
	t.Setenv("SYNTHETIC_SECRET", "must-not-appear-in-diagnostics")
	for _, name := range []string{"../outside", "/outside", "a/b", "a\\b", "NUL", "com1.txt", "LPT0", "file.", "environment.json", "recovery.json", "completed.json", "name:stream"} {
		if validFileName(name) {
			t.Fatal("unsafe portable recovery file name accepted", name)
		}
	}
	for _, data := range []string{`{"environment":[],"environment":["SYNTHETIC_SECRET"]}`, `{"files":[],"unknown":true}`, `{"files":[]} {}`, `{"files":[{"name":"a","name":"b","path":"test"}]}`} {
		var spec Specification
		if decodeJSON([]byte(data), &spec) == nil {
			t.Fatal("ambiguous specification accepted")
		}
	}
	path := filepath.Join(dir, "key.txt")
	public, err := GenerateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := readPrivate(path, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	if _, err := GenerateIdentity(path); !errors.Is(err, ErrFile) {
		t.Fatal("key generation overwrote identity")
	}
	after, err := readPrivate(path, 64<<10)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing identity changed")
	}
	clear(after)
	if strings.Contains(public, "SECRET") {
		t.Fatal("key generation returned private identity")
	}
	for _, value := range []any{CreateConfig{DatabaseURL: os.Getenv("SYNTHETIC_SECRET")}, RestoreConfig{DatabaseURL: os.Getenv("SYNTHETIC_SECRET")}} {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded)+fmt.Sprintf("%v %+v %#v", value, value, value), os.Getenv("SYNTHETIC_SECRET")) {
			t.Fatal("configuration diagnostics exposed credentials")
		}
	}
	for _, spec := range []Specification{{Environment: []string{"SYNTHETIC_SECRET", "SYNTHETIC_SECRET"}}, {Environment: []string{"missing lower case"}}, {Files: []FileSource{{Name: "CON", Path: path}}}} {
		if b, err := collect(spec, "test"); err == nil || b != nil {
			t.Fatal("invalid recovery specification accepted")
		}
	}
}

func TestRecoveryEnvelopeGrammarIsNotJustEncryption(t *testing.T) {
	// A public recipient can encrypt data. The envelope still requires strict
	// metadata and a matched recovery bundle; encryption is not sender identity.
	db, dsn := recoveryDatabase(t)
	if _, err := db.Exec(`CREATE TABLE evidence(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	c, o := recoveryFixture(t, dsn)
	if _, err := Create(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(o.DatabaseInput)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ids, err := identities(o.DatabaseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(f, ids...)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	for _, name := range []string{"version", "extra field", "duplicate field", "unknown magic", "unterminated magic", "wrong payload"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(plain)
			defer clear(data)
			switch name {
			case "version":
				data = bytes.Replace(data, []byte(`"version":1`), []byte(`"version":2`), 1)
			case "extra field":
				data = bytes.Replace(data, []byte(`{"version":1`), []byte(`{"unexpected":true,"version":1`), 1)
			case "duplicate field":
				data = bytes.Replace(data, []byte(`{"version":1`), []byte(`{"version":1,"version":1`), 1)
			case "unterminated magic":
				data = bytes.Repeat([]byte("X"), maxHeaderBytes*4)
			case "unknown magic":
				data[0] = 'X'
			case "wrong payload":
				data = bytes.Replace(data, []byte("PGDMP"), []byte("PLAIN"), 1)
			}
			path := filepath.Join(o.WorkDirectory, strings.ReplaceAll(name, " ", "-")+".age")
			f, err := keyfile.CreateFile(path)
			if err != nil {
				t.Fatal(err)
			}
			key, err := recipient(c.DatabaseRecipient)
			if err != nil {
				t.Fatal(err)
			}
			w, err := age.Encrypt(f, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			f.Close()
			input := o
			input.DatabaseInput = path
			if got, err := Verify(t.Context(), input); !errors.Is(err, ErrArchive) || got != nil {
				t.Fatal("malformed encrypted backup accepted", err)
			}
		})
	}
}

func TestRecoveryAtomicPublicationPreservesExistingFiles(t *testing.T) {
	dir := privateDirectory(t)
	path := filepath.Join(dir, "final.age")
	s, err := stage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := s.file.Write([]byte("synthetic encrypted artifact")); err != nil {
		t.Fatal(err)
	}
	if err := s.publish(); err != nil {
		t.Fatal("atomic publication failed", err)
	}
	if _, err := stage(path); !errors.Is(err, ErrFile) {
		t.Fatal("existing artifact could be replaced")
	}
	s.unpublish()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed pair publication could not be rolled back")
	}
	if err := keyfile.Create(path, []byte("preserve other writer")); err != nil {
		t.Fatal(err)
	}
	s.unpublish()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserve other writer" {
		t.Fatal("cleanup removed another file")
	}
}

func TestRecoveryFailedRestoreRollsBackDatabaseAndPreservesKeys(t *testing.T) {
	db, dsn := recoveryDatabase(t)
	var sourceName string
	if err := db.QueryRow(`SELECT current_database()`).Scan(&sourceName); err != nil {
		t.Fatal(err)
	}
	// This fixture's CHECK intentionally cannot hold in another database. The
	// real pg_restore must fail during COPY and roll back its schema/data changes.
	if _, err := db.Exec(`CREATE TABLE source_bound_evidence(id INTEGER PRIMARY KEY,secret TEXT NOT NULL,CHECK(current_database()='` + sourceName + `')); INSERT INTO source_bound_evidence VALUES(1,'synthetic private device evidence')`); err != nil {
		t.Fatal(err)
	}
	c, o := recoveryFixture(t, dsn)
	report, err := Create(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	target, targetURL := recoveryDatabase(t)
	var name string
	if err := target.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	target.Close()
	restore := RestoreConfig{OpenConfig: o, DatabaseURL: targetURL, ConfirmDatabase: name, ConfirmBackupID: report.ID, RecoveryDirectory: filepath.Join(o.WorkDirectory, "failed-restore"), PGRestore: os.Getenv("OPENUEM_RECOVERY_TEST_PG_RESTORE")}
	if report, err := Restore(t.Context(), restore); !errors.Is(err, ErrRestore) || report != nil || strings.Contains(err.Error(), "synthetic private") {
		t.Fatal("failed restore exposed content or claimed success", err)
	}
	reopened, err := connectDatabase(t.Context(), targetURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.db.Close()
	if err := reopened.emptyTarget(t.Context(), name, 17); err != nil {
		t.Fatal("failed restore did not roll back its database changes", err)
	}
	if _, err := readPrivate(filepath.Join(restore.RecoveryDirectory, "environment.json"), 1<<20); err != nil {
		t.Fatal("unconfirmed restore discarded recovery keys", err)
	}
	if _, err := os.Stat(filepath.Join(restore.RecoveryDirectory, "completed.json")); !os.IsNotExist(err) {
		t.Fatal("failed restore wrote a completion receipt")
	}
}

func TestRecoverySourceKeyDetectionAcrossSchemas(t *testing.T) {
	db, dsn := recoveryDatabase(t)
	if _, err := db.Exec(`CREATE SCHEMA native; CREATE TABLE native.mdm_apple_devices(id INTEGER); CREATE TABLE native.mdm_windows_authorities(id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	c, err := connectDatabase(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.db.Close()
	b := &recoveryBundle{Environment: map[string]string{}}
	if err := c.requiredKeys(t.Context(), b); !errors.Is(err, ErrConfig) {
		t.Fatal("backup omitted source application keys", err)
	}
	b.Environment["ENCRYPTION_MASTER_KEY"] = "synthetic-encryption-master-key-32-bytes"
	for _, value := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"} {
		b.Environment["WINDOWS_MDM_MASTER_KEY"] = value
		if err := c.requiredKeys(t.Context(), b); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid Windows root key accepted", err)
		}
	}
	b.Environment["WINDOWS_MDM_MASTER_KEY"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := c.requiredKeys(t.Context(), b); err != nil {
		t.Fatal("complete source keys rejected", err)
	}
}

func TestRecoveryRefusesUnconfirmedOrActiveDestination(t *testing.T) {
	db, dsn := recoveryDatabase(t)
	if _, err := db.Exec(`CREATE TABLE retained(id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	c, o := recoveryFixture(t, dsn)
	report, err := Create(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	target, destination := recoveryDatabase(t)
	var name string
	if err := target.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	restore := RestoreConfig{OpenConfig: o, DatabaseURL: destination, ConfirmDatabase: name, ConfirmBackupID: report.ID, RecoveryDirectory: filepath.Join(o.WorkDirectory, "blocked"), PGRestore: os.Getenv("OPENUEM_RECOVERY_TEST_PG_RESTORE")}
	// This test's live connection is intentionally still open.
	if _, err := Restore(t.Context(), restore); !errors.Is(err, ErrTarget) {
		t.Fatal("active target accepted", err)
	}
	target.Close()
	restore.ConfirmDatabase = "another database"
	if _, err := Restore(t.Context(), restore); !errors.Is(err, ErrTarget) {
		t.Fatal("unconfirmed target accepted", err)
	}
	restore.ConfirmDatabase = name
	restore.ConfirmBackupID = "another backup"
	if _, err := Restore(t.Context(), restore); !errors.Is(err, ErrConfig) {
		t.Fatal("unconfirmed backup accepted", err)
	}
	if _, err := os.Stat(restore.RecoveryDirectory); !os.IsNotExist(err) {
		t.Fatal("preflight failure left prepared directory")
	}
	t.Setenv("PGOPTIONS", "-c search_path=untrusted")
	if _, err := connectDatabase(t.Context(), destination); !errors.Is(err, ErrConfig) {
		t.Fatal("ambient database settings accepted", err)
	}
}

func TestRecoveryRejectsIdenticalRecipientsBeforeSourceAccess(t *testing.T) {
	c, _ := recoveryFixture(t, "invalid source")
	c.RecoveryRecipient = "# recipient comment\n" + c.DatabaseRecipient + "\n"
	if _, err := Create(t.Context(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("same recipient accepted", err)
	}
	c.RecoveryOutput = c.DatabaseOutput
	if _, err := Create(t.Context(), c); !errors.Is(err, ErrConfig) {
		t.Fatal("same output accepted", err)
	}
}

func TestRecoveryRejectsFileSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires optional Windows developer privileges")
	}
	dir := privateDirectory(t)
	path, link := filepath.Join(dir, "original"), filepath.Join(dir, "link")
	if err := keyfile.Create(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(link, 1024); !errors.Is(err, ErrFile) {
		t.Fatal("source symlink accepted", err)
	}
	if f, err := openArchive(link); !errors.Is(err, ErrFile) {
		if f != nil {
			f.Close()
		}
		t.Fatal("archive symlink accepted", err)
	}
}

func TestRecoveryRejectsUnboundedRecipientsAndImplicitConnections(t *testing.T) {
	if _, err := recipient(strings.Repeat("x", (64<<10)+1)); !errors.Is(err, ErrConfig) {
		t.Fatal("unbounded recipient accepted", err)
	}
	for _, raw := range []string{
		"postgres://user:password@db.example.test/database?sslmode=disable",
		"postgres://user:password@127.0.0.1:55440/database?sslmode=prefer",
		"postgres://user:password@127.0.0.1:55440/database?sslmode=disable&host=other",
		"postgres://user:password@127.0.0.1:55440/database?sslmode=disable&options=untrusted",
		"postgres://user:password@127.0.0.1:55440/database?sslmode=disable&sslmode=verify-full",
		"postgres://user:password@127.0.0.1:55440/database?sslmode=verify-full&sslrootcert=relative.pem",
		"postgres://user:password@127.0.0.1:55440/database?sslmode=verify-full&sslkey=relative.key",
		"postgres://user:password%0Ainjection@127.0.0.1:55440/database?sslmode=disable",
		"postgres://user:password@127.0.0.1:55440/database%00?sslmode=disable",
	} {
		if c, err := connectDatabase(t.Context(), raw); !errors.Is(err, ErrConfig) {
			if c != nil {
				c.db.Close()
			}
			t.Fatal("unsafe database settings reached connection handling", err)
		}
	}
}
