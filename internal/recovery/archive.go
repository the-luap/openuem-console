package recovery

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/keyfile"
)

const archiveMagic = "OPENUEM-DATABASE-BACKUP-1\n"

func Create(ctx context.Context, c CreateConfig) (*Report, error) {
	dataRecipient, err := recipient(c.DatabaseRecipient)
	if err != nil {
		return nil, err
	}
	keyRecipient, err := recipient(c.RecoveryRecipient)
	if err != nil {
		return nil, err
	}
	if fmt.Sprint(dataRecipient) == fmt.Sprint(keyRecipient) || strings.EqualFold(filepath.Clean(c.DatabaseOutput), filepath.Clean(c.RecoveryOutput)) {
		return nil, ErrConfig
	}
	bundle, err := collect(c.Specification, uuid.NewString())
	if err != nil {
		return nil, err
	}
	defer bundle.clear()
	database, err := connectDatabase(ctx, c.DatabaseURL)
	if err != nil {
		return nil, err
	}
	defer database.db.Close()
	if err := database.requiredKeys(ctx, bundle); err != nil {
		return nil, err
	}
	tool, err := postgresTool(ctx, c.PGDump, "pg_dump", database.major)
	if err != nil {
		return nil, err
	}
	dataFile, err := stage(c.DatabaseOutput)
	if err != nil {
		return nil, err
	}
	defer dataFile.close()
	keyFile, err := stage(c.RecoveryOutput)
	if err != nil {
		return nil, err
	}
	defer keyFile.close()
	encoded, err := json.Marshal(bundle)
	if err != nil || len(encoded) > maxRecoveryBytes {
		return nil, ErrConfig
	}
	defer clear(encoded)
	createdAt := time.Now().UTC()
	// Bind the ciphertext, not a public hash of potentially low-entropy secrets.
	digest := sha256.New()
	keyWriter, err := age.Encrypt(io.MultiWriter(keyFile.file, digest), keyRecipient)
	if err != nil {
		return nil, ErrArchive
	}
	if _, err = keyWriter.Write(encoded); err != nil {
		return nil, ErrArchive
	}
	if err = keyWriter.Close(); err != nil {
		return nil, ErrArchive
	}
	report := &Report{Version: formatVersion, ID: bundle.ID, CreatedAt: createdAt, Database: database.database, PostgresMajor: database.major, RecoverySHA256: hex.EncodeToString(digest.Sum(nil)), Environment: sortedKeys(bundle.Environment), Files: sortedKeys(bundle.Files)}
	dataWriter, err := age.Encrypt(&boundedWriter{writer: dataFile.file, remaining: maxBackupBytes}, dataRecipient)
	if err != nil {
		return nil, ErrArchive
	}
	writer := &boundedWriter{writer: dataWriter, remaining: maxBackupBytes}
	if _, err = io.WriteString(writer, archiveMagic); err != nil {
		return nil, ErrArchive
	}
	if err = json.NewEncoder(writer).Encode(report); err != nil {
		return nil, ErrArchive
	}
	// The custom dump includes every non-system schema, all table data, large
	// objects, sequences and post-data constraints/triggers. No data-only restore
	// or trigger disabling is used.
	if err = database.run(ctx, tool, filepath.Dir(dataFile.path), []string{"--format=custom", "--compress=gzip:6", "--lock-wait-timeout=30000", "--quote-all-identifiers"}, writer); err != nil {
		return nil, err
	}
	if err = dataWriter.Close(); err != nil {
		return nil, ErrArchive
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = keyFile.publish(); err != nil {
		return nil, err
	}
	if err = dataFile.publish(); err != nil {
		keyFile.unpublish()
		return nil, err
	}
	return report, nil
}

func (b *recoveryBundle) clear() {
	for _, data := range b.Files {
		clear(data)
	}
	clear(b.Files)
	clear(b.Environment)
}

type openedBackup struct {
	report *Report
	bundle *recoveryBundle
	dump   *os.File
	path   string
}

func (b *openedBackup) close() { b.bundle.clear(); b.dump.Close(); os.Remove(b.path) }

// openBackup authenticates both complete encrypted files before any connection
// to a restore destination. Its temporary plaintext is protected before writing.
// Operators must place WorkDirectory on encrypted storage and keep its ancestors
// trusted. Normal errors/cancellation remove staging; crash cleanup is operational.
func openBackup(ctx context.Context, c OpenConfig) (*openedBackup, error) {
	if keyfile.CheckDirectory(c.WorkDirectory) != nil {
		return nil, ErrFile
	}
	dataKeys, err := identities(c.DatabaseIdentity)
	if err != nil {
		return nil, err
	}
	recoveryKeys, err := identities(c.RecoveryIdentity)
	if err != nil {
		return nil, err
	}
	keyFile, err := openArchive(c.RecoveryInput)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()
	digest := sha256.New()
	keyReader, err := age.Decrypt(contextReader{ctx, io.TeeReader(keyFile, digest)}, recoveryKeys...)
	if err != nil {
		return nil, ErrArchive
	}
	encoded, err := io.ReadAll(io.LimitReader(contextReader{ctx, keyReader}, maxRecoveryBytes+1))
	defer clear(encoded)
	if err != nil || len(encoded) > maxRecoveryBytes {
		return nil, ErrArchive
	}
	var bundle recoveryBundle
	if decodeJSON(encoded, &bundle) != nil || validateBundle(&bundle) != nil {
		bundle.clear()
		return nil, ErrArchive
	}
	file, err := openArchive(c.DatabaseInput)
	if err != nil {
		bundle.clear()
		return nil, err
	}
	defer file.Close()
	reader, err := age.Decrypt(contextReader{ctx, file}, dataKeys...)
	if err != nil {
		bundle.clear()
		return nil, ErrArchive
	}
	buffer := bufio.NewReaderSize(contextReader{ctx, reader}, maxHeaderBytes)
	magic := make([]byte, len(archiveMagic))
	_, err = io.ReadFull(buffer, magic)
	if err != nil || string(magic) != archiveMagic {
		bundle.clear()
		return nil, ErrArchive
	}
	head, err := buffer.ReadSlice('\n')
	if err != nil {
		bundle.clear()
		return nil, ErrArchive
	}
	var report Report
	if decodeJSON(head, &report) != nil || report.Version != formatVersion || report.ID != bundle.ID || report.RecoverySHA256 != hex.EncodeToString(digest.Sum(nil)) || report.PostgresMajor < 17 || report.PostgresMajor > 99 || !validDatabaseName(report.Database) || report.CreatedAt.IsZero() || !reflect.DeepEqual(report.Environment, sortedKeys(bundle.Environment)) || !reflect.DeepEqual(report.Files, sortedKeys(bundle.Files)) {
		bundle.clear()
		return nil, ErrArchive
	}
	if prefix, err := buffer.Peek(5); err != nil || !bytes.Equal(prefix, []byte("PGDMP")) {
		bundle.clear()
		return nil, ErrArchive
	}
	path := filepath.Join(c.WorkDirectory, "restore-"+uuid.NewString()+".dump")
	dump, err := keyfile.CreateFile(path)
	if err != nil {
		bundle.clear()
		return nil, ErrFile
	}
	opened := &openedBackup{report: &report, bundle: &bundle, dump: dump, path: path}
	ready := false
	defer func() {
		if !ready {
			opened.close()
		}
	}()
	if _, err := io.Copy(&boundedWriter{writer: dump, remaining: maxBackupBytes}, buffer); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrArchive
	}
	if err := dump.Sync(); err != nil {
		return nil, ErrFile
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ready = true
	return opened, nil
}

func validateBundle(b *recoveryBundle) error {
	id, err := uuid.Parse(b.ID)
	if err != nil || id.String() != b.ID || b.Version != formatVersion || b.Environment == nil || b.Files == nil || len(b.Environment) > 128 || len(b.Files) > 128 {
		return ErrArchive
	}
	for name, value := range b.Environment {
		if !environmentName.MatchString(name) || len(value) == 0 || len(value) > 1<<20 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return ErrArchive
		}
	}
	for name, data := range b.Files {
		if !validFileName(name) || name != strings.ToLower(name) || len(data) > maxFileBytes {
			return ErrArchive
		}
	}
	return nil
}

// Verify checks encryption, pair binding and envelope grammar. A successful
// verification does not substitute for a restore drill against an isolated server.
func Verify(ctx context.Context, c OpenConfig) (*Report, error) {
	b, err := openBackup(ctx, c)
	if err != nil {
		return nil, err
	}
	defer b.close()
	return b.report, nil
}

func Restore(ctx context.Context, c RestoreConfig) (*Report, error) {
	b, err := openBackup(ctx, c.OpenConfig)
	if err != nil {
		return nil, err
	}
	defer b.close()
	if c.ConfirmBackupID != b.report.ID {
		return nil, ErrConfig
	}
	if !filepath.IsAbs(c.RecoveryDirectory) || keyfile.CheckDirectory(filepath.Dir(c.RecoveryDirectory)) != nil {
		return nil, ErrFile
	}
	if _, err := os.Lstat(c.RecoveryDirectory); !os.IsNotExist(err) {
		return nil, ErrFile
	}
	database, err := connectDatabase(ctx, c.DatabaseURL)
	if err != nil {
		return nil, err
	}
	defer database.db.Close()
	if err := database.emptyTarget(ctx, c.ConfirmDatabase, b.report.PostgresMajor); err != nil {
		return nil, err
	}
	tool, err := postgresTool(ctx, c.PGRestore, "pg_restore", database.major)
	if err != nil {
		return nil, err
	}
	// Fully prepare recovery files before committing database changes, so an
	// unwritable recovery destination cannot strand a restored encrypted database.
	if err := os.Mkdir(c.RecoveryDirectory, 0700); err != nil {
		return nil, ErrFile
	}
	ready := false
	defer func() {
		if !ready {
			os.RemoveAll(c.RecoveryDirectory)
		}
	}()
	if keyfile.CheckDirectory(c.RecoveryDirectory) != nil {
		return nil, ErrFile
	}
	env, err := json.Marshal(b.bundle.Environment)
	if err != nil {
		return nil, ErrArchive
	}
	defer clear(env)
	if err := writePrivate(filepath.Join(c.RecoveryDirectory, "environment.json"), env); err != nil {
		return nil, ErrFile
	}
	for name, data := range b.bundle.Files {
		if err := writePrivate(filepath.Join(c.RecoveryDirectory, name), data); err != nil {
			return nil, ErrFile
		}
	}
	prepared, err := json.Marshal(b.report)
	if err != nil {
		return nil, ErrArchive
	}
	if err := writePrivate(filepath.Join(c.RecoveryDirectory, "recovery.json"), prepared); err != nil {
		return nil, ErrFile
	}
	if err := syncDirectory(filepath.Dir(c.RecoveryDirectory)); err != nil {
		return nil, ErrFile
	}
	if err := database.emptyTarget(ctx, c.ConfirmDatabase, b.report.PostgresMajor); err != nil {
		return nil, err
	}
	if err := b.dump.Close(); err != nil {
		return nil, ErrFile
	}
	// Once a restore process may have committed, an interrupted acknowledgement
	// cannot establish rollback. Preserve the matched recovery keys on every such
	// failure; a retry never overwrites the target or the prepared directory.
	ready = true
	if err := database.run(ctx, tool, c.WorkDirectory, []string{"--single-transaction", "--exit-on-error", "--no-owner", "--no-acl", "--no-tablespaces", b.path}, io.Discard); err != nil {
		return nil, ErrRestore
	}
	completed, err := json.Marshal(struct {
		ID          string    `json:"backup_id"`
		Database    string    `json:"destination_database"`
		CompletedAt time.Time `json:"completed_at"`
	}{b.report.ID, database.database, time.Now().UTC()})
	if err != nil || writePrivate(filepath.Join(c.RecoveryDirectory, "completed.json"), completed) != nil {
		return nil, ErrRestore
	}
	return b.report, nil
}
