// Package recovery creates encrypted database backups with a separately encrypted
// recovery bundle. It never starts application services or replaces a live database.
package recovery

import (
	"errors"
	"time"
)

const (
	formatVersion    = 1
	maxHeaderBytes   = 64 << 10
	maxRecoveryBytes = 64 << 20
	maxFileBytes     = 16 << 20
	maxBackupBytes   = int64(1 << 40)
)

var (
	ErrConfig   = errors.New("invalid recovery configuration")
	ErrFile     = errors.New("recovery requires new output files and protected, trusted parent directories")
	ErrArchive  = errors.New("backup authentication or recovery bundle validation failed")
	ErrDatabase = errors.New("database backup or restore failed; no successful recovery is recorded")
	ErrTarget   = errors.New("restore requires the confirmed, empty destination database with no other connections")
	ErrRestore  = errors.New("restore completion is unconfirmed; inspect the destination database; prepared recovery files have been preserved")
)

// Specification contains names and paths, never environment values. Files are
// restored into a new directory under their flat logical names, not original paths.
type Specification struct {
	Environment []string     `json:"environment"`
	Files       []FileSource `json:"files"`
}

type FileSource struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type CreateConfig struct {
	DatabaseURL       string
	DatabaseOutput    string
	RecoveryOutput    string
	DatabaseRecipient string
	RecoveryRecipient string
	Specification     Specification
	PGDump            string
}

type OpenConfig struct {
	DatabaseInput    string
	RecoveryInput    string
	DatabaseIdentity string
	RecoveryIdentity string
	WorkDirectory    string
}

type RestoreConfig struct {
	OpenConfig
	DatabaseURL       string
	ConfirmDatabase   string
	ConfirmBackupID   string
	RecoveryDirectory string
	PGRestore         string
}

// Report contains no credentials, file contents, connection URL or private key.
type Report struct {
	Version        int       `json:"version"`
	ID             string    `json:"backup_id"`
	CreatedAt      time.Time `json:"created_at"`
	Database       string    `json:"source_database"`
	PostgresMajor  int       `json:"postgres_major"`
	RecoverySHA256 string    `json:"recovery_sha256"` // SHA-256 of the encrypted recovery file.
	Environment    []string  `json:"environment"`
	Files          []string  `json:"files"`
}

type recoveryBundle struct {
	Version     int               `json:"version"`
	ID          string            `json:"backup_id"`
	Environment map[string]string `json:"environment"`
	Files       map[string][]byte `json:"files"`
}

// Secret-bearing configuration must not enter ordinary JSON or diagnostics.
func (CreateConfig) String() string                { return "[private recovery configuration]" }
func (CreateConfig) GoString() string              { return "[private recovery configuration]" }
func (CreateConfig) MarshalJSON() ([]byte, error)  { return []byte(`{}`), nil }
func (RestoreConfig) String() string               { return "[private recovery configuration]" }
func (RestoreConfig) GoString() string             { return "[private recovery configuration]" }
func (RestoreConfig) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (recoveryBundle) String() string              { return "[private recovery bundle]" }
func (recoveryBundle) GoString() string            { return "[private recovery bundle]" }
