package desktop

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/open-uem/nats/enrollment/artifacts"
)

var (
	ErrNoRelease    = errors.New("no approved installer release is available")
	ErrWithdrawn    = errors.New("installer release has been withdrawn")
	ErrReleaseFiles = errors.New("approved installer files are unavailable or changed")
)

// Catalog is installation-wide. Only trusted server administrators may accept or
// withdraw releases; user-facing callers must enforce that capability. It owns
// its directory handle, not the shared database connection.
type Catalog struct {
	db      *sql.DB
	root    *os.Root
	trusted []ed25519.PublicKey
}

func NewCatalog(db *sql.DB, directory string, trusted []ed25519.PublicKey) (*Catalog, error) {
	if db == nil || directory == "" || len(trusted) == 0 || len(trusted) > 8 {
		return nil, artifacts.ErrInvalid
	}
	keys := make([]ed25519.PublicKey, 0, len(trusted))
	seen := make(map[string]bool)
	for _, key := range trusted {
		id := artifacts.KeyID(key)
		if id == "" || seen[id] {
			return nil, artifacts.ErrInvalid
		}
		seen[id] = true
		keys = append(keys, append(ed25519.PublicKey(nil), key...))
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrReleaseFiles
	}
	return &Catalog{db: db, root: root, trusted: keys}, nil
}

func (c *Catalog) Close() error { return c.root.Close() }

// Accept verifies every artifact before locking the persisted checkpoint. It
// then rechecks signature, expiry and the latest checkpoint inside the same
// transaction as acceptance/audit, so concurrent approvals cannot lower it.
func (c *Catalog) Accept(ctx context.Context, envelope []byte, actor string) (*artifacts.Verified, error) {
	if !releaseActor(actor) {
		return nil, artifacts.ErrInvalid
	}
	// Own the bytes throughout verification and persistence.
	if len(envelope) > artifacts.MaxEnvelopeSize {
		return nil, artifacts.ErrInvalid
	}
	data := append([]byte(nil), envelope...)
	candidate, err := artifacts.Verify(data, c.trusted, time.Now(), artifacts.Checkpoint{})
	if err != nil {
		return nil, err
	}
	for _, target := range candidate.Manifest().Artifacts {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		file, err := c.openPackage(ctx, candidate, target.Platform, target.Architecture)
		if err != nil {
			return nil, err
		}
		if err = file.Close(); err != nil {
			return nil, ErrReleaseFiles
		}
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	checkpoint, err := lockedCheckpoint(ctx, tx)
	if err != nil {
		return nil, err
	}
	verified, err := artifacts.Verify(data, c.trusted, time.Now(), checkpoint)
	if err != nil {
		return nil, err
	}
	var withdrawn bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_desktop_releases WHERE digest=$1 AND withdrawn_at IS NOT NULL)`, verified.Digest()).Scan(&withdrawn); err != nil {
		return nil, err
	}
	if withdrawn {
		return nil, ErrWithdrawn
	}
	m := verified.Manifest()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_desktop_releases(digest,sequence,version,published_at,expires_at,signing_key_id,envelope,accepted_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(digest) DO UPDATE SET envelope=EXCLUDED.envelope,signing_key_id=EXCLUDED.signing_key_id,accepted_at=clock_timestamp(),accepted_by=EXCLUDED.accepted_by`, verified.Digest(), m.Sequence, m.Version, m.PublishedAt, m.ExpiresAt, verified.SigningKeyID(), data, actor)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_desktop_release_checkpoint SET sequence=$1,digest=$2 WHERE id=1`, m.Sequence, verified.Digest()); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_desktop_release_audit(actor,action,digest,sequence) VALUES($1,'release.accept',$2,$3)`, actor, verified.Digest(), m.Sequence); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return verified, nil
}

func lockedCheckpoint(ctx context.Context, tx *sql.Tx) (artifacts.Checkpoint, error) {
	var checkpoint artifacts.Checkpoint
	err := tx.QueryRowContext(ctx, `SELECT sequence,COALESCE(digest,'') FROM uem_desktop_release_checkpoint WHERE id=1 FOR UPDATE`).Scan(&checkpoint.Sequence, &checkpoint.Digest)
	return checkpoint, err
}

// Current re-verifies stored bytes under the configured trust ring and current
// time on every call. It does not fall back to an older release after withdrawal,
// expiry, a missing package or removal of the release signing key.
func (c *Catalog) Current(ctx context.Context) (*artifacts.Verified, error) {
	var checkpoint artifacts.Checkpoint
	var data []byte
	var withdrawn bool
	err := c.db.QueryRowContext(ctx, `SELECT p.sequence,p.digest,r.envelope,r.withdrawn_at IS NOT NULL FROM uem_desktop_release_checkpoint p JOIN uem_desktop_releases r ON r.digest=p.digest WHERE p.id=1`).Scan(&checkpoint.Sequence, &checkpoint.Digest, &data, &withdrawn)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoRelease
	}
	if err != nil {
		return nil, err
	}
	if withdrawn {
		return nil, ErrWithdrawn
	}
	verified, err := artifacts.Verify(data, c.trusted, time.Now(), checkpoint)
	if err != nil {
		return nil, err
	}
	if verified.Checkpoint() != checkpoint {
		return nil, artifacts.ErrInvalid
	}
	return verified, nil
}

func (c *Catalog) Withdraw(ctx context.Context, digest, actor string) error {
	return WithdrawRelease(ctx, c.db, digest, actor)
}

// WithdrawRelease needs only administrative database access. It remains usable
// when the package repository or release trust-key file is unavailable.
func WithdrawRelease(ctx context.Context, db *sql.DB, digest, actor string) error {
	if db == nil || !releaseActor(actor) || !releaseDigest(digest) {
		return artifacts.ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	checkpoint, err := lockedCheckpoint(ctx, tx)
	if err != nil {
		return err
	}
	if checkpoint.Digest != digest {
		return ErrNoRelease
	}
	result, err := tx.ExecContext(ctx, `UPDATE uem_desktop_releases SET withdrawn_at=clock_timestamp() WHERE digest=$1 AND withdrawn_at IS NULL`, digest)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed > 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_desktop_release_audit(actor,action,digest,sequence) VALUES($1,'release.withdraw',$2,$3)`, actor, digest, checkpoint.Sequence); err != nil {
			return err
		}
	}
	// Deliberately retain the sequence/digest checkpoint after withdrawal.
	return tx.Commit()
}

// OpenPackage returns the same open file descriptor whose bytes were verified.
// The release repository must be read-only to the serving process and published
// by atomic directory/file renames, never in-place writes. The caller owns Close.
// Requests already authorized may finish when a later release is accepted.
func (c *Catalog) OpenPackage(ctx context.Context, digest, platform, architecture string) (*os.File, artifacts.Artifact, error) {
	if !releaseDigest(digest) {
		return nil, artifacts.Artifact{}, ErrNoRelease
	}
	verified, err := c.Current(ctx)
	if err != nil {
		return nil, artifacts.Artifact{}, err
	}
	if verified.Digest() != digest {
		return nil, artifacts.Artifact{}, ErrNoRelease
	}
	target, err := verified.Select(platform, architecture)
	if err != nil {
		return nil, artifacts.Artifact{}, err
	}
	file, err := c.openPackage(ctx, verified, platform, architecture)
	if err != nil {
		return nil, artifacts.Artifact{}, err
	}
	current, err := c.Current(ctx)
	if err != nil || current.Digest() != digest {
		file.Close()
		if err == nil {
			err = ErrNoRelease
		}
		return nil, artifacts.Artifact{}, err
	}
	return file, target, nil
}

func (c *Catalog) openPackage(ctx context.Context, verified *artifacts.Verified, platform, architecture string) (*os.File, error) {
	target, err := verified.Select(platform, architecture)
	if err != nil {
		return nil, err
	}
	info, err := c.root.Lstat(verified.Digest())
	if err != nil || !info.IsDir() {
		return nil, ErrReleaseFiles
	}
	directory, err := c.root.OpenRoot(verified.Digest())
	if err != nil {
		return nil, ErrReleaseFiles
	}
	defer directory.Close()
	before, err := directory.Lstat(target.Filename)
	if err != nil || !before.Mode().IsRegular() || before.Size() != target.Size {
		return nil, ErrReleaseFiles
	}
	file, err := directory.Open(target.Filename)
	if err != nil {
		return nil, ErrReleaseFiles
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, ErrReleaseFiles
	}
	if err = verified.VerifyPackage(platform, architecture, contextReader{ctx: ctx, reader: file}); err != nil {
		file.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrReleaseFiles
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, ErrReleaseFiles
	}
	return file, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func releaseActor(actor string) bool {
	return actor != "" && len(actor) <= 255 && strings.IndexFunc(actor, unicode.IsControl) < 0
}
func releaseDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
