package desktop

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/gateway"
)

type InstallerInvitation struct {
	*registry.Invitation
	ReleaseDigest string             `json:"release_digest"`
	Version       string             `json:"version"`
	Artifact      artifacts.Artifact `json:"artifact"`
}

// InviteInstaller binds a scoped invitation to the exact approved release. The
// caller supplies the canonical server origin from trusted configuration and
// enforces its user's enrollment capability before calling. No invitation token
// leaves this function until the invitation, release binding and audit commit.
func (s *Store) InviteInstaller(ctx context.Context, catalog *Catalog, options registry.InvitationOptions, releaseDigest, publicOrigin, actor string) (*InstallerInvitation, error) {
	if catalog == nil || catalog.db != s.db {
		return nil, ErrNoRelease
	}
	if !canonicalEnrollmentOrigin(publicOrigin) {
		return nil, registry.ErrInvalid
	}
	file, _, err := catalog.OpenPackage(ctx, releaseDigest, options.Platform, options.Architecture)
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, ErrReleaseFiles
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, err := catalog.currentInTransaction(ctx, tx)
	if err != nil {
		return nil, err
	}
	if current.Digest() != releaseDigest {
		return nil, ErrNoRelease
	}
	if options.ExpiresAt.After(current.Manifest().ExpiresAt) {
		return nil, registry.ErrInvalid
	}
	target, err := current.Select(options.Platform, options.Architecture)
	if err != nil {
		return nil, err
	}
	invitation, err := s.Registry.InviteInTransaction(ctx, tx, options, actor)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(invitation.URL, publicOrigin+"/enroll/desktop/") {
		return nil, registry.ErrInvalid
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_desktop_invitation_releases(invitation_id,release_digest) VALUES($1,$2)`, invitation.ID, releaseDigest); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &InstallerInvitation{Invitation: invitation, ReleaseDigest: releaseDigest, Version: current.Manifest().Version, Artifact: target}, nil
}

// ClaimInstaller requires the invitation's selected release to remain current,
// trusted and active. The shared checkpoint lock serializes issuance with
// release acceptance/withdrawal. Registry checks still enforce both key proofs,
// site ownership, expiry/revocation and idempotent identity recovery.
func (s *Store) ClaimInstaller(ctx context.Context, catalog *Catalog, request enrollment.Request, publicOrigin string) (*enrollment.Response, error) {
	if catalog == nil || catalog.db != s.db {
		return nil, ErrNoRelease
	}
	if !canonicalEnrollmentOrigin(publicOrigin) {
		return nil, registry.ErrInvalid
	}
	// Reject malformed/forged proofs before acquiring a database connection.
	if _, err := enrollment.Validate(request); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, err := catalog.currentInTransaction(ctx, tx)
	if err != nil {
		return nil, err
	}
	if _, err = current.Select(request.Platform, request.Architecture); err != nil {
		return nil, err
	}
	var selected, origin string
	digest := sha256.Sum256([]byte(request.Invitation))
	err = tx.QueryRowContext(ctx, `SELECT b.release_digest,a.public_origin FROM uem_agent_invitations i JOIN uem_desktop_invitation_releases b ON b.invitation_id=i.id JOIN uem_agent_authorities a ON a.tenant_id=i.tenant_id WHERE i.token_hash=$1`, hex.EncodeToString(digest[:])).Scan(&selected, &origin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, registry.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if selected != current.Digest() {
		return nil, ErrNoRelease
	}
	if origin != publicOrigin {
		return nil, registry.ErrNotFound
	}
	response, err := s.Registry.ClaimInTransaction(ctx, tx, request)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}

// Always acquire the release checkpoint before registry invitation/site/identity
// locks. No file or network operations run while these transaction locks are held.
func (c *Catalog) currentInTransaction(ctx context.Context, tx *sql.Tx) (*artifacts.Verified, error) {
	var checkpoint artifacts.Checkpoint
	err := tx.QueryRowContext(ctx, `SELECT sequence,COALESCE(digest,'') FROM uem_desktop_release_checkpoint WHERE id=1 FOR SHARE`).Scan(&checkpoint.Sequence, &checkpoint.Digest)
	if err != nil {
		return nil, err
	}
	if checkpoint.Sequence == 0 {
		return nil, ErrNoRelease
	}
	var data []byte
	var withdrawn bool
	err = tx.QueryRowContext(ctx, `SELECT envelope,withdrawn_at IS NOT NULL FROM uem_desktop_releases WHERE digest=$1 FOR SHARE`, checkpoint.Digest).Scan(&data, &withdrawn)
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

func canonicalEnrollmentOrigin(value string) bool {
	origin, err := gateway.ParseOrigin(value)
	return err == nil && origin.String() == value
}
