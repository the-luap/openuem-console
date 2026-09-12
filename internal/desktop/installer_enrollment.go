package desktop

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
	"github.com/open-uem/openuem-console/internal/gateway"
)

type InstallerInvitation struct {
	*registry.Invitation
	ReleaseDigest string             `json:"release_digest"`
	Version       string             `json:"version"`
	Artifact      artifacts.Artifact `json:"artifact"`
}

// InstallerMetadata contains only public installation information. The release
// envelope authenticates artifact hashes under separately pinned release keys;
// it does not sign the organization, invitation or origin in this response.
type InstallerMetadata struct {
	Version         int                `json:"version"`
	Organization    string             `json:"organization"`
	Site            string             `json:"site"`
	TenantID        int                `json:"tenant_id"`
	SiteID          int                `json:"site_id"`
	Platform        string             `json:"platform"`
	Architecture    string             `json:"architecture"`
	ExpiresAt       time.Time          `json:"expires_at"`
	AvailableUses   int                `json:"available_uses"`
	ReleaseDigest   string             `json:"release_digest"`
	ReleaseEnvelope json.RawMessage    `json:"release_envelope"`
	Artifact        artifacts.Artifact `json:"artifact"`
	DownloadURL     string             `json:"download_url"`
}

// InstallerMetadata never reserves a use or changes enrollment state. A fully
// used invitation may still expose public metadata for recovery with the same
// endpoint keys; ClaimInstaller alone decides whether that retry is authorized.
func (s *Store) InstallerMetadata(ctx context.Context, catalog *Catalog, token, publicOrigin string) (*InstallerMetadata, error) {
	if catalog == nil || catalog.db != s.db {
		return nil, ErrNoRelease
	}
	if !enrollment.ValidToken(token) || !canonicalEnrollmentOrigin(publicOrigin) {
		return nil, registry.ErrNotFound
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
	digest := sha256.Sum256([]byte(token))
	result := &InstallerMetadata{Version: enrollment.Version, ReleaseDigest: current.Digest()}
	err = tx.QueryRowContext(ctx, `SELECT a.organization,s.description,i.tenant_id,i.site_id,i.platform,i.architecture,i.expires_at,i.max_uses-i.uses,r.envelope
		FROM uem_agent_invitations i
		JOIN uem_desktop_invitation_releases b ON b.invitation_id=i.id
		JOIN uem_desktop_releases r ON r.digest=b.release_digest
		JOIN uem_agent_authorities a ON a.tenant_id=i.tenant_id
		JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id
		WHERE i.token_hash=$1 AND b.release_digest=$2 AND a.public_origin=$3
		AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp() AND a.expires_at>clock_timestamp()`, hex.EncodeToString(digest[:]), current.Digest(), publicOrigin).Scan(&result.Organization, &result.Site, &result.TenantID, &result.SiteID, &result.Platform, &result.Architecture, &result.ExpiresAt, &result.AvailableUses, &result.ReleaseEnvelope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, registry.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	result.Artifact, err = current.Select(result.Platform, result.Architecture)
	if err != nil {
		return nil, err
	}
	result.DownloadURL = publicOrigin + protocol.DownloadPath(current.Digest(), result.Platform, result.Architecture)
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
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
