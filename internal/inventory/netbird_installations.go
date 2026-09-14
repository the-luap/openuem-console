package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// NetbirdInstallationStore retains reviewed installation intent. Its optional
// preparation constructor admits one authenticated download/inspection RPC.
// Its delivery constructor additionally rechecks current source authority and
// persists one native attempt; preparation alone cannot authorize installation.
type NetbirdInstallationStore struct {
	packages   *NetbirdPackageStore
	inspect    NetbirdOperationInspector
	individual bool
	prepare    NetbirdPreparationExecutor
	execute    NetbirdInstallationExecutor
	control    NetbirdOperationControl
}

func NewNetbirdInstallationStore(db *sql.DB, permissions *access.Store, individual bool, master string, inspect NetbirdOperationInspector) (*NetbirdInstallationStore, error) {
	p, err := NewNetbirdPackageStore(db, permissions, master)
	if err != nil || inspect == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	return &NetbirdInstallationStore{packages: p, inspect: inspect, individual: individual}, nil
}

type NetbirdInstallationReview struct {
	Target   ManualTarget
	Approval NetbirdInstallationPackage
	Revision string
	Journal  netbirdcommand.State
}

// Site assignment exposes the reviewed artifact, not organization-wide approval
// history or the approver's free-text verification reference.
type NetbirdInstallationPackage struct {
	ID, Platform, Architecture, Format, PackageID, Version, SHA256, Digest string
	TenantID, Size                                                         int64
}

// Public history deliberately contains neither the package source nor an
// encrypted descriptor, broker credential, certificate or executable command.
type NetbirdInstallation struct {
	ID, DeviceID, Actor, ApprovalID, ApprovalDigest, Revision, JournalRevision string
	Scope                                                                      access.Scope
	RequestedAt, ExpiresAt                                                     time.Time
	CancellationID, CancelledBy                                                string
	CancelledAt                                                                *time.Time
	CompletedAt                                                                *time.Time
	ReleasedAt                                                                 *time.Time
	ReleasedBy, ResolutionID                                                   string
}

type installationSource struct {
	review            NetbirdInstallationReview
	packageDescriptor packageapi.Package
	identity          netbirdcommand.Identity
	identityExpiresAt time.Time
}

func (installationSource) String() string {
	return "NetBird installation source (private data redacted)"
}
func (s installationSource) GoString() string { return s.String() }

func (s *NetbirdInstallationStore) begin(ctx context.Context, actor string, scope access.Scope, capability access.Capability) (*sql.Tx, error) {
	if scope.TenantID <= 0 || scope.SiteID <= 0 {
		return nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.packages.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = s.packages.permissions.AuthorizeTransaction(ctx, tx, actor, capability, scope); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// approvedDescriptor holds revocation exclusion until its caller's transaction
// ends. Only trusted inventory admission code can obtain the private descriptor.
func (s *NetbirdPackageStore) approvedDescriptor(ctx context.Context, tx *sql.Tx, tenant int, id, digest string) (*NetbirdPackageApproval, packageapi.Package, error) {
	var empty packageapi.Package
	if !canonicalRequestID(id) || !netbirdcommand.ValidDigest(digest) || tenant <= 0 {
		return nil, empty, ErrNetbirdPackageInvalid
	}
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT id::text FROM uem_netbird_packages WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNetbirdPackageMissing
		}
		return nil, empty, err
	}
	p, err := scanNetbirdPackage(tx.QueryRowContext(ctx, `SELECT `+netbirdPackageColumns+netbirdPackageFrom+`WHERE p.id=$1`, id))
	if err != nil {
		return nil, empty, err
	}
	if p.Digest != digest || p.RevokedAt != nil {
		return nil, empty, ErrNetbirdPackageConflict
	}
	var encrypted []byte
	if err = tx.QueryRowContext(ctx, `SELECT encrypted_descriptor FROM uem_netbird_packages WHERE id=$1`, id).Scan(&encrypted); err != nil {
		return nil, empty, err
	}
	plain, err := s.openPackage(p, encrypted)
	defer clear(plain)
	if err != nil {
		return nil, empty, err
	}
	d, err := packageapi.Decode(plain)
	if err != nil {
		return nil, empty, ErrNetbirdPackageSecret
	}
	canonical, err := packageapi.Encode(d)
	defer clear(canonical)
	hash, hashErr := d.Digest()
	if err != nil || hashErr != nil || !bytes.Equal(plain, canonical) || hash != digest || d.ApprovalID != p.ID || d.TenantID != p.TenantID || d.Platform != p.Platform || d.Architecture != p.Architecture || d.Format != p.Format || d.PackageID != p.PackageID || d.Version != p.Version || d.Size != p.Size || d.SHA256 != p.SHA256 {
		return nil, empty, ErrNetbirdPackageSecret
	}
	return p, d, nil
}

func (s *NetbirdInstallationStore) source(ctx context.Context, tx *sql.Tx, scope access.Scope, device, approval, digest string) (*installationSource, error) {
	if !s.individual {
		return nil, ErrNetbirdOperationNotReady
	}
	if !canonicalRequestID(device) {
		return nil, ErrNetbirdOperationInvalid
	}
	manual := &ManualExecutionStore{db: s.packages.db, permissions: s.packages.permissions, individual: true}
	target, err := manual.target(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	if target.Platform != "macos" && target.Platform != "linux" {
		return nil, ErrManualUnsupported
	}
	p, d, err := s.packages.approvedDescriptor(ctx, tx, scope.TenantID, approval, digest)
	if err != nil {
		return nil, err
	}
	preview := NetbirdInstallationPackage{ID: p.ID, Platform: p.Platform, Architecture: p.Architecture, Format: p.Format, PackageID: p.PackageID, Version: p.Version, SHA256: p.SHA256, Digest: p.Digest, TenantID: p.TenantID, Size: p.Size}
	r := &installationSource{review: NetbirdInstallationReview{Target: target, Approval: preview}, packageDescriptor: d}
	var platform, architecture, broker, generation string
	var consumer int64
	err = tx.QueryRowContext(ctx, `SELECT i.platform,i.architecture,i.certificate_hash,i.broker_key,q.revision,i.certificate_expires_at FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 FOR SHARE OF i,q`, device, scope.TenantID, scope.SiteID).Scan(&platform, &architecture, &r.identity.CertificateHash, &broker, &consumer, &r.identityExpiresAt)
	if err != nil {
		return nil, err
	}
	r.identity.DeviceID, r.identity.TenantID, r.identity.SiteID, r.identity.Individual = device, int64(scope.TenantID), int64(scope.SiteID), true
	if !r.identity.Valid() || target.Platform != platform || !d.MatchesTarget(int64(scope.TenantID), platform, architecture) || len(broker) > 256 {
		return nil, ErrNetbirdOperationChanged
	}
	// Follow report writer ordering, including an optional absent-client row.
	var ignored bool
	err = tx.QueryRowContext(ctx, `SELECT true FROM netbirds WHERE agent_netbird=$1 FOR SHARE`, device).Scan(&ignored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT revision::text FROM uem_netbird_device_bindings WHERE device_id=$1 FOR SHARE`, device).Scan(&generation); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(2 * time.Second)
	if r.identityExpiresAt.Before(deadline) {
		deadline = r.identityExpiresAt
	}
	probe, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	r.review.Journal, err = s.inspect(probe, r.identity)
	if err != nil || probe.Err() != nil || !r.review.Journal.Valid() || r.review.Journal.Status != "ready" {
		return nil, ErrNetbirdOperationNotReady
	}
	data, err := json.Marshal(struct {
		Version                                                                         int
		Operation, Device, Approval, Digest, Generation, Broker, Platform, Architecture string
		Scope                                                                           access.Scope
		Identity                                                                        netbirdcommand.Identity
		CertificateExpiresAt                                                            time.Time
		Consumer                                                                        int64
		Journal                                                                         string
	}{1, "install", device, approval, digest, generation, broker, platform, architecture, scope, r.identity, r.identityExpiresAt.UTC(), consumer, r.review.Journal.Revision})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	r.review.Revision = hex.EncodeToString(hash[:])
	return r, nil
}

func installationAudit(ctx context.Context, tx *sql.Tx, actor string, r *NetbirdInstallation, action, result string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "install"}, actor, action, result)
}

func (s *NetbirdInstallationStore) Review(parent context.Context, actor string, scope access.Scope, device, approval, digest string) (*NetbirdInstallationReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := s.source(ctx, tx, scope, device, approval, digest)
	if err != nil {
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, &NetbirdInstallation{DeviceID: device, Scope: scope}, "review", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &r.review, nil
}

const installationColumns = `id::text,device_id,tenant_id,site_id,actor,approval_id::text,approval_digest,revision,journal_revision,requested_at,expires_at,coalesce(cancellation_id::text,''),coalesce(cancelled_by,''),cancelled_at,completed_at,released_at,coalesce(released_by,''),coalesce(resolution_id::text,'')`

func scanInstallation(row interface{ Scan(...any) error }) (*NetbirdInstallation, error) {
	var r NetbirdInstallation
	err := row.Scan(&r.ID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.ApprovalID, &r.ApprovalDigest, &r.Revision, &r.JournalRevision, &r.RequestedAt, &r.ExpiresAt, &r.CancellationID, &r.CancelledBy, &r.CancelledAt, &r.CompletedAt, &r.ReleasedAt, &r.ReleasedBy, &r.ResolutionID)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *NetbirdInstallationStore) Request(parent context.Context, actor string, scope access.Scope, device, id, approval, digest, revision string) (*NetbirdInstallation, error) {
	if !canonicalRequestID(device) || !canonicalRequestID(id) || !canonicalRequestID(approval) || !netbirdcommand.ValidDigest(digest) || !netbirdcommand.ValidDigest(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629916,hashtext($1))`, id); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, err
	}
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1`, id))
	if err == nil {
		if r.DeviceID != device || r.Actor != actor || r.Scope != scope || r.ApprovalID != approval || r.ApprovalDigest != digest || r.Revision != revision {
			return nil, ErrNetbirdOperationConflict
		}
		if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var pending bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_operations WHERE id=$2 OR (device_id=$1 AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))) OR EXISTS(SELECT 1 FROM uem_netbird_registrations WHERE id=$2 OR (device_id=$1 AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))) OR EXISTS(SELECT 1 FROM uem_netbird_installations WHERE device_id=$1 AND cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL)`, device, id).Scan(&pending)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrNetbirdOperationConflict
	}
	source, err := s.source(ctx, tx, scope, device, approval, digest)
	if err != nil {
		return nil, err
	}
	if source.review.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	r, err = scanInstallation(tx.QueryRowContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_installations(id,device_id,tenant_id,site_id,actor,approval_id,approval_digest,revision,journal_revision,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,at,least(at+interval '10 minutes',$10) FROM stamp WHERE at<$10 RETURNING `+installationColumns, id, device, scope.TenantID, scope.SiteID, actor, approval, digest, revision, source.review.Journal.Revision, source.identityExpiresAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetbirdOperationChanged
	}
	if err != nil {
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, r, "request", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *NetbirdInstallationStore) Read(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdInstallation, error) {
	if !canonicalRequestID(id) || !canonicalRequestID(device) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

// Cancel applies before native command delivery, including during preparation.
// Preparation cannot undo cancellation. Native delivery attempts permanently
// exclude this operation; only verified completion or explicit recovery can proceed.
func (s *NetbirdInstallationStore) Cancel(parent context.Context, actor string, scope access.Scope, device, id, revision, cancellation string) (*NetbirdInstallation, error) {
	if !canonicalRequestID(device) || !canonicalRequestID(id) || !canonicalRequestID(cancellation) || !netbirdcommand.ValidDigest(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, err
	}
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if r.Revision != revision {
		return nil, ErrNetbirdOperationConflict
	}
	if r.CancelledAt != nil {
		if r.CancellationID != cancellation || r.CancelledBy != actor {
			return nil, ErrNetbirdOperationConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	var attempted bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_installation_attempts WHERE request_id=$1)`, id).Scan(&attempted); err != nil {
		return nil, err
	}
	if attempted || r.CompletedAt != nil || r.ReleasedAt != nil {
		return nil, ErrNetbirdOperationConflict
	}
	r, err = scanInstallation(tx.QueryRowContext(ctx, `UPDATE uem_netbird_installations SET cancellation_id=$2,cancelled_by=$3,cancelled_at=clock_timestamp() WHERE id=$1 RETURNING `+installationColumns, id, cancellation, actor))
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			err = ErrNetbirdOperationConflict
		}
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, r, "stopped", "cancelled"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
