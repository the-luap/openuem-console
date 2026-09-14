package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// StageCleanup requests form a separate durable family. The original uninstall
// and its release evidence remain unchanged by stage cleanup delivery.
type NetbirdRemovalStageCleanupStore struct {
	base    *NetbirdRemovalStore
	execute NetbirdRemovalStageCleanupExecutor
}

func NewNetbirdRemovalStageCleanupStore(db *sql.DB, permissions *access.Store, individual bool, control NetbirdOperationControl) (*NetbirdRemovalStageCleanupStore, error) {
	base, err := NewNetbirdRemovalStore(db, permissions, individual, control)
	if err != nil {
		return nil, err
	}
	return &NetbirdRemovalStageCleanupStore{base: base}, nil
}

type NetbirdRemovalStageCleanupReview struct {
	Target                       ManualTarget
	StageCleanup                 netbirdcommand.RemovalStageCleanup `json:"-"`
	StageCleanupDigest, Revision string
	Journal                      netbirdcommand.State
}

type NetbirdRemovalStageCleanup struct {
	ID, OriginalID, DeviceID, Actor, Revision, JournalRevision, StageCleanupDigest string
	Scope                                                                          access.Scope
	StageCleanup                                                                   netbirdcommand.RemovalStageCleanup `json:"-"`
	RequestedAt, ExpiresAt                                                         time.Time
	CancellationID, CancelledBy                                                    string
	CancelledAt, CompletedAt, ReleasedAt                                           *time.Time
	ReleasedBy, ResolutionID                                                       string
}

// Public records explicitly serialize source-free stage cleanup evidence without a
// current certificate, broker key, executable command or private native paths.
func (r NetbirdRemovalStageCleanupReview) MarshalJSON() ([]byte, error) {
	type public NetbirdRemovalStageCleanupReview
	data, err := netbirdcommand.EncodeRemovalStageCleanup(r.StageCleanup)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		public
		StageCleanup json.RawMessage
	}{public(r), data})
}
func (r NetbirdRemovalStageCleanup) MarshalJSON() ([]byte, error) {
	type public NetbirdRemovalStageCleanup
	data, err := netbirdcommand.EncodeRemovalStageCleanup(r.StageCleanup)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		public
		StageCleanup json.RawMessage
	}{public(r), data})
}

type removalStageCleanupSource struct {
	review            NetbirdRemovalStageCleanupReview
	identity          netbirdcommand.Identity
	identityExpiresAt time.Time
}

func (removalStageCleanupSource) String() string {
	return "NetBird stage cleanup source (private data redacted)"
}
func (s removalStageCleanupSource) GoString() string { return s.String() }
func (removalStageCleanupSource) MarshalJSON() ([]byte, error) {
	return nil, ErrNetbirdOperationInvalid
}

func removalStageCleanupDigest(r netbirdcommand.RemovalStageCleanup) (string, error) {
	data, err := netbirdcommand.EncodeRemovalStageCleanup(r)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-stage-cleanup-descriptor/v1\x00"), data...))
	return hex.EncodeToString(hash[:]), nil
}

func (s *NetbirdRemovalStageCleanupStore) source(ctx context.Context, tx *sql.Tx, scope access.Scope, device, originalID string) (*removalStageCleanupSource, error) {
	if !s.base.individual {
		return nil, ErrNetbirdOperationNotReady
	}
	original, err := readRemovalRecoveryOriginal(ctx, tx, scope, device, originalID)
	if err != nil {
		return nil, err
	}
	manual := &ManualExecutionStore{db: s.base.db, permissions: s.base.permissions, individual: true}
	target, err := manual.target(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	if target.Platform != "macos" {
		return nil, ErrManualUnsupported
	}
	r := &removalStageCleanupSource{review: NetbirdRemovalStageCleanupReview{Target: target}}
	var platform, architecture, broker, generation string
	var consumer int64
	err = tx.QueryRowContext(ctx, `SELECT i.platform,i.architecture,i.certificate_hash,i.broker_key,q.revision,i.certificate_expires_at FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 FOR SHARE OF i,q`, device, scope.TenantID, scope.SiteID).Scan(&platform, &architecture, &r.identity.CertificateHash, &broker, &consumer, &r.identityExpiresAt)
	if err != nil {
		return nil, err
	}
	r.identity.DeviceID, r.identity.TenantID, r.identity.SiteID, r.identity.Individual = device, int64(scope.TenantID), int64(scope.SiteID), true
	if !r.identity.Valid() || platform != target.Platform || original.Removal.Platform != platform || original.Removal.Architecture != architecture || len(broker) > 256 {
		return nil, ErrNetbirdOperationChanged
	}
	// Keep report-writer lock order, including missing periodic client inventory.
	var ignored bool
	err = tx.QueryRowContext(ctx, `SELECT true FROM netbirds WHERE agent_netbird=$1 FOR SHARE`, device).Scan(&ignored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT revision::text FROM uem_netbird_device_bindings WHERE device_id=$1 FOR SHARE`, device).Scan(&generation); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	expires := at.Add(netbirdcommand.RemovalStageCleanupInspectionLifetime)
	if r.identityExpiresAt.Before(expires) {
		expires = r.identityExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	q := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalStageCleanupInspectionVersion, Identity: r.identity, RequestID: uuid.NewString(), Kind: "removal-stage-cleanup-state", RemovalStageCleanupOriginal: netbirdcommand.RemovalStageCleanupReference{RequestID: original.RequestID, CommandHash: original.CommandHash, Revision: original.Revision, ReleaseID: original.ReleaseID}, IssuedAt: at, ExpiresAt: expires}
	if !q.Executable(r.identity, at) {
		return nil, ErrNetbirdOperationNotReady
	}
	probe, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	p, err := s.base.control(probe, q)
	if err != nil || p == nil || probe.Err() != nil || !p.Matches(q) || p.Outcome != "ok" || p.State.Status != "ready" {
		return nil, ErrNetbirdOperationNotReady
	}
	r.review.StageCleanup, r.review.Journal = p.RemovalStageCleanup, p.State
	r.review.StageCleanupDigest, err = removalStageCleanupDigest(p.RemovalStageCleanup)
	if err != nil {
		return nil, ErrNetbirdOperationChanged
	}
	data, err := json.Marshal(struct {
		Schema                                                                      int
		Operation, Device, StageCleanup, Generation, Broker, Platform, Architecture string
		Scope                                                                       access.Scope
		Identity                                                                    netbirdcommand.Identity
		CertificateExpiresAt                                                        time.Time
		Consumer                                                                    int64
	}{1, "cleanup-removal-stage", device, r.review.StageCleanupDigest, generation, broker, platform, architecture, scope, r.identity, r.identityExpiresAt.UTC(), consumer})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-stage-cleanup-review/v1\x00"), data...))
	clear(data)
	r.review.Revision = hex.EncodeToString(hash[:])
	return r, nil
}

func removalStageCleanupAudit(ctx context.Context, tx *sql.Tx, actor string, r *NetbirdRemovalStageCleanup, action, result string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "cleanup-removal-stage"}, actor, action, result)
}

func (s *NetbirdRemovalStageCleanupStore) Review(parent context.Context, actor string, scope access.Scope, device, originalID string) (*NetbirdRemovalStageCleanupReview, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(originalID) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 50*time.Second)
	defer cancel()
	tx, err := s.base.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, err
	}
	source, err := s.source(ctx, tx, scope, device, originalID)
	if err != nil {
		return nil, err
	}
	if err = removalStageCleanupAudit(ctx, tx, actor, &NetbirdRemovalStageCleanup{OriginalID: originalID, DeviceID: device, Scope: scope}, "review", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &source.review, nil
}

const removalStageCleanupColumns = `id::text,original_id::text,device_id,tenant_id,site_id,actor,revision,journal_revision,stage_cleanup_digest,stage_cleanup,requested_at,expires_at,coalesce(cancellation_id::text,''),coalesce(cancelled_by,''),cancelled_at,completed_at,released_at,coalesce(released_by,''),coalesce(resolution_id::text,'')`

func scanRemovalStageCleanup(row interface{ Scan(...any) error }) (*NetbirdRemovalStageCleanup, error) {
	var r NetbirdRemovalStageCleanup
	var data []byte
	err := row.Scan(&r.ID, &r.OriginalID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.Revision, &r.JournalRevision, &r.StageCleanupDigest, &data, &r.RequestedAt, &r.ExpiresAt, &r.CancellationID, &r.CancelledBy, &r.CancelledAt, &r.CompletedAt, &r.ReleasedAt, &r.ReleasedBy, &r.ResolutionID)
	if err != nil {
		return nil, err
	}
	r.StageCleanup, err = netbirdcommand.DecodeRemovalStageCleanup(data)
	if err != nil || r.StageCleanup.Original.RequestID != r.OriginalID || r.StageCleanup.JournalRevision != r.JournalRevision {
		return nil, ErrNetbirdOperationConflict
	}
	digest, err := removalStageCleanupDigest(r.StageCleanup)
	if err != nil || digest != r.StageCleanupDigest {
		return nil, ErrNetbirdOperationConflict
	}
	return &r, nil
}

func (s *NetbirdRemovalStageCleanupStore) Request(parent context.Context, actor string, scope access.Scope, device, originalID, id, digest, revision string) (*NetbirdRemovalStageCleanup, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(originalID) || !canonicalRequestID(id) || id == originalID || !netbirdcommand.ValidDigest(digest) || !netbirdcommand.ValidDigest(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 50*time.Second)
	defer cancel()
	tx, err := s.base.begin(ctx, actor, scope, access.AssignSoftware)
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
	r, err := scanRemovalStageCleanup(tx.QueryRowContext(ctx, `SELECT `+removalStageCleanupColumns+` FROM uem_netbird_removal_stage_cleanups WHERE id=$1`, id))
	if err == nil {
		if r.OriginalID != originalID || r.DeviceID != device || r.Scope != scope || r.Actor != actor || r.Revision != revision || r.StageCleanupDigest != digest {
			return nil, ErrNetbirdOperationConflict
		}
		if err = removalStageCleanupAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, err
		}
		return r, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	pending, err := netbirdRequestConflict(ctx, tx, device, id)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrNetbirdOperationConflict
	}
	source, err := s.source(ctx, tx, scope, device, originalID)
	if err != nil {
		return nil, err
	}
	if source.review.Revision != revision || source.review.StageCleanupDigest != digest || id == source.review.StageCleanup.Original.ReleaseID {
		return nil, ErrNetbirdOperationChanged
	}
	data, err := netbirdcommand.EncodeRemovalStageCleanup(source.review.StageCleanup)
	if err != nil {
		return nil, err
	}
	r, err = scanRemovalStageCleanup(tx.QueryRowContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removal_stage_cleanups(id,original_id,device_id,tenant_id,site_id,actor,revision,journal_revision,stage_cleanup_digest,stage_cleanup,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,at,least(at+interval '2 minutes',$11) FROM stamp WHERE at<$11 RETURNING `+removalStageCleanupColumns, id, originalID, device, scope.TenantID, scope.SiteID, actor, revision, source.review.Journal.Revision, digest, string(data), source.identityExpiresAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetbirdOperationChanged
	}
	if err != nil {
		return nil, err
	}
	if err = removalStageCleanupAudit(ctx, tx, actor, r, "request", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

func (s *NetbirdRemovalStageCleanupStore) Read(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRemovalStageCleanup, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.base.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := scanRemovalStageCleanup(tx.QueryRowContext(ctx, `SELECT `+removalStageCleanupColumns+` FROM uem_netbird_removal_stage_cleanups WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = removalStageCleanupAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

// Cancel is available only before durable delivery admission.
func (s *NetbirdRemovalStageCleanupStore) Cancel(parent context.Context, actor string, scope access.Scope, device, id, revision, cancellation string) (*NetbirdRemovalStageCleanup, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) || !canonicalRequestID(cancellation) || cancellation == id || !netbirdcommand.ValidDigest(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.base.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, err
	}
	r, err := scanRemovalStageCleanup(tx.QueryRowContext(ctx, `SELECT `+removalStageCleanupColumns+` FROM uem_netbird_removal_stage_cleanups WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if r.Revision != revision || cancellation == r.OriginalID || cancellation == r.StageCleanup.Original.ReleaseID {
		return nil, ErrNetbirdOperationConflict
	}
	if r.CancelledAt != nil {
		if r.CancellationID != cancellation || r.CancelledBy != actor {
			return nil, ErrNetbirdOperationConflict
		}
		return r, tx.Commit()
	}
	var attempted bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=$1)`, id).Scan(&attempted); err != nil {
		return nil, err
	}
	if attempted || r.CompletedAt != nil || r.ReleasedAt != nil {
		return nil, ErrNetbirdOperationConflict
	}

	r, err = scanRemovalStageCleanup(tx.QueryRowContext(ctx, `UPDATE uem_netbird_removal_stage_cleanups SET cancellation_id=$2,cancelled_by=$3,cancelled_at=clock_timestamp() WHERE id=$1 RETURNING `+removalStageCleanupColumns, id, cancellation, actor))
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrNetbirdOperationConflict
		}
		return nil, err
	}
	if err = removalStageCleanupAudit(ctx, tx, actor, r, "stopped", "cancelled"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}
