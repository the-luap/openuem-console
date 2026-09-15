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

// Recovery requests form a separate durable family. The original uninstall
// and its release evidence remain unchanged by recovery delivery.
type NetbirdRemovalRecoveryStore struct {
	base    *NetbirdRemovalStore
	execute NetbirdRemovalRecoveryExecutor
}

func NewNetbirdRemovalRecoveryStore(db *sql.DB, permissions *access.Store, individual bool, control NetbirdOperationControl) (*NetbirdRemovalRecoveryStore, error) {
	base, err := NewNetbirdRemovalStore(db, permissions, individual, control)
	if err != nil {
		return nil, err
	}
	return &NetbirdRemovalRecoveryStore{base: base}, nil
}

type NetbirdRemovalRecoveryReview struct {
	Target                   ManualTarget
	Recovery                 netbirdcommand.RemovalRecovery `json:"-"`
	RecoveryDigest, Revision string
	Journal                  netbirdcommand.State
}

type NetbirdRemovalRecovery struct {
	ID, OriginalID, DeviceID, Actor, Revision, JournalRevision, RecoveryDigest string
	Scope                                                                      access.Scope
	Recovery                                                                   netbirdcommand.RemovalRecovery `json:"-"`
	RequestedAt, ExpiresAt                                                     time.Time
	CancellationID, CancelledBy                                                string
	CancelledAt, CompletedAt, ReleasedAt                                       *time.Time
	ReleasedBy, ResolutionID                                                   string
}

// Public records explicitly serialize source-free recovery evidence without a
// current certificate, broker key, executable command or private native paths.
func (r NetbirdRemovalRecoveryReview) MarshalJSON() ([]byte, error) {
	type public NetbirdRemovalRecoveryReview
	data, err := netbirdcommand.EncodeRemovalRecovery(r.Recovery)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		public
		Recovery json.RawMessage
	}{public(r), data})
}
func (r NetbirdRemovalRecovery) MarshalJSON() ([]byte, error) {
	type public NetbirdRemovalRecovery
	data, err := netbirdcommand.EncodeRemovalRecovery(r.Recovery)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		public
		Recovery json.RawMessage
	}{public(r), data})
}

type removalRecoverySource struct {
	review            NetbirdRemovalRecoveryReview
	identity          netbirdcommand.Identity
	identityExpiresAt time.Time
}

func (removalRecoverySource) String() string {
	return "NetBird recovery source (private data redacted)"
}
func (s removalRecoverySource) GoString() string           { return s.String() }
func (removalRecoverySource) MarshalJSON() ([]byte, error) { return nil, ErrNetbirdOperationInvalid }

func removalRecoveryDigest(r netbirdcommand.RemovalRecovery) (string, error) {
	data, err := netbirdcommand.EncodeRemovalRecovery(r)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-recovery-descriptor/v1\x00"), data...))
	return hex.EncodeToString(hash[:]), nil
}

// Retained release status can also mean withdrawal. Reconstruct the exact owned
// proof and original command before accepting only an unconfirmed uninstall.
func readRemovalRecoveryOriginal(ctx context.Context, tx *sql.Tx, scope access.Scope, device, id string) (netbirdcommand.RemovalRecoveryReference, error) {
	r, err := scanRemoval(tx.QueryRowContext(ctx, `SELECT `+removalColumns+` FROM uem_netbird_removals WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return netbirdcommand.RemovalRecoveryReference{}, ErrNotFound
	}
	if err != nil {
		return netbirdcommand.RemovalRecoveryReference{}, err
	}
	if r.CancelledAt != nil || r.CompletedAt != nil || r.ReleasedAt == nil || !canonicalRequestID(r.ResolutionID) {
		return netbirdcommand.RemovalRecoveryReference{}, ErrNetbirdOperationConflict
	}
	var control, response []byte
	// The original attempt stores minimal immutable wire metadata. Reconstruct
	// its complete source-free command and verify its retained hash.
	c := netbirdcommand.Command{Identity: netbirdcommand.Identity{DeviceID: device, TenantID: int64(scope.TenantID), SiteID: int64(scope.SiteID), Individual: true}, RequestID: id, Revision: r.Revision, Operation: "uninstall", Removal: r.Descriptor}
	var commandHash, controlHash, releaseID, actor string
	var recorded time.Time
	var ownedRelease bool
	err = tx.QueryRowContext(ctx, `SELECT a.wire_version,a.certificate_hash,a.issued_at,a.expires_at,a.command_hash,
 CASE WHEN p.attempt_id IS NOT NULL THEN c.control ELSE o.control END,
 CASE WHEN p.attempt_id IS NOT NULL THEN c.control_hash ELSE o.control_hash END,
 CASE WHEN p.attempt_id IS NOT NULL THEN v.response ELSE o.response END,
 p.resolution_id::text,p.actor,p.recorded_at,
 EXISTS(SELECT 1 FROM uem_netbird_removal_controls z WHERE z.request_id=p.request_id AND z.resolution_id=p.resolution_id AND z.kind='release' AND z.created_at<=coalesce(v.recorded_at,o.recorded_at))
 FROM uem_netbird_removal_release_proofs p JOIN uem_netbird_removal_attempts a USING(request_id)
 LEFT JOIN uem_netbird_removal_controls c ON c.id=p.attempt_id
 LEFT JOIN uem_netbird_removal_control_results v ON v.attempt_id=p.attempt_id
 LEFT JOIN uem_netbird_removal_observations o ON o.id=p.observation_id
 WHERE p.request_id=$1 AND p.resolution_id=$2`, id, r.ResolutionID).Scan(&c.Version, &c.CertificateHash, &c.IssuedAt, &c.ExpiresAt, &commandHash, &control, &controlHash, &response, &releaseID, &actor, &recorded, &ownedRelease)
	if errors.Is(err, sql.ErrNoRows) {
		return netbirdcommand.RemovalRecoveryReference{}, ErrNetbirdOperationConflict
	}
	if err != nil {
		return netbirdcommand.RemovalRecoveryReference{}, err
	}
	fail := func() (netbirdcommand.RemovalRecoveryReference, error) {
		return netbirdcommand.RemovalRecoveryReference{}, ErrNetbirdOperationConflict
	}
	if c.Version != netbirdcommand.RemovalVersion || !c.Valid() {
		return fail()
	}
	hash, err := c.Digest()
	if err != nil || hash != commandHash {
		return fail()
	}
	q, err := netbirdcommand.DecodeControl(control)
	if err != nil || (q.Kind != "release" && q.Kind != "receipt") || q.ReferenceID != id || q.CommandHash != hash || !q.Individual || q.DeviceID != device || q.TenantID != c.TenantID || q.SiteID != c.SiteID {
		return fail()
	}
	qh, err := q.Digest()
	if err != nil || qh != controlHash {
		return fail()
	}
	p, err := netbirdcommand.DecodeControlResponse(response, q)
	if err != nil || !ownedRelease || p.Outcome != "ok" || p.Receipt.Status != "unconfirmed" || !p.Receipt.Matches(c) || p.ReleaseID != releaseID || releaseID != r.ResolutionID || actor != r.ReleasedBy || !recorded.Equal(*r.ReleasedAt) {
		return fail()
	}
	original := netbirdcommand.RemovalRecoveryReference{RequestID: id, CommandHash: hash, Revision: r.Revision, ReleaseID: releaseID, Removal: r.Descriptor}
	if !original.Valid() {
		return fail()
	}
	return original, nil
}

func (s *NetbirdRemovalRecoveryStore) source(ctx context.Context, tx *sql.Tx, scope access.Scope, device, originalID string) (*removalRecoverySource, error) {
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
	r := &removalRecoverySource{review: NetbirdRemovalRecoveryReview{Target: target}}
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
	expires := at.Add(netbirdcommand.RemovalRecoveryInspectionLifetime)
	if r.identityExpiresAt.Before(expires) {
		expires = r.identityExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	q := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalRecoveryInspectionVersion, Identity: r.identity, RequestID: uuid.NewString(), Kind: "removal-recovery-state", RemovalRecoveryOriginal: original, IssuedAt: at, ExpiresAt: expires}
	if !q.Executable(r.identity, at) {
		return nil, ErrNetbirdOperationNotReady
	}
	probe, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	p, err := s.base.control(probe, q)
	if err != nil || p == nil || probe.Err() != nil || !p.Matches(q) || p.Outcome != "ok" || p.State.Status != "ready" {
		return nil, ErrNetbirdOperationNotReady
	}
	r.review.Recovery, r.review.Journal = p.RemovalRecovery, p.State
	r.review.RecoveryDigest, err = removalRecoveryDigest(p.RemovalRecovery)
	if err != nil {
		return nil, ErrNetbirdOperationChanged
	}
	data, err := json.Marshal(struct {
		Schema                                                                  int
		Operation, Device, Recovery, Generation, Broker, Platform, Architecture string
		Scope                                                                   access.Scope
		Identity                                                                netbirdcommand.Identity
		CertificateExpiresAt                                                    time.Time
		Consumer                                                                int64
	}{1, "recover-removal", device, r.review.RecoveryDigest, generation, broker, platform, architecture, scope, r.identity, r.identityExpiresAt.UTC(), consumer})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-recovery-review/v1\x00"), data...))
	clear(data)
	r.review.Revision = hex.EncodeToString(hash[:])
	return r, nil
}

func removalRecoveryAudit(ctx context.Context, tx *sql.Tx, actor string, r *NetbirdRemovalRecovery, action, result string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "recover-removal"}, actor, action, result)
}

func (s *NetbirdRemovalRecoveryStore) Review(parent context.Context, actor string, scope access.Scope, device, originalID string) (*NetbirdRemovalRecoveryReview, error) {
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
	if err = removalRecoveryAudit(ctx, tx, actor, &NetbirdRemovalRecovery{OriginalID: originalID, DeviceID: device, Scope: scope}, "review", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &source.review, nil
}

const removalRecoveryColumns = `id::text,original_id::text,device_id,tenant_id,site_id,actor,revision,journal_revision,recovery_digest,recovery,requested_at,expires_at,coalesce(cancellation_id::text,''),coalesce(cancelled_by,''),cancelled_at,completed_at,released_at,coalesce(released_by,''),coalesce(resolution_id::text,'')`

func scanRemovalRecovery(row interface{ Scan(...any) error }) (*NetbirdRemovalRecovery, error) {
	var r NetbirdRemovalRecovery
	var data []byte
	err := row.Scan(&r.ID, &r.OriginalID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.Revision, &r.JournalRevision, &r.RecoveryDigest, &data, &r.RequestedAt, &r.ExpiresAt, &r.CancellationID, &r.CancelledBy, &r.CancelledAt, &r.CompletedAt, &r.ReleasedAt, &r.ReleasedBy, &r.ResolutionID)
	if err != nil {
		return nil, err
	}
	r.Recovery, err = netbirdcommand.DecodeRemovalRecovery(data)
	if err != nil || r.Recovery.Original.RequestID != r.OriginalID || r.Recovery.JournalRevision != r.JournalRevision {
		return nil, ErrNetbirdOperationConflict
	}
	digest, err := removalRecoveryDigest(r.Recovery)
	if err != nil || digest != r.RecoveryDigest {
		return nil, ErrNetbirdOperationConflict
	}
	return &r, nil
}

func (s *NetbirdRemovalRecoveryStore) Request(parent context.Context, actor string, scope access.Scope, device, originalID, id, digest, revision string) (*NetbirdRemovalRecovery, error) {
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
	r, err := scanRemovalRecovery(tx.QueryRowContext(ctx, `SELECT `+removalRecoveryColumns+` FROM uem_netbird_removal_recoveries WHERE id=$1`, id))
	if err == nil {
		if r.OriginalID != originalID || r.DeviceID != device || r.Scope != scope || r.Actor != actor || r.Revision != revision || r.RecoveryDigest != digest {
			return nil, ErrNetbirdOperationConflict
		}
		if err = removalRecoveryAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
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
	if source.review.Revision != revision || source.review.RecoveryDigest != digest || id == source.review.Recovery.Original.ReleaseID {
		return nil, ErrNetbirdOperationChanged
	}
	data, err := netbirdcommand.EncodeRemovalRecovery(source.review.Recovery)
	if err != nil {
		return nil, err
	}
	r, err = scanRemovalRecovery(tx.QueryRowContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removal_recoveries(id,original_id,device_id,tenant_id,site_id,actor,revision,journal_revision,recovery_digest,recovery,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,at,least(at+interval '10 minutes',$11) FROM stamp WHERE at<$11 RETURNING `+removalRecoveryColumns, id, originalID, device, scope.TenantID, scope.SiteID, actor, revision, source.review.Journal.Revision, digest, string(data), source.identityExpiresAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetbirdOperationChanged
	}
	if err != nil {
		return nil, err
	}
	if err = removalRecoveryAudit(ctx, tx, actor, r, "request", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

func (s *NetbirdRemovalRecoveryStore) Read(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRemovalRecovery, error) {
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
	r, err := scanRemovalRecovery(tx.QueryRowContext(ctx, `SELECT `+removalRecoveryColumns+` FROM uem_netbird_removal_recoveries WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = removalRecoveryAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

// Cancel is available only before durable delivery admission.
func (s *NetbirdRemovalRecoveryStore) Cancel(parent context.Context, actor string, scope access.Scope, device, id, revision, cancellation string) (*NetbirdRemovalRecovery, error) {
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
	r, err := scanRemovalRecovery(tx.QueryRowContext(ctx, `SELECT `+removalRecoveryColumns+` FROM uem_netbird_removal_recoveries WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if r.Revision != revision || cancellation == r.OriginalID || cancellation == r.Recovery.Original.ReleaseID {
		return nil, ErrNetbirdOperationConflict
	}
	if r.CancelledAt != nil {
		if r.CancellationID != cancellation || r.CancelledBy != actor {
			return nil, ErrNetbirdOperationConflict
		}
		return r, tx.Commit()
	}
	var attempted bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_removal_recovery_attempts WHERE request_id=$1)`, id).Scan(&attempted); err != nil {
		return nil, err
	}
	if attempted || r.CompletedAt != nil || r.ReleasedAt != nil {
		return nil, ErrNetbirdOperationConflict
	}

	r, err = scanRemovalRecovery(tx.QueryRowContext(ctx, `UPDATE uem_netbird_removal_recoveries SET cancellation_id=$2,cancelled_by=$3,cancelled_at=clock_timestamp() WHERE id=$1 RETURNING `+removalRecoveryColumns, id, cancellation, actor))
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrNetbirdOperationConflict
		}
		return nil, err
	}
	if err = removalRecoveryAudit(ctx, tx, actor, r, "stopped", "cancelled"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}
