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

// Absence requests form a separate durable family. The original uninstall
// and its release evidence remain unchanged by absence delivery.
type NetbirdRemovalAbsenceStore struct {
	base    *NetbirdRemovalStore
	execute NetbirdRemovalAbsenceExecutor
}

func NewNetbirdRemovalAbsenceStore(db *sql.DB, permissions *access.Store, individual bool, control NetbirdOperationControl) (*NetbirdRemovalAbsenceStore, error) {
	base, err := NewNetbirdRemovalStore(db, permissions, individual, control)
	if err != nil {
		return nil, err
	}
	return &NetbirdRemovalAbsenceStore{base: base}, nil
}

type NetbirdRemovalAbsenceReview struct {
	Target                  ManualTarget
	Absence                 netbirdcommand.RemovalAbsence `json:"-"`
	AbsenceDigest, Revision string
	Journal                 netbirdcommand.State
}

type NetbirdRemovalAbsence struct {
	ID, OriginalID, DeviceID, Actor, Revision, JournalRevision, AbsenceDigest string
	Scope                                                                     access.Scope
	Absence                                                                   netbirdcommand.RemovalAbsence `json:"-"`
	RequestedAt, ExpiresAt                                                    time.Time
	CancellationID, CancelledBy                                               string
	CancelledAt, CompletedAt, ReleasedAt                                      *time.Time
	ReleasedBy, ResolutionID                                                  string
}

// Public records explicitly serialize source-free absence evidence without a
// current certificate, broker key, executable command or private native paths.
func (r NetbirdRemovalAbsenceReview) MarshalJSON() ([]byte, error) {
	type public NetbirdRemovalAbsenceReview
	data, err := netbirdcommand.EncodeRemovalAbsence(r.Absence)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		public
		Absence json.RawMessage
	}{public(r), data})
}
func (r NetbirdRemovalAbsence) MarshalJSON() ([]byte, error) {
	type public NetbirdRemovalAbsence
	data, err := netbirdcommand.EncodeRemovalAbsence(r.Absence)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		public
		Absence json.RawMessage
	}{public(r), data})
}

type removalAbsenceSource struct {
	review            NetbirdRemovalAbsenceReview
	identity          netbirdcommand.Identity
	identityExpiresAt time.Time
}

func (removalAbsenceSource) String() string {
	return "NetBird absence source (private data redacted)"
}
func (s removalAbsenceSource) GoString() string           { return s.String() }
func (removalAbsenceSource) MarshalJSON() ([]byte, error) { return nil, ErrNetbirdOperationInvalid }

func removalAbsenceDigest(r netbirdcommand.RemovalAbsence) (string, error) {
	data, err := netbirdcommand.EncodeRemovalAbsence(r)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-absence-descriptor/v1\x00"), data...))
	return hex.EncodeToString(hash[:]), nil
}

func (s *NetbirdRemovalAbsenceStore) source(ctx context.Context, tx *sql.Tx, scope access.Scope, device, originalID string) (*removalAbsenceSource, error) {
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
	r := &removalAbsenceSource{review: NetbirdRemovalAbsenceReview{Target: target}}
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
	expires := at.Add(netbirdcommand.RemovalAbsenceInspectionLifetime)
	if r.identityExpiresAt.Before(expires) {
		expires = r.identityExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	q := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalAbsenceInspectionVersion, Identity: r.identity, RequestID: uuid.NewString(), Kind: "removal-absence-state", RemovalAbsenceOriginal: netbirdcommand.RemovalAbsenceReference{RequestID: original.RequestID, CommandHash: original.CommandHash, Revision: original.Revision, ReleaseID: original.ReleaseID}, IssuedAt: at, ExpiresAt: expires}
	if !q.Executable(r.identity, at) {
		return nil, ErrNetbirdOperationNotReady
	}
	probe, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	p, err := s.base.control(probe, q)
	if err != nil || p == nil || probe.Err() != nil || !p.Matches(q) || p.Outcome != "ok" || p.State.Status != "ready" {
		return nil, ErrNetbirdOperationNotReady
	}
	r.review.Absence, r.review.Journal = p.RemovalAbsence, p.State
	r.review.AbsenceDigest, err = removalAbsenceDigest(p.RemovalAbsence)
	if err != nil {
		return nil, ErrNetbirdOperationChanged
	}
	data, err := json.Marshal(struct {
		Schema                                                                 int
		Operation, Device, Absence, Generation, Broker, Platform, Architecture string
		Scope                                                                  access.Scope
		Identity                                                               netbirdcommand.Identity
		CertificateExpiresAt                                                   time.Time
		Consumer                                                               int64
	}{1, "verify-removal-absence", device, r.review.AbsenceDigest, generation, broker, platform, architecture, scope, r.identity, r.identityExpiresAt.UTC(), consumer})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-absence-review/v1\x00"), data...))
	clear(data)
	r.review.Revision = hex.EncodeToString(hash[:])
	return r, nil
}

func removalAbsenceAudit(ctx context.Context, tx *sql.Tx, actor string, r *NetbirdRemovalAbsence, action, result string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "verify-removal-absence"}, actor, action, result)
}

func (s *NetbirdRemovalAbsenceStore) Review(parent context.Context, actor string, scope access.Scope, device, originalID string) (*NetbirdRemovalAbsenceReview, error) {
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
	if err = removalAbsenceAudit(ctx, tx, actor, &NetbirdRemovalAbsence{OriginalID: originalID, DeviceID: device, Scope: scope}, "review", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &source.review, nil
}

const removalAbsenceColumns = `id::text,original_id::text,device_id,tenant_id,site_id,actor,revision,journal_revision,absence_digest,absence,requested_at,expires_at,coalesce(cancellation_id::text,''),coalesce(cancelled_by,''),cancelled_at,completed_at,released_at,coalesce(released_by,''),coalesce(resolution_id::text,'')`

func scanRemovalAbsence(row interface{ Scan(...any) error }) (*NetbirdRemovalAbsence, error) {
	var r NetbirdRemovalAbsence
	var data []byte
	err := row.Scan(&r.ID, &r.OriginalID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.Revision, &r.JournalRevision, &r.AbsenceDigest, &data, &r.RequestedAt, &r.ExpiresAt, &r.CancellationID, &r.CancelledBy, &r.CancelledAt, &r.CompletedAt, &r.ReleasedAt, &r.ReleasedBy, &r.ResolutionID)
	if err != nil {
		return nil, err
	}
	r.Absence, err = netbirdcommand.DecodeRemovalAbsence(data)
	if err != nil || r.Absence.Original.RequestID != r.OriginalID || r.Absence.JournalRevision != r.JournalRevision {
		return nil, ErrNetbirdOperationConflict
	}
	digest, err := removalAbsenceDigest(r.Absence)
	if err != nil || digest != r.AbsenceDigest {
		return nil, ErrNetbirdOperationConflict
	}
	return &r, nil
}

func (s *NetbirdRemovalAbsenceStore) Request(parent context.Context, actor string, scope access.Scope, device, originalID, id, digest, revision string) (*NetbirdRemovalAbsence, error) {
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
	r, err := scanRemovalAbsence(tx.QueryRowContext(ctx, `SELECT `+removalAbsenceColumns+` FROM uem_netbird_removal_absences WHERE id=$1`, id))
	if err == nil {
		if r.OriginalID != originalID || r.DeviceID != device || r.Scope != scope || r.Actor != actor || r.Revision != revision || r.AbsenceDigest != digest {
			return nil, ErrNetbirdOperationConflict
		}
		if err = removalAbsenceAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
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
	if source.review.Revision != revision || source.review.AbsenceDigest != digest || id == source.review.Absence.Original.ReleaseID {
		return nil, ErrNetbirdOperationChanged
	}
	data, err := netbirdcommand.EncodeRemovalAbsence(source.review.Absence)
	if err != nil {
		return nil, err
	}
	r, err = scanRemovalAbsence(tx.QueryRowContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removal_absences(id,original_id,device_id,tenant_id,site_id,actor,revision,journal_revision,absence_digest,absence,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,at,least(at+interval '2 minutes',$11) FROM stamp WHERE at<$11 RETURNING `+removalAbsenceColumns, id, originalID, device, scope.TenantID, scope.SiteID, actor, revision, source.review.Journal.Revision, digest, string(data), source.identityExpiresAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetbirdOperationChanged
	}
	if err != nil {
		return nil, err
	}
	if err = removalAbsenceAudit(ctx, tx, actor, r, "request", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

func (s *NetbirdRemovalAbsenceStore) Read(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRemovalAbsence, error) {
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
	r, err := scanRemovalAbsence(tx.QueryRowContext(ctx, `SELECT `+removalAbsenceColumns+` FROM uem_netbird_removal_absences WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = removalAbsenceAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

// Cancel is available only before durable delivery admission.
func (s *NetbirdRemovalAbsenceStore) Cancel(parent context.Context, actor string, scope access.Scope, device, id, revision, cancellation string) (*NetbirdRemovalAbsence, error) {
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
	r, err := scanRemovalAbsence(tx.QueryRowContext(ctx, `SELECT `+removalAbsenceColumns+` FROM uem_netbird_removal_absences WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if r.Revision != revision || cancellation == r.OriginalID || cancellation == r.Absence.Original.ReleaseID {
		return nil, ErrNetbirdOperationConflict
	}
	if r.CancelledAt != nil {
		if r.CancellationID != cancellation || r.CancelledBy != actor {
			return nil, ErrNetbirdOperationConflict
		}
		return r, tx.Commit()
	}
	var attempted bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_removal_absence_attempts WHERE request_id=$1)`, id).Scan(&attempted); err != nil {
		return nil, err
	}
	if attempted || r.CompletedAt != nil || r.ReleasedAt != nil {
		return nil, ErrNetbirdOperationConflict
	}

	r, err = scanRemovalAbsence(tx.QueryRowContext(ctx, `UPDATE uem_netbird_removal_absences SET cancellation_id=$2,cancelled_by=$3,cancelled_at=clock_timestamp() WHERE id=$1 RETURNING `+removalAbsenceColumns, id, cancellation, actor))
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrNetbirdOperationConflict
		}
		return nil, err
	}
	if err = removalAbsenceAudit(ctx, tx, actor, r, "stopped", "cancelled"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}
