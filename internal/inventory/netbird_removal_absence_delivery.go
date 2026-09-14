package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// NetbirdRemovalAbsenceExecutor sends one admitted version-six command. It must
// bound local waiting and return only a correlated receipt, without redelivery.
type NetbirdRemovalAbsenceExecutor func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error)

func NewNetbirdRemovalAbsenceDeliveryStore(db *sql.DB, permissions *access.Store, individual bool, control NetbirdOperationControl, execute NetbirdRemovalAbsenceExecutor) (*NetbirdRemovalAbsenceStore, error) {
	if execute == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	s, err := NewNetbirdRemovalAbsenceStore(db, permissions, individual, control)
	if err != nil {
		return nil, err
	}
	s.execute = execute
	return s, nil
}

// OriginalOutcome retains the first absence delivery result, independently of
// the original uninstall referenced by the request. Public history has no
// certificate or executable envelope. Pending is not retry authority.
type NetbirdRemovalAbsenceDelivery struct {
	RequestID, CommandHash, Outcome, OriginalOutcome string
	IssuedAt, ExpiresAt                              time.Time
	RecordedAt, CompletedAt, ReleasedAt              *time.Time
	ReleasedBy, ResolutionID                         string
	Receipt                                          *netbirdcommand.Receipt
	ObservationID, ObservedBy, ObservedOutcome       string
	ObservedAt                                       *time.Time
}

func readRemovalAbsenceDelivery(ctx context.Context, tx *sql.Tx, id string) (*NetbirdRemovalAbsenceDelivery, error) {
	var d NetbirdRemovalAbsenceDelivery
	var receipt []byte
	r, err := scanRemovalAbsence(tx.QueryRowContext(ctx, `SELECT `+removalAbsenceColumns+` FROM uem_netbird_removal_absences WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	c := netbirdcommand.Command{Identity: netbirdcommand.Identity{DeviceID: r.DeviceID, TenantID: int64(r.Scope.TenantID), SiteID: int64(r.Scope.SiteID), Individual: true}, RequestID: r.ID, Revision: r.Revision, Operation: "verify-removal-absence", RemovalAbsence: r.Absence}
	err = tx.QueryRowContext(ctx, `SELECT a.request_id::text,a.command_hash,a.issued_at,a.expires_at,a.wire_version,a.certificate_hash,
 CASE WHEN i.completed_at IS NOT NULL THEN 'completed' WHEN i.released_at IS NOT NULL THEN 'released' ELSE coalesce(r.outcome,'pending') END,coalesce(r.outcome,'pending'),r.recorded_at,i.completed_at,i.released_at,coalesce(i.released_by,''),coalesce(i.resolution_id::text,''),
 coalesce((SELECT o.response->'receipt' FROM uem_netbird_removal_absence_observations o WHERE o.request_id=i.id AND o.recorded_at=i.completed_at AND o.response->'receipt'->>'status'='completed' LIMIT 1),r.receipt),
 coalesce(o.id::text,''),coalesce(o.actor,''),coalesce(CASE WHEN o.response->>'outcome'='ok' THEN o.response->'receipt'->>'status' ELSE coalesce(o.response->>'outcome','unavailable') END,''),o.recorded_at
 FROM uem_netbird_removal_absence_attempts a JOIN uem_netbird_removal_absences i ON i.id=a.request_id LEFT JOIN uem_netbird_removal_absence_results r USING(request_id)
 LEFT JOIN LATERAL(SELECT * FROM uem_netbird_removal_absence_observations WHERE request_id=a.request_id ORDER BY recorded_at DESC,id DESC LIMIT 1) o ON true
 WHERE a.request_id=$1`, id).Scan(&d.RequestID, &d.CommandHash, &d.IssuedAt, &d.ExpiresAt, &c.Version, &c.CertificateHash, &d.Outcome, &d.OriginalOutcome, &d.RecordedAt, &d.CompletedAt, &d.ReleasedAt, &d.ReleasedBy, &d.ResolutionID, &receipt, &d.ObservationID, &d.ObservedBy, &d.ObservedOutcome, &d.ObservedAt)
	if err != nil {
		return nil, err
	}
	c.IssuedAt, c.ExpiresAt = d.IssuedAt, d.ExpiresAt
	hash, err := c.Digest()
	if err != nil || hash != d.CommandHash {
		return nil, ErrNetbirdOperationConflict
	}
	if len(receipt) > 0 {
		r, err := netbirdcommand.DecodeReceipt(receipt)
		if err != nil || !r.Matches(c) {
			return nil, ErrNetbirdOperationConflict
		}
		d.Receipt = &r
	}
	if d.ObservedAt == nil {
		d.ObservedOutcome = ""
	}
	return &d, nil
}

func removalAbsenceStageAudit(ctx context.Context, tx *sql.Tx, r *NetbirdRemovalAbsence, actor, action, stage string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "verify-removal-absence/" + stage}, actor, action, "recorded")
}

func (s *NetbirdRemovalAbsenceStore) absenceRecord(ctx context.Context, actor string, scope access.Scope, device, id, revision string, capability access.Capability) (*sql.Tx, *NetbirdRemovalAbsence, error) {
	if !canonicalRequestID(device) || !canonicalRequestID(id) || !netbirdcommand.ValidDigest(revision) {
		return nil, nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.base.begin(ctx, actor, scope, capability)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*sql.Tx, *NetbirdRemovalAbsence, error) { tx.Rollback(); return nil, nil, err }
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return fail(err)
	}
	r, err := scanRemovalAbsence(tx.QueryRowContext(ctx, `SELECT `+removalAbsenceColumns+` FROM uem_netbird_removal_absences WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return fail(err)
	}
	if r.Revision != revision {
		return fail(ErrNetbirdOperationConflict)
	}
	return tx, r, nil
}

// Verify rechecks the exact absence review once. Its attempt and audit commit
// before direct delivery; no database transaction spans the read-only check.
func (s *NetbirdRemovalAbsenceStore) Verify(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdRemovalAbsenceDelivery, error) {
	if parent == nil || s.execute == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	r, d, c, err := s.admitAbsence(parent, actor, scope, device, id, revision)
	if err != nil || c == nil {
		return d, err
	}
	call, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
	var receipt *netbirdcommand.Receipt
	if call.Err() == nil {
		receipt, err = s.execute(call, *c)
	}
	if err != nil || call.Err() != nil || receipt == nil || !receipt.Matches(*c) {
		receipt = nil
	}
	record, stop := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer stop()
	return s.finishAbsence(record, r, receipt)
}

func (s *NetbirdRemovalAbsenceStore) admitAbsence(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdRemovalAbsence, *NetbirdRemovalAbsenceDelivery, *netbirdcommand.Command, error) {
	ctx, cancel := context.WithTimeout(parent, 50*time.Second)
	defer cancel()
	tx, r, err := s.absenceRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	if r.Actor != actor {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	d, err := readRemovalAbsenceDelivery(ctx, tx, id)
	if err == nil {
		if err = removalAbsenceAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, nil, nil, err
		}
		return r, d, nil, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, err
	}
	stopped, err := readAbsenceDispatchStop(ctx, tx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if stopped != nil {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	if r.CancelledAt != nil || r.CompletedAt != nil || r.ReleasedAt != nil || !time.Now().Before(r.ExpiresAt) {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	source, err := s.source(ctx, tx, scope, device, r.OriginalID)
	if err != nil {
		return nil, nil, nil, err
	}
	if source.review.Revision != revision || source.review.Journal.Revision != r.JournalRevision || source.review.Absence != r.Absence || source.review.AbsenceDigest != r.AbsenceDigest {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	var issued time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&issued); err != nil {
		return nil, nil, nil, err
	}
	issued = issued.UTC()
	expires := issued.Add(netbirdcommand.RemovalAbsenceLifetime)
	if source.identityExpiresAt.Before(expires) {
		expires = source.identityExpiresAt.UTC()
	}
	c := netbirdcommand.Command{Version: netbirdcommand.RemovalAbsenceVersion, Identity: source.identity, RequestID: id, Revision: revision, Operation: "verify-removal-absence", IssuedAt: issued, ExpiresAt: expires, RemovalAbsence: source.review.Absence}
	digest, err := c.Digest()
	if err != nil || !c.Executable(source.identity, time.Now()) || issued.Before(r.RequestedAt) {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_removal_absence_attempts(request_id,wire_version,certificate_hash,command_hash,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, id, c.Version, c.CertificateHash, digest, c.IssuedAt, c.ExpiresAt)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = removalAbsenceStageAudit(ctx, tx, r, actor, "attempt", "deliver"); err != nil {
		return nil, nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	return r, nil, &c, nil
}

func (s *NetbirdRemovalAbsenceStore) finishAbsence(ctx context.Context, r *NetbirdRemovalAbsence, receipt *netbirdcommand.Receipt) (*NetbirdRemovalAbsenceDelivery, error) {
	tx, err := s.base.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM uem_netbird_removal_absences WHERE id=$1 FOR UPDATE`, r.ID).Scan(&locked); err != nil {
		return nil, err
	}
	outcome := "unconfirmed"
	var data any
	if receipt != nil {
		wire, err := netbirdcommand.EncodeReceipt(*receipt)
		if err != nil {
			return nil, ErrNetbirdOperationConflict
		}
		data = string(wire)
		if receipt.Status == "completed" {
			outcome = "completed"
		}
	}
	var recorded time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_netbird_removal_absence_results(request_id,outcome,receipt) VALUES($1,$2,$3::jsonb) RETURNING recorded_at`, r.ID, outcome, data).Scan(&recorded)
	if err != nil {
		return nil, err
	}
	if outcome == "completed" {
		if _, err = tx.ExecContext(ctx, `UPDATE uem_netbird_removal_absences SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL AND released_at IS NULL`, r.ID, recorded); err != nil {
			return nil, err
		}
	}
	if err = removalAbsenceStageAudit(ctx, tx, r, r.Actor, "attempt", "result-"+outcome); err != nil {
		return nil, err
	}
	d, err := readRemovalAbsenceDelivery(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *NetbirdRemovalAbsenceStore) ReadDelivery(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRemovalAbsenceDelivery, error) {
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
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d, err := readRemovalAbsenceDelivery(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = removalAbsenceAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}
