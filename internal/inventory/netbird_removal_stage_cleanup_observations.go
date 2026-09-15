package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// ObserveStageCleanup recovers retained receipts using current individual
// authority. It sends only a version-two receipt query, never a native removal,
// withdrawal or release. Missing and uncertain evidence cannot clear the barrier.
func (s *NetbirdRemovalStageCleanupStore) ObserveStageCleanup(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdRemovalStageCleanupDelivery, error) {
	if parent == nil || s.base.control == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.stageCleanupRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readRemovalStageCleanupDelivery(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		return nil, err
	}
	if r.CompletedAt != nil || r.ReleasedAt != nil {
		if err = removalStageCleanupAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	// StageCleanup authenticates the current recipient without requiring the original
	// native installed state or certificate.
	// Those could have changed after already-authorized work completed.
	operations := &NetbirdOperationStore{db: s.base.db, permissions: s.base.permissions, individual: s.base.individual}
	v, _, err := operations.resolutionTarget(ctx, tx, &NetbirdOperation{ID: id, DeviceID: device, Scope: scope, Individual: true, Revision: r.Revision, Operation: "cleanup-removal-stage", CommandHash: d.CommandHash})
	if err != nil {
		return nil, err
	}
	query := netbirdRecoveryControl(ctx, v, "receipt", uuid.NewString())
	// Use the database clock for a control whose timestamp is retained beside
	// database evidence. Keep the earlier certificate/caller limit from above.
	var issued time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&issued); err != nil {
		return nil, err
	}
	query.IssuedAt = issued.UTC()
	if expires := query.IssuedAt.Add(2 * time.Second); expires.Before(query.ExpiresAt) {
		query.ExpiresAt = expires
	}
	if !query.Executable(query.Identity, time.Now()) {
		return nil, ErrNetbirdOperationNotReady
	}
	response := s.base.removalControl(ctx, query)
	if _, err = recordStageCleanupObservation(ctx, tx, r, actor, query, response); err != nil {
		return nil, err
	}
	if err = removalStageCleanupStageAudit(ctx, tx, r, actor, "resolution.observe", "receipt"); err != nil {
		return nil, err
	}
	d, err = readRemovalStageCleanupDelivery(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}

// All read-only removal controls retain the same strict, source-free evidence.
func recordStageCleanupObservation(ctx context.Context, tx *sql.Tx, r *NetbirdRemovalStageCleanup, actor string, query netbirdcommand.ControlRequest, response *netbirdcommand.ControlResponse) (time.Time, error) {
	control, err := netbirdcommand.EncodeControl(query)
	if err != nil {
		return time.Time{}, err
	}
	hash, err := query.Digest()
	if err != nil {
		return time.Time{}, err
	}
	var data any
	completed := false
	if response != nil {
		encoded, err := netbirdcommand.EncodeControlResponse(query, *response)
		if err != nil {
			return time.Time{}, ErrNetbirdOperationConflict
		}
		data = string(encoded)
		completed = response.Outcome == "ok" && response.Receipt.Status == "completed" && response.ReleaseID == ""
	}
	var recorded time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_netbird_removal_stage_cleanup_observations(id,request_id,actor,control_hash,control,response) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb) RETURNING recorded_at`, query.RequestID, r.ID, actor, hash, string(control), data).Scan(&recorded)
	if err != nil {
		return time.Time{}, err
	}
	if completed {
		_, err = tx.ExecContext(ctx, `UPDATE uem_netbird_removal_stage_cleanups SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL AND released_at IS NULL`, r.ID, recorded)
	}
	return recorded, err
}
