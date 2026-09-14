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

// ObserveInstallation recovers retained receipts using current individual
// authority. It sends only a version-two receipt query, never an installer,
// withdrawal or release. Missing and uncertain evidence cannot clear the barrier.
func (s *NetbirdInstallationStore) ObserveInstallation(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdInstallationDelivery, error) {
	if parent == nil || s.control == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.installationRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readInstallationDelivery(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		return nil, err
	}
	if r.CompletedAt != nil {
		if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	// Recovery authenticates the current recipient but does not require a still
	// approved source, unchanged installation report or original certificate.
	// Those could have changed after already-authorized work completed.
	operations := &NetbirdOperationStore{db: s.packages.db, permissions: s.packages.permissions, individual: s.individual}
	v, _, err := operations.resolutionTarget(ctx, tx, &NetbirdOperation{ID: id, DeviceID: device, Scope: scope, Individual: true, Revision: r.Revision, Operation: "install", CommandHash: d.CommandHash})
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
	control, err := netbirdcommand.EncodeControl(query)
	if err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	hash, err := query.Digest()
	if err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	call, finish := context.WithDeadline(ctx, query.ExpiresAt)
	response, callErr := s.control(call, query)
	valid := callErr == nil && call.Err() == nil && response != nil && response.Matches(query)
	finish()
	var data any
	completed := false
	if valid {
		encoded, err := netbirdcommand.EncodeControlResponse(query, *response)
		if err != nil {
			return nil, ErrNetbirdOperationConflict
		}
		data = string(encoded)
		completed = response.Outcome == "ok" && response.Receipt.Status == "completed" && response.ReleaseID == ""
	}
	var recorded time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_netbird_installation_observations(id,request_id,actor,control_hash,control,response) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb) RETURNING recorded_at`, query.RequestID, id, actor, hash, string(control), data).Scan(&recorded)
	if err != nil {
		return nil, err
	}
	if completed {
		if _, err = tx.ExecContext(ctx, `UPDATE uem_netbird_installations SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL`, id, recorded); err != nil {
			return nil, err
		}
	}
	if err = installationStageAudit(ctx, tx, r, actor, "resolution.observe", "receipt"); err != nil {
		return nil, err
	}
	d, err = readInstallationDelivery(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}
