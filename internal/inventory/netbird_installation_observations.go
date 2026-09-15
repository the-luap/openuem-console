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
	if r.CompletedAt != nil || r.ReleasedAt != nil {
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
	response := s.installationControl(ctx, query)
	if _, err = recordInstallationObservation(ctx, tx, r, actor, query, response); err != nil {
		return nil, err
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

// All read-only installation controls retain the same strict, source-free evidence.
func recordInstallationObservation(ctx context.Context, tx *sql.Tx, r *NetbirdInstallation, actor string, query netbirdcommand.ControlRequest, response *netbirdcommand.ControlResponse) (time.Time, error) {
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
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_netbird_installation_observations(id,request_id,actor,control_hash,control,response) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb) RETURNING recorded_at`, query.RequestID, r.ID, actor, hash, string(control), data).Scan(&recorded)
	if err != nil {
		return time.Time{}, err
	}
	if completed {
		_, err = tx.ExecContext(ctx, `UPDATE uem_netbird_installations SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL AND released_at IS NULL`, r.ID, recorded)
	}
	return recorded, err
}

func (s *NetbirdInstallationStore) installationControl(ctx context.Context, c netbirdcommand.ControlRequest) *netbirdcommand.ControlResponse {
	if !c.Executable(c.Identity, time.Now()) || ctx.Err() != nil {
		return nil
	}
	call, cancel := context.WithDeadline(ctx, c.ExpiresAt)
	defer cancel()
	p, err := s.control(call, c)
	if err != nil || call.Err() != nil || p == nil || !p.Matches(c) {
		return nil
	}
	return p
}
