package windows

import (
	"context"
	"database/sql"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func (s *Store) readUpdateSchedule(ctx context.Context, tx *sql.Tx, actor string, r *updateStoredSchedule) error {
	if err := s.openUpdateSchedule(r); err != nil {
		return err
	}
	if r.Phase == "activated" {
		rollout, err := scanUpdateRollout(tx.QueryRowContext(ctx, `SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, r.RolloutID, r.Scope.TenantID, r.Scope.SiteID))
		if err != nil {
			return err
		}
		if err := s.openUpdateRollout(rollout); err != nil {
			return err
		}
		if err := s.validateUpdateRolloutSchedule(ctx, tx, rollout); err != nil {
			return err
		}
	}
	return auditUpdateSchedule(ctx, tx, r, actor, "schedule.read")
}

func (s *Store) UpdateScheduleDetails(ctx context.Context, actor string, scope access.Scope, id string) (*UpdateSchedule, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(id) {
		return nil, ErrUpdateSchedule
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	r, err := scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if err := s.readUpdateSchedule(ctx, tx, actor, r); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &r.UpdateSchedule, nil
}

func (s *Store) UpdateSchedules(ctx context.Context, actor string, scope access.Scope, offset, limit int) ([]UpdateSchedule, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, ErrUpdateSchedule
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE tenant_id=$1 AND site_id=$2 ORDER BY created_at DESC,id LIMIT $3 OFFSET $4 FOR SHARE`, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	stored := []*updateStoredSchedule{}
	for rows.Next() {
		r, err := scanUpdateSchedule(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		stored = append(stored, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []UpdateSchedule{}
	for _, r := range stored {
		if err := s.readUpdateSchedule(ctx, tx, actor, r); err != nil {
			return nil, err
		}
		result = append(result, r.UpdateSchedule)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// Cancellation wins only before activation. Already activated work has its own
// per-device lifecycle and cannot be silently recalled by canceling a schedule.
func (s *Store) CancelUpdateSchedule(ctx context.Context, actor string, scope access.Scope, id string, expectedRevision int64) error {
	if s == nil || s.db == nil {
		return ErrStore
	}
	if s.secrets == nil {
		return ErrMasterKey
	}
	if !canonicalInvitationID(id) || expectedRevision < 1 {
		return ErrUpdateSchedule
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return err
	}
	r, err := scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if err := s.openUpdateSchedule(r); err != nil {
		return err
	}
	if r.Revision != expectedRevision {
		return ErrUpdateScheduleConflict
	}
	if r.Phase != "scheduled" && r.Phase != "waiting" {
		return ErrCSPAlreadySent
	}
	r.Phase, r.Reason = "canceled", "canceled_by_operator"
	r.Revision++
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.UpdatedAt); err != nil {
		return err
	}
	r.CompletedAt = &r.UpdatedAt
	if err := s.writeUpdateSchedule(ctx, tx, r, actor); err != nil {
		return err
	}
	return tx.Commit()
}
