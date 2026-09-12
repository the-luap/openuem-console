package apple

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func sameScheduledUpdatePlan(a, b UpdatePlan) bool {
	return a.ID == b.ID && a.Scope == b.Scope && a.Revision == b.Revision && a.Definition == b.Definition && a.Actor == b.Actor && a.CreatedAt.Equal(b.CreatedAt)
}
func matchesUpdateScheduleAssignment(r *updateStoredSchedule, receipt *UpdatePlanGroupAssignment) bool {
	targets := make([]UpdatePlanGroupSelection, len(receipt.Commands))
	for i, command := range receipt.Commands {
		targets[i] = command.Selection
	}
	return r.Phase == "activated" && r.AssignmentID == receipt.ID && r.Scope == receipt.Scope && r.activationKey == receipt.RequestKey && sameScheduledUpdatePlan(r.Plan, receipt.Plan) && r.Group == receipt.Group && r.Actor == receipt.Actor && r.ActorRevision == receipt.ActorRevision && slices.Equal(r.Targets, targets) && r.CompletedAt != nil && !receipt.CreatedAt.Before(r.CreatedAt) && !receipt.CreatedAt.Before(r.NotBefore) && !receipt.CreatedAt.After(*r.CompletedAt) && r.CompletedAt.Before(r.ExpiresAt)
}
func (s *Store) validateUpdateScheduleAssignment(ctx context.Context, tx *sql.Tx, r *updateStoredSchedule) error {
	if r.Phase != "activated" {
		return nil
	}
	receipt, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, r.AssignmentID, r.Scope.TenantID, r.Scope.SiteID))
	if err != nil {
		return err
	}
	if !matchesUpdateScheduleAssignment(r, receipt) {
		return ErrUpdateScheduleIntegrity
	}
	return nil
}

func (s *Store) UpdateScheduleDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, id string) (*UpdateSchedule, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(id) {
		return nil, ErrUpdateSchedule
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return nil, err
	}
	r, err := s.scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, id, scope.TenantID, scope.SiteID, planID))
	if err != nil {
		return nil, err
	}
	if err = s.validateUpdateScheduleAssignment(ctx, tx, r); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "schedule.read", r.ID, r.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &r.UpdateSchedule, nil
}

// UpdateSchedules uses bounded keyset history, including terminal records and
// original sources after a later plan revision or archive.
func (s *Store) UpdateSchedules(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, before string) ([]UpdateSchedule, string, error) {
	if !profileRevisionUUID(planID) || (before != "" && !profileRevisionUUID(before)) {
		return nil, "", ErrUpdateSchedule
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return nil, "", err
	}
	var stamp, cursor any
	if before != "" {
		var at time.Time
		if err = tx.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_update_schedules WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND id=$4`, scope.TenantID, scope.SiteID, planID, before).Scan(&at); err != nil {
			return nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5::uuid)) ORDER BY created_at DESC,id DESC LIMIT 26`, scope.TenantID, scope.SiteID, planID, stamp, cursor)
	if err != nil {
		return nil, "", err
	}
	stored := []*updateStoredSchedule{}
	for rows.Next() {
		r, err := s.scanUpdateSchedule(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		stored = append(stored, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(stored) > 25 {
		next = stored[24].ID
		stored = stored[:25]
	}
	items := make([]UpdateSchedule, 0, len(stored))
	for _, r := range stored {
		if err = s.validateUpdateScheduleAssignment(ctx, tx, r); err != nil {
			return nil, "", err
		}
		items = append(items, r.UpdateSchedule)
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "schedule.list", planID, 0); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}

func (s *Store) CancelUpdateSchedule(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, id string, expectedRevision int) error {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(id) || expectedRevision < 1 || expectedRevision >= 1000000 {
		return ErrUpdateSchedule
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return err
	}
	r, err := s.scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4 FOR UPDATE`, id, scope.TenantID, scope.SiteID, planID))
	if err != nil {
		return err
	}
	if r.Revision != expectedRevision || (r.Phase != "scheduled" && r.Phase != "waiting") {
		return ErrConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if now.Before(r.UpdatedAt) {
		return ErrUpdateScheduleIntegrity
	}
	r.Phase, r.Reason, r.UpdatedAt = "canceled", "canceled_by_operator", now
	r.Revision++
	r.CompletedAt = &r.UpdatedAt
	if err = s.writeUpdateSchedule(ctx, tx, r, actor); err != nil {
		return err
	}
	return tx.Commit()
}
