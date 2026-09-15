package apple

import (
	"context"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func (s *Store) UpdateGroupRemovalDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID, id string) (*UpdateGroupRemoval, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) || !profileRevisionUUID(id) {
		return nil, ErrUpdatePlanGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateGroupRemovalAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	r, err := s.scanUpdateGroupRemoval(tx.QueryRowContext(ctx, `SELECT `+updateGroupRemovalColumns+` FROM mdm_apple_update_group_removals WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4 AND assignment_id=$5`, id, scope.TenantID, scope.SiteID, planID, assignmentID))
	if err != nil {
		return nil, err
	}
	if err = s.validateUpdateGroupRemoval(ctx, tx, r); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.removal.read", id, r.Assignment.Plan.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) UpdateGroupRemovals(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID, before string) ([]UpdateGroupRemoval, string, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) || (before != "" && !profileRevisionUUID(before)) {
		return nil, "", ErrUpdatePlanGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = updateGroupRemovalAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, "", err
	}
	original, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, assignmentID, scope.TenantID, scope.SiteID, planID))
	if err != nil {
		return nil, "", err
	}
	var stamp, cursor any
	if before != "" {
		anchor, err := s.scanUpdateGroupRemoval(tx.QueryRowContext(ctx, `SELECT `+updateGroupRemovalColumns+` FROM mdm_apple_update_group_removals WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4 AND assignment_id=$5`, before, scope.TenantID, scope.SiteID, planID, assignmentID))
		if err != nil {
			return nil, "", err
		}
		if err = s.validateUpdateGroupRemoval(ctx, tx, anchor); err != nil {
			return nil, "", err
		}
		stamp, cursor = anchor.CreatedAt, before
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateGroupRemovalColumns+` FROM mdm_apple_update_group_removals WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND assignment_id=$4 AND ($5::timestamptz IS NULL OR (created_at,id)<($5,$6::uuid)) ORDER BY created_at DESC,id DESC LIMIT 26`, scope.TenantID, scope.SiteID, planID, assignmentID, stamp, cursor)
	if err != nil {
		return nil, "", err
	}
	items := []UpdateGroupRemoval{}
	for rows.Next() {
		r, err := s.scanUpdateGroupRemoval(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		items = append(items, *r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	for i := range items {
		if err = s.validateUpdateGroupRemoval(ctx, tx, &items[i]); err != nil {
			return nil, "", err
		}
	}
	next := ""
	if len(items) > 25 {
		next, items = items[24].ID, items[:25]
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.removal.list", assignmentID, original.Plan.Revision); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
