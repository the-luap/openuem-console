package apple

import (
	"context"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func (s *Store) UpdatePromotionDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, pilotPlanID, pilotAssignmentID, id string) (*UpdatePromotion, error) {
	if !profileRevisionUUID(pilotPlanID) || !profileRevisionUUID(pilotAssignmentID) || !profileRevisionUUID(id) {
		return nil, ErrUpdatePromotion
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	r, err := s.scanUpdatePromotion(tx.QueryRowContext(ctx, `SELECT `+updatePromotionColumns+` FROM mdm_apple_update_promotions WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND pilot_plan_id=$4 AND pilot_assignment_id=$5`, id, scope.TenantID, scope.SiteID, pilotPlanID, pilotAssignmentID))
	if err != nil {
		return nil, err
	}
	if err = s.validateUpdatePromotionSources(ctx, tx, r); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "promotion.read", r.ID, r.DestinationRevision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *Store) UpdatePromotions(ctx context.Context, actor string, permissions *access.Store, scope Scope, pilotPlanID, pilotAssignmentID, before string) ([]UpdatePromotion, string, error) {
	if !profileRevisionUUID(pilotPlanID) || !profileRevisionUUID(pilotAssignmentID) || (before != "" && !profileRevisionUUID(before)) {
		return nil, "", ErrUpdatePromotion
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, "", err
	}
	original, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, pilotAssignmentID, scope.TenantID, scope.SiteID, pilotPlanID))
	if err != nil {
		return nil, "", err
	}
	var at any
	if before != "" {
		anchor, err := s.scanUpdatePromotion(tx.QueryRowContext(ctx, `SELECT `+updatePromotionColumns+` FROM mdm_apple_update_promotions WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND pilot_plan_id=$4 AND pilot_assignment_id=$5`, before, scope.TenantID, scope.SiteID, pilotPlanID, pilotAssignmentID))
		if err != nil {
			return nil, "", err
		}
		if err = s.validateUpdatePromotionSources(ctx, tx, anchor); err != nil {
			return nil, "", err
		}
		at = anchor.CreatedAt
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updatePromotionColumns+` FROM mdm_apple_update_promotions WHERE tenant_id=$1 AND site_id=$2 AND pilot_plan_id=$3 AND pilot_assignment_id=$4 AND ($5::timestamptz IS NULL OR (created_at,id)<($5,$6::uuid)) ORDER BY created_at DESC,id DESC LIMIT 26`, scope.TenantID, scope.SiteID, pilotPlanID, pilotAssignmentID, at, escalationNullableID(before))
	if err != nil {
		return nil, "", err
	}
	items := []UpdatePromotion{}
	for rows.Next() {
		r, err := s.scanUpdatePromotion(rows)
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
		if err = s.validateUpdatePromotionSources(ctx, tx, &items[i]); err != nil {
			return nil, "", err
		}
	}
	next := ""
	if len(items) > 25 {
		next, items = items[24].ID, items[:25]
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "promotion.list", pilotAssignmentID, original.Plan.Revision); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
