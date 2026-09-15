package apple

import (
	"context"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func (s *Store) UpdateEscalationDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID string) (*UpdateEscalation, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) {
		return nil, ErrUpdateEscalation
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
	r, err := s.escalationForAssignment(ctx, tx, scope, planID, assignmentID, " FOR SHARE")
	if err != nil {
		return nil, err
	}
	if err = auditUpdateEscalation(ctx, tx, scope, actor, "read", r.ID, r.StateRevision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *Store) UpdateEscalations(ctx context.Context, actor string, permissions *access.Store, scope Scope, before string) ([]UpdateEscalation, string, error) {
	if before != "" && !profileRevisionUUID(before) {
		return nil, "", ErrUpdateEscalation
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
	var at any
	if before != "" {
		anchor, err := s.scanUpdateEscalation(tx.QueryRowContext(ctx, `SELECT `+updateEscalationColumns+` FROM mdm_apple_update_escalations WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, before, scope.TenantID, scope.SiteID))
		if err != nil {
			return nil, "", err
		}
		if err = s.validateUpdateEscalationSource(ctx, tx, anchor); err != nil {
			return nil, "", err
		}
		at = anchor.CreatedAt
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateEscalationColumns+` FROM mdm_apple_update_escalations WHERE tenant_id=$1 AND site_id=$2 AND ($3::timestamptz IS NULL OR (created_at,id)<($3,$4::uuid)) ORDER BY created_at DESC,id DESC LIMIT 26`, scope.TenantID, scope.SiteID, at, escalationNullableID(before))
	if err != nil {
		return nil, "", err
	}
	items := []UpdateEscalation{}
	for rows.Next() {
		r, err := s.scanUpdateEscalation(rows)
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
		if err = s.validateUpdateEscalationSource(ctx, tx, &items[i]); err != nil {
			return nil, "", err
		}
		if err = s.validateUpdateEscalationReferences(ctx, tx, &items[i]); err != nil {
			return nil, "", err
		}
	}
	next := ""
	if len(items) > 25 {
		next, items = items[24].ID, items[:25]
	}
	if err = auditUpdateEscalation(ctx, tx, scope, actor, "list", "", 0); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
func (s *Store) UpdateEscalationEventDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID, id string) (*UpdateEscalationEvent, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) || !profileRevisionUUID(id) {
		return nil, ErrUpdateEscalation
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
	e, err := s.scanUpdateEscalationEvent(tx.QueryRowContext(ctx, `SELECT `+updateEscalationEventColumns+` FROM mdm_apple_update_escalation_events WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4 AND assignment_id=$5`, id, scope.TenantID, scope.SiteID, planID, assignmentID))
	if err != nil {
		return nil, err
	}
	if err = s.validateUpdateEscalationEventSource(ctx, tx, e); err != nil {
		return nil, err
	}
	if err = auditUpdateEscalation(ctx, tx, scope, actor, "event.read", e.ID, e.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return e, nil
}
func (s *Store) UpdateEscalationEvents(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID, before string) ([]UpdateEscalationEvent, string, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) || (before != "" && !profileRevisionUUID(before)) {
		return nil, "", ErrUpdateEscalation
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
	// Even an empty history authenticates its original assignment and exact scope.
	original, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, assignmentID, scope.TenantID, scope.SiteID, planID))
	if err != nil {
		return nil, "", err
	}
	var revision any
	if before != "" {
		anchor, err := s.scanUpdateEscalationEvent(tx.QueryRowContext(ctx, `SELECT `+updateEscalationEventColumns+` FROM mdm_apple_update_escalation_events WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4 AND assignment_id=$5`, before, scope.TenantID, scope.SiteID, planID, assignmentID))
		if err != nil {
			return nil, "", err
		}
		if err = s.validateUpdateEscalationEventSource(ctx, tx, anchor); err != nil {
			return nil, "", err
		}
		revision = anchor.Revision
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateEscalationEventColumns+` FROM mdm_apple_update_escalation_events WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND assignment_id=$4 AND ($5::bigint IS NULL OR revision<$5) ORDER BY revision DESC LIMIT 26`, scope.TenantID, scope.SiteID, planID, assignmentID, revision)
	if err != nil {
		return nil, "", err
	}
	items := []UpdateEscalationEvent{}
	for rows.Next() {
		e, err := s.scanUpdateEscalationEvent(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		items = append(items, *e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	for i := range items {
		if err = s.validateUpdateEscalationEventSource(ctx, tx, &items[i]); err != nil {
			return nil, "", err
		}
	}
	next := ""
	if len(items) > 25 {
		next, items = items[24].ID, items[:25]
	}
	if err = auditUpdateEscalation(ctx, tx, scope, actor, "event.list", original.ID, 0); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
