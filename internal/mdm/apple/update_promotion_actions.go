package apple

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrUpdatePromotion = errors.New("invalid Apple update promotion request")

type UpdatePromotionRequest struct {
	RequestKey          string                     `json:"-" xml:"-" yaml:"-"`
	PilotPlanID         string                     `json:"-" xml:"-" yaml:"-"`
	PilotAssignmentID   string                     `json:"-" xml:"-" yaml:"-"`
	DestinationPlanID   string                     `json:"-" xml:"-" yaml:"-"`
	DestinationRevision int                        `json:"-" xml:"-" yaml:"-"`
	GroupID             string                     `json:"-" xml:"-" yaml:"-"`
	GroupRevision       int                        `json:"-" xml:"-" yaml:"-"`
	Targets             []UpdatePlanGroupSelection `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePromotionRequest) String() string     { return "[protected Apple update promotion request]" }
func (r UpdatePromotionRequest) GoString() string { return r.String() }

func (s *Store) verifyUpdatePromotionAdmission(ctx context.Context, tx *sql.Tx, r *UpdatePromotion, now time.Time) error {
	if err := validateUpdatePilotEvidence(r.Evidence, r.Pilot, now); err != nil {
		return ErrUpdatePromotionNotReady
	}
	ids := make([]string, 0, len(r.Targets)+len(r.Evidence.Devices))
	for _, target := range r.Targets {
		ids = append(ids, target.DeviceID)
	}
	for _, proof := range r.Evidence.Devices {
		ids = append(ids, proof.DeviceID)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	for _, id := range ids {
		var valid bool
		err := tx.QueryRowContext(ctx, `SELECT status='enrolled' AND certificate_expires_at>$4 FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, id, r.Scope.TenantID, r.Scope.SiteID, now).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUpdatePromotionNotReady
		}
		if err != nil {
			return err
		}
		if !valid {
			return ErrUpdatePromotionNotReady
		}
	}
	return nil
}

// Promotion is an explicit reviewed action. The original pilot must still be
// ready in the same transaction that applies the destination group policies.
func (s *Store) PromoteUpdatePlanGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, q UpdatePromotionRequest) (*UpdatePromotion, error) {
	targets, err := canonicalUpdateGroupSelection(q.Targets)
	if err != nil || !sources.Apple || !profileRevisionUUID(q.RequestKey) || !profileRevisionUUID(q.PilotPlanID) || !profileRevisionUUID(q.PilotAssignmentID) || !profileRevisionUUID(q.DestinationPlanID) || !profileRevisionUUID(q.GroupID) || q.DestinationRevision < 1 || q.DestinationRevision > 2147483647 || q.GroupRevision < 1 || q.GroupRevision > 2147483647 {
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
	var actorRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, actor).Scan(&actorRevision); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629912,hashtext($1))`, fmt.Sprintf("%d/%d/%s", scope.TenantID, scope.SiteID, q.RequestKey)); err != nil {
		return nil, err
	}
	previous, err := s.scanUpdatePromotion(tx.QueryRowContext(ctx, `SELECT `+updatePromotionColumns+` FROM mdm_apple_update_promotions WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3`, scope.TenantID, scope.SiteID, q.RequestKey))
	if err == nil {
		if previous.Actor != actor || previous.ActorRevision != actorRevision || previous.PilotPlanID != q.PilotPlanID || previous.PilotAssignmentID != q.PilotAssignmentID || previous.DestinationPlanID != q.DestinationPlanID || previous.DestinationRevision != q.DestinationRevision || previous.GroupID != q.GroupID || previous.GroupRevision != q.GroupRevision || !slices.Equal(previous.Targets, targets) {
			return nil, ErrConflict
		}
		if err = s.validateUpdatePromotionSources(ctx, tx, previous); err != nil {
			return nil, err
		}
		if err = auditUpdatePlan(ctx, tx, scope, actor, "promotion.replayed", previous.ID, previous.DestinationRevision); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	preview, err := s.inspectUpdatePromotion(ctx, tx, actor, permissions, scope, sources, q.PilotPlanID, q.PilotAssignmentID, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision, true)
	if err != nil {
		return nil, err
	}
	if !preview.Ready {
		return nil, ErrUpdatePromotionNotReady
	}
	current := make([]UpdatePlanGroupSelection, 0, len(preview.Destination.Targets))
	for _, target := range preview.Destination.Targets {
		current = append(current, target.Selection)
	}
	if !slices.Equal(current, targets) {
		return nil, ErrConflict
	}
	evidence, err := s.captureUpdatePilotEvidence(ctx, tx, &preview.Pilot)
	if err != nil {
		return nil, err
	}
	activationKey := uuid.NewString()
	assignment, err := s.writeUpdatePlanGroupAssignment(ctx, tx, actor, actorRevision, scope, activationKey, &preview.Destination)
	if err != nil {
		return nil, err
	}
	r := &UpdatePromotion{ID: uuid.NewString(), Scope: scope, RequestKey: q.RequestKey, PilotPlanID: q.PilotPlanID, PilotAssignmentID: q.PilotAssignmentID, DestinationPlanID: q.DestinationPlanID, AssignmentID: assignment.ID, Actor: actor, ActorRevision: actorRevision, DestinationRevision: q.DestinationRevision, GroupID: q.GroupID, GroupRevision: q.GroupRevision, Targets: targets, Evidence: evidence, Pilot: &preview.Pilot.Progress.Assignment, Assignment: assignment, activationKey: activationKey, sources: sources}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	if err = s.verifyUpdatePromotionAdmission(ctx, tx, r, r.CreatedAt); err != nil {
		return nil, err
	}
	if err = s.insertUpdatePromotion(ctx, tx, r); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "promotion.created", r.ID, r.DestinationRevision); err != nil {
		return nil, err
	}
	// A late audit cannot turn stale OS proof or an expired identity into an
	// approved rollout. All destination work and both receipts roll back together.
	var completed time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&completed); err != nil {
		return nil, err
	}
	if completed.Before(r.CreatedAt) {
		return nil, ErrUpdatePromotionIntegrity
	}
	if err = s.verifyUpdatePromotionAdmission(ctx, tx, r, completed); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
