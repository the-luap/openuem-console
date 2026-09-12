package apple

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdatePromotionPreview struct {
	Pilot            UpdatePilotReadiness   `json:"-" xml:"-" yaml:"-"`
	Destination      UpdatePlanGroupPreview `json:"-" xml:"-" yaml:"-"`
	CompatibleTarget bool                   `json:"-" xml:"-" yaml:"-"`
	PilotOverlap     []string               `json:"-" xml:"-" yaml:"-"`
	NewTargets       int                    `json:"-" xml:"-" yaml:"-"`
	Ready            bool                   `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePromotionPreview) String() string     { return "[protected Apple update promotion preview]" }
func (r UpdatePromotionPreview) GoString() string { return r.String() }
func UpdatePromotionTargetMatches(pilot, destination UpdatePlanDefinition) bool {
	return pilot.Platform == destination.Platform && pilot.TargetVersion == destination.TargetVersion && pilot.TargetBuild == destination.TargetBuild
}
func (s *Store) inspectUpdatePromotion(ctx context.Context, tx *sql.Tx, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, pilotPlanID, pilotAssignmentID, destinationPlanID string, destinationRevision int, groupID string, groupRevision int, admitting bool) (*UpdatePromotionPreview, error) {
	original, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, pilotAssignmentID, scope.TenantID, scope.SiteID, pilotPlanID))
	if err != nil {
		return nil, err
	}
	pilotIDs := make([]string, 0, len(original.Commands))
	for _, command := range original.Commands {
		pilotIDs = append(pilotIDs, command.Selection.DeviceID)
	}
	destination, err := s.inspectUpdatePlanGroupWithPilot(ctx, tx, actor, permissions, scope, sources, destinationPlanID, destinationRevision, groupID, groupRevision, admitting, pilotIDs)
	if err != nil {
		return nil, err
	}
	progress, err := s.assessUpdateGroupProgressTransaction(ctx, tx, scope, pilotPlanID, pilotAssignmentID)
	if err != nil {
		return nil, err
	}
	pilot := assessUpdatePilotReadiness(progress)
	r := &UpdatePromotionPreview{Pilot: *pilot, Destination: *destination, CompatibleTarget: UpdatePromotionTargetMatches(original.Plan.Definition, destination.Plan.Definition), PilotOverlap: []string{}}
	for _, target := range destination.Targets {
		if _, found := slices.BinarySearch(pilotIDs, target.Selection.DeviceID); found {
			r.PilotOverlap = append(r.PilotOverlap, target.Selection.DeviceID)
		} else {
			r.NewTargets++
		}
	}
	// Reapplying only to the pilot does not broaden a rollout. Overlapping pilot
	// IDs remain explicit reviewed targets under the ordinary group contract.
	r.Ready = r.Pilot.AllReady && r.CompatibleTarget && r.NewTargets > 0
	return r, nil
}
func (s *Store) PreviewUpdatePromotion(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, pilotPlanID, pilotAssignmentID, destinationPlanID string, destinationRevision int, groupID string, groupRevision int) (*UpdatePromotionPreview, error) {
	if !sources.Apple || !profileRevisionUUID(pilotPlanID) || !profileRevisionUUID(pilotAssignmentID) || !profileRevisionUUID(destinationPlanID) || !profileRevisionUUID(groupID) || destinationRevision < 1 || destinationRevision > 2147483647 || groupRevision < 1 || groupRevision > 2147483647 {
		return nil, ErrUpdatePlanGroup
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
	r, err := s.inspectUpdatePromotion(ctx, tx, actor, permissions, scope, sources, pilotPlanID, pilotAssignmentID, destinationPlanID, destinationRevision, groupID, groupRevision, false)
	if err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "promotion.preview", pilotAssignmentID, r.Pilot.Progress.Assignment.Plan.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
