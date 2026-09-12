package apple

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedOrganizationPromotionFixture(t *testing.T) (updateScheduleFixture, *UpdatePlanGroupAssignment, UpdatePromotionRequest) {
	t.Helper()
	f, pilot, q := ownedUpdatePromotionFixture(t)
	var err error
	f.group, err = inventory.SaveDeviceGroup(t.Context(), f.store.db, f.permissions, "organization", access.Scope{TenantID: 1}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <organization rollout>"})
	require.NoError(t, err)
	q.GroupID, q.GroupRevision = f.group.ID, f.group.Revision
	preview, err := f.store.PreviewUpdatePromotionOrganizationGroup(t.Context(), "organization", f.permissions, f.scope, f.sources, q.PilotPlanID, q.PilotAssignmentID, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision)
	require.NoError(t, err)
	require.True(t, preview.Ready)
	q.Targets = updateGroupSelection(&preview.Destination)
	return f, pilot, q
}

func TestUpdateOrganizationPromotionKeepsReviewedSitePilotProofAndOriginalReplay(t *testing.T) {
	f, pilot, q := ownedOrganizationPromotionFixture(t)
	s, ctx := f.store, t.Context()
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: 1}}, {Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err := s.db.Exec(`INSERT INTO sites(id,tenant_sites) VALUES(3,1)`)
	require.NoError(t, err)
	outside, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 3}, "Owned other-site rollout target")
	drainCommands(t, s, outside, nil)
	preview, err := s.PreviewUpdatePromotionOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, q.PilotPlanID, q.PilotAssignmentID, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision)
	require.NoError(t, err)
	require.True(t, preview.Ready)
	require.Equal(t, q.Targets, updateGroupSelection(&preview.Destination))
	require.Equal(t, 1, preview.NewTargets)
	require.Equal(t, []string{f.device.ID}, preview.PilotOverlap)
	require.Len(t, preview.Destination.Excluded, 1)
	require.Equal(t, "owned-desktop", preview.Destination.Excluded[0].Entry.ID)
	for _, actor := range []string{"operator", "viewer"} {
		result, err := s.PreviewUpdatePromotionOrganizationGroup(ctx, actor, f.permissions, f.scope, f.sources, q.PilotPlanID, q.PilotAssignmentID, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, result)
	}
	_, err = s.PreviewUpdatePromotion(ctx, "organization", f.permissions, f.scope, f.sources, q.PilotPlanID, q.PilotAssignmentID, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	injected := q
	injected.RequestKey = uuid.NewString()
	injected.Targets = append(append([]UpdatePlanGroupSelection{}, q.Targets...), UpdatePlanGroupSelection{DeviceID: outside.ID, PolicyToken: updatePolicyGroupToken(f.scope, outside.ID, nil)})
	_, err = s.PromoteUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, injected)
	require.ErrorIs(t, err, ErrConflict)
	var workers sync.WaitGroup
	var results [2]*UpdatePromotion
	var failures [2]error
	for i := range 2 {
		workers.Go(func() {
			results[i], failures[i] = s.PromoteUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, q)
		})
	}
	workers.Wait()
	for i := range results {
		require.NoError(t, failures[i])
		require.Equal(t, results[0].ID, results[i].ID)
	}
	original := results[0]
	require.Equal(t, Scope{TenantID: 1}, original.GroupScope)
	require.Equal(t, original.GroupScope, original.Assignment.GroupScope)
	require.Equal(t, f.scope, original.Pilot.GroupScope)
	require.Equal(t, pilot.ID, original.Pilot.ID)
	require.Len(t, original.Assignment.Commands, 2)
	require.Len(t, original.Evidence.Devices, 1)
	require.Equal(t, "18.7.1", original.Evidence.Devices[0].Observation.Version)
	_, err = s.UpdatePolicy(ctx, Scope{TenantID: 1, SiteID: 3}, outside.ID)
	require.ErrorIs(t, err, ErrNotFound)
	var parents, assignments int
	require.NoError(t, s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_update_promotions),(SELECT count(*) FROM mdm_apple_update_group_assignments)`).Scan(&parents, &assignments))
	require.Equal(t, 1, parents)
	require.Equal(t, 2, assignments)
	definition := f.group.DeviceGroupDefinition
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "admin", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
	require.NoError(t, err)
	ids := make([]string, len(q.Targets))
	for i, target := range q.Targets {
		ids[i] = target.DeviceID
	}
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, f.scope, ids, nil, "operator", f.permissions))
	p0, a0, n0 := f.counts(t)
	replay, err := s.PromoteUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, q)
	require.NoError(t, err)
	require.Equal(t, original.ID, replay.ID)
	require.Equal(t, original.Evidence.AssessedAt, replay.Evidence.AssessedAt)
	p, a, n := f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	require.Zero(t, p)
	_, err = s.PromoteUpdatePlanGroup(ctx, "organization", f.permissions, f.scope, f.sources, q)
	require.ErrorIs(t, err, ErrConflict)
	detail, err := s.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, original.ID)
	require.NoError(t, err)
	require.Equal(t, original.GroupScope, detail.GroupScope)
	require.Equal(t, f.group.Name, detail.Assignment.Group.Name)
	items, _, err := s.UpdatePromotions(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, original.GroupScope, items[0].GroupScope)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 2, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err = s.PromoteUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, q)
	require.ErrorIs(t, err, access.ErrDenied)
}
