package apple

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedOrganizationUpdateFixture(t *testing.T) updateScheduleFixture {
	t.Helper()
	f := ownedUpdateScheduleFixture(t)
	var err error
	f.group, err = inventory.SaveDeviceGroup(t.Context(), f.store.db, f.permissions, "organization", access.Scope{TenantID: 1}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <organization update source>"})
	require.NoError(t, err)
	preview, err := f.store.PreviewUpdatePlanOrganizationGroup(t.Context(), "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	f.selection = updateGroupSelection(preview)
	return f
}

func TestUpdateOrganizationGroupCombinesSourceReadWithTargetSiteAuthority(t *testing.T) {
	f := ownedOrganizationUpdateFixture(t)
	ctx := t.Context()
	grants := []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: 1}}, {Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, grants))
	preview, err := f.store.PreviewUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	_, err = f.store.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), updateGroupSelection(preview))
	require.NoError(t, err)
	// Organization read access alone cannot manage the target site's updates.
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 2, grants[:1]))
	preview, err = f.store.PreviewUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, preview)
}

func TestUpdateOrganizationGroupAdmitsOnlyReviewedSiteAndRetainsOriginalCohort(t *testing.T) {
	f := ownedOrganizationUpdateFixture(t)
	s, ctx := f.store, t.Context()
	_, err := s.db.Exec(`INSERT INTO sites(id,tenant_sites) VALUES(3,1)`)
	require.NoError(t, err)
	outside, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 3}, "Other site private update device")
	drainCommands(t, s, outside, nil)
	preview, err := s.PreviewUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1)
	require.NoError(t, err)
	require.Zero(t, preview.Group.Scope.SiteID)
	require.Equal(t, f.selection, updateGroupSelection(preview))
	require.Len(t, preview.Targets, 1)
	require.Len(t, preview.Excluded, 1)
	require.Equal(t, "owned-desktop", preview.Excluded[0].Entry.ID)
	for _, actor := range []string{"operator", "viewer"} {
		result, err := s.PreviewUpdatePlanOrganizationGroup(ctx, actor, f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, result)
	}
	_, err = s.PreviewUpdatePlanGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	injected := append([]UpdatePlanGroupSelection{}, f.selection...)
	injected = append(injected, UpdatePlanGroupSelection{DeviceID: outside.ID, PolicyToken: updatePolicyGroupToken(f.scope, outside.ID, nil)})
	_, err = s.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, uuid.NewString(), injected)
	require.ErrorIs(t, err, ErrConflict)
	key := uuid.NewString()
	var receipts [2]*UpdatePlanGroupAssignment
	var failures [2]error
	var workers sync.WaitGroup
	for i := range 2 {
		workers.Go(func() {
			receipts[i], failures[i] = s.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, key, f.selection)
		})
	}
	workers.Wait()
	for i := range receipts {
		require.NoError(t, failures[i])
		require.Equal(t, receipts[0], receipts[i])
	}
	original := receipts[0]
	require.Equal(t, Scope{TenantID: 1}, original.GroupScope)
	require.Equal(t, f.scope, original.Scope)
	_, err = s.UpdatePolicy(ctx, Scope{TenantID: 1, SiteID: 3}, outside.ID)
	require.ErrorIs(t, err, ErrNotFound)
	drainCommands(t, s, f.device, nil)
	response, err := s.DeclarativeManagement(ctx, f.device, map[string]any{"UDID": f.device.UDID, "Endpoint": "declaration/configuration/eu.openuem.apple." + f.device.ID + ".update"})
	require.NoError(t, err)
	declaration := response.(Declaration)
	require.Equal(t, f.plan.Definition.TargetVersion, declaration.Payload["TargetOSVersion"])
	require.Equal(t, f.plan.Definition.Deadline, declaration.Payload["TargetLocalDateTime"])
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	definition := f.group.DeviceGroupDefinition
	definition.Name, definition.Archived = "Later archived organization group", true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "organization", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
	require.NoError(t, err)
	progress, err := s.UpdatePlanGroupProgress(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	require.Equal(t, original.GroupScope, progress.Assignment.GroupScope)
	require.Equal(t, 1, progress.Counts.TargetReported)
	_, err = s.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, UpdateEscalationRequest{PlanID: f.plan.ID, AssignmentID: original.ID, RequestKey: uuid.NewString(), Enabled: true})
	require.NoError(t, err)
	_, err = s.UpdateEscalationDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	_, err = s.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), ownedUpdateRemovalReview(t, f, original))
	require.NoError(t, err)
	p0, a0, n0 := f.counts(t)
	replay, err := s.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, key, f.selection)
	require.NoError(t, err)
	require.Equal(t, original, replay)
	p, a, n := f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	require.Zero(t, p)
	_, err = s.AssignUpdatePlanFromGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, key, f.selection)
	require.ErrorIs(t, err, ErrConflict)
	detail, err := s.UpdatePlanGroupAssignmentDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	require.Equal(t, original, detail)
	items, _, err := s.UpdatePlanGroupAssignments(ctx, "operator", f.permissions, f.scope, f.plan.ID, "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, original.GroupScope, items[0].GroupScope)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err = s.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, key, f.selection)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestUpdateOrganizationGroupArchivedSourceCanRemainHistoricalPilot(t *testing.T) {
	f := ownedOrganizationUpdateFixture(t)
	s, ctx := f.store, t.Context()
	original, err := s.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, uuid.NewString(), f.selection)
	require.NoError(t, err)
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	definition := f.group.DeviceGroupDefinition
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "organization", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
	require.NoError(t, err)
	second, _ := testEnroll(t, s, f.scope, "Owned new rollout device")
	drainCommands(t, s, second, nil)
	destination, err := inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned site destination"})
	require.NoError(t, err)
	planDefinition := f.plan.Definition
	planDefinition.Name, planDefinition.Deadline = "Owned broad rollout", "2026-11-01T18:00:00"
	plan, err := s.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, "", 0, planDefinition)
	require.NoError(t, err)
	preview, err := s.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, original.ID, plan.ID, plan.Revision, destination.ID, 1)
	require.NoError(t, err)
	require.True(t, preview.Ready)
	require.Equal(t, 1, preview.NewTargets)
	r, err := s.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, UpdatePromotionRequest{RequestKey: uuid.NewString(), PilotPlanID: f.plan.ID, PilotAssignmentID: original.ID, DestinationPlanID: plan.ID, DestinationRevision: plan.Revision, GroupID: destination.ID, GroupRevision: 1, Targets: updateGroupSelection(&preview.Destination)})
	require.NoError(t, err)
	require.Equal(t, original.GroupScope, r.Pilot.GroupScope)
	require.Equal(t, f.scope, r.Assignment.GroupScope)
	_, err = s.PreviewUpdatePromotion(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, original.ID, plan.ID, plan.Revision, f.group.ID, 1)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}
