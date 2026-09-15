package apple

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedOrganizationSchedule(t *testing.T, f updateScheduleFixture, at time.Time) *UpdateSchedule {
	t.Helper()
	r, err := f.store.ScheduleUpdatePlanFromOrganizationGroup(t.Context(), "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection, at, time.Hour)
	require.NoError(t, err)
	return r
}

func TestUpdateOrganizationScheduleConcurrentActivationRetainsExactSiteSourceAndReplay(t *testing.T) {
	f := ownedOrganizationUpdateFixture(t)
	s, ctx := f.store, t.Context()
	// Read authority for the source can be combined with action authority only
	// at the selected target site; an organization administrator is unnecessary.
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: 1}}, {Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	p0, a0, n0 := f.counts(t)
	r := ownedOrganizationSchedule(t, f, time.Now().UTC().Truncate(time.Second))
	require.Equal(t, Scope{TenantID: 1}, r.GroupScope)
	p, a, n := f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	// An unrelated new member in another site does not invalidate this review.
	_, err := s.db.Exec(`INSERT INTO sites(id,tenant_sites) VALUES(3,1)`)
	require.NoError(t, err)
	outside, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 3}, "Owned later other-site member")
	drainCommands(t, s, outside, nil)
	var workers sync.WaitGroup
	var results [2]UpdateScheduleProgress
	var failures [2]error
	for i := range 2 {
		workers.Go(func() {
			results[i], failures[i] = s.ProcessDueUpdateSchedules(ctx, f.permissions, f.sources, 25)
		})
	}
	workers.Wait()
	for i := range results {
		require.NoError(t, failures[i])
	}
	require.Equal(t, 1, results[0].Activated+results[1].Activated)
	current := f.details(t, r.ID)
	require.Equal(t, "activated", current.Phase)
	require.Equal(t, r.GroupScope, current.GroupScope)
	receipt, err := s.UpdatePlanGroupAssignmentDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, current.AssignmentID)
	require.NoError(t, err)
	require.Equal(t, r.GroupScope, receipt.GroupScope)
	require.Len(t, receipt.Commands, 1)
	require.Equal(t, f.device.ID, receipt.Commands[0].Selection.DeviceID)
	_, err = s.UpdatePolicy(ctx, Scope{TenantID: 1, SiteID: 3}, outside.ID)
	require.ErrorIs(t, err, ErrNotFound)
	drainCommands(t, s, f.device, nil)
	response, err := s.DeclarativeManagement(ctx, f.device, map[string]any{"UDID": f.device.UDID, "Endpoint": "declaration/configuration/eu.openuem.apple." + f.device.ID + ".update"})
	require.NoError(t, err)
	require.Equal(t, f.plan.Definition.TargetVersion, response.(Declaration).Payload["TargetOSVersion"])
	definition := f.group.DeviceGroupDefinition
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "admin", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
	require.NoError(t, err)
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions))
	p0, a0, n0 = f.counts(t)
	replay, err := s.ScheduleUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, r.RequestKey, f.selection, r.NotBefore, time.Hour)
	require.NoError(t, err)
	require.Equal(t, current, replay)
	p, a, n = f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	require.Zero(t, p)
	_, err = s.ScheduleUpdatePlanFromGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, r.RequestKey, f.selection, r.NotBefore, time.Hour)
	require.ErrorIs(t, err, ErrConflict)
	items, _, err := s.UpdateSchedules(ctx, "operator", f.permissions, f.scope, f.plan.ID, "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, current.GroupScope, items[0].GroupScope)
}

func TestUpdateOrganizationScheduleHistoryAndCancellationKeepTargetSiteAuthority(t *testing.T) {
	f := ownedOrganizationUpdateFixture(t)
	s, ctx := f.store, t.Context()
	r := ownedOrganizationSchedule(t, f, time.Now().UTC().Add(time.Hour).Truncate(time.Second))
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err := s.ScheduleUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, r.RequestKey, f.selection, r.NotBefore, time.Hour)
	require.ErrorIs(t, err, access.ErrDenied)
	detail, err := s.UpdateScheduleDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, r.ID)
	require.NoError(t, err)
	require.Equal(t, r.GroupScope, detail.GroupScope)
	require.NoError(t, s.CancelUpdateSchedule(ctx, "operator", f.permissions, f.scope, f.plan.ID, r.ID, r.Revision))
	require.Equal(t, "canceled", f.details(t, r.ID).Phase)
	require.Zero(t, f.process(t).Processed)
	_, err = s.UpdateScheduleDetails(ctx, "viewer", f.permissions, f.scope, f.plan.ID, r.ID)
	require.ErrorIs(t, err, access.ErrDenied)
}
