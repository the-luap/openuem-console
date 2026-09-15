package apple

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdatePromotionPreviewRequiresObservedPilotSuccessAndNewNativeTargets(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	read := func() *UpdatePromotionPreview {
		t.Helper()
		p, err := f.store.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, original.ID, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
		require.NoError(t, err)
		return p
	}
	p := read()
	require.False(t, p.Ready)
	require.False(t, p.Pilot.AllReady)
	require.Zero(t, p.NewTargets)
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	p = read()
	require.True(t, p.Pilot.AllReady)
	require.True(t, p.CompatibleTarget)
	require.False(t, p.Ready)
	require.Equal(t, []string{f.device.ID}, p.PilotOverlap)
	second, _ := testEnroll(t, f.store, f.scope, "Owned broad promotion target")
	drainCommands(t, f.store, second, nil)
	beforePolicies, beforeAssignments, beforeCommands := f.counts(t)
	p = read()
	require.True(t, p.Ready)
	require.Equal(t, 1, p.NewTargets)
	require.Len(t, p.Destination.Targets, 2)
	require.Len(t, p.Pilot.Progress.Devices, 1)
	policies, assignments, commands := f.counts(t)
	require.Equal(t, []int{beforePolicies, beforeAssignments, beforeCommands}, []int{policies, assignments, commands})
	originalProof := p.Pilot.Progress.Devices[0]
	require.Equal(t, f.device.ID, originalProof.DeviceID)
	require.Equal(t, "target_reported", originalProof.Result)
	require.Equal(t, 1, len(p.PilotOverlap))
	require.Equal(t, f.device.ID, p.PilotOverlap[0])
	for _, value := range []any{p, p.Pilot, p.Destination} {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(raw))
		require.NotContains(t, fmt.Sprintf("%#v", value), f.device.ID)
	}
	_, err := f.store.PreviewUpdatePromotion(ctx, "viewer", f.permissions, f.scope, f.sources, f.plan.ID, original.ID, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
}
func TestUpdatePromotionPreviewRetainsOriginalPilotAndRejectsDifferentRelease(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	second, _ := testEnroll(t, f.store, f.scope, "Owned broad promotion target")
	drainCommands(t, f.store, second, nil)
	definition := f.plan.Definition
	definition.Name = "Owned broad plan"
	definition.Deadline = "2026-11-01T18:00:00"
	broad, err := f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, "", 0, definition)
	require.NoError(t, err)
	definition = f.plan.Definition
	definition.Archived = true
	_, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	p, err := f.store.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, original.ID, broad.ID, broad.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	require.True(t, p.Ready)
	require.Equal(t, original.Plan.Definition, p.Pilot.Progress.Assignment.Plan.Definition)
	definition = broad.Definition
	definition.TargetBuild = "22H999"
	broad, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, broad.ID, broad.Revision, definition)
	require.NoError(t, err)
	p, err = f.store.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, original.ID, broad.ID, broad.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	require.False(t, p.CompatibleTarget)
	require.False(t, p.Ready)
	_, err = f.store.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, inventory.DeviceSources{}, f.plan.ID, original.ID, broad.ID, broad.Revision, f.group.ID, f.group.Revision)
	require.ErrorIs(t, err, ErrUpdatePlanGroup)
}
