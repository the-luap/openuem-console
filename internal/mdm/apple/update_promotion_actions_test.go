package apple

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedUpdatePromotionFixture(t *testing.T) (updateScheduleFixture, *UpdatePlanGroupAssignment, UpdatePromotionRequest) {
	t.Helper()
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	second, _ := testEnroll(t, f.store, f.scope, "Owned broad promotion target")
	drainCommands(t, f.store, second, nil)
	definition := f.plan.Definition
	definition.Name = "Owned reviewed broad rollout"
	definition.Deadline = "2026-11-01T18:00:00"
	broad, err := f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, "", 0, definition)
	require.NoError(t, err)
	preview, err := f.store.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, original.ID, broad.ID, broad.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	require.True(t, preview.Ready)
	q := UpdatePromotionRequest{RequestKey: uuid.NewString(), PilotPlanID: f.plan.ID, PilotAssignmentID: original.ID, DestinationPlanID: broad.ID, DestinationRevision: broad.Revision, GroupID: f.group.ID, GroupRevision: f.group.Revision}
	for _, target := range preview.Destination.Targets {
		q.Targets = append(q.Targets, target.Selection)
	}
	return f, original, q
}
func TestUpdatePromotionConcurrentReplayRetainsProofAndLaterPolicies(t *testing.T) {
	f, original, q := ownedUpdatePromotionFixture(t)
	ctx := t.Context()
	var wg sync.WaitGroup
	results := make(chan *UpdatePromotion, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			r, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
			results <- r
			failures <- err
		})
	}
	wg.Wait()
	require.NoError(t, <-failures)
	require.NoError(t, <-failures)
	first, second := <-results, <-results
	require.Equal(t, first.ID, second.ID)
	require.NotEqual(t, q.RequestKey, first.activationKey)
	require.Len(t, first.Evidence.Devices, 1)
	require.Len(t, first.Assignment.Commands, 2)
	require.Equal(t, original.ID, first.Pilot.ID)
	require.Equal(t, "18.7.1", first.Evidence.Devices[0].Observation.Version)
	require.Equal(t, "22H100", first.Evidence.Devices[0].Observation.Build)
	var promotions, assignments int
	require.NoError(t, f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_update_promotions),(SELECT count(*) FROM mdm_apple_update_group_assignments)`).Scan(&promotions, &assignments))
	require.Equal(t, 1, promotions)
	require.Equal(t, 2, assignments)
	// Overlapping pilot devices received the separately reviewed broad deadline.
	policy, err := f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.NoError(t, err)
	require.Equal(t, "2026-11-01T18:00:00", policy.Deadline)
	pilot, err := f.store.ReviewUpdatePilotReadiness(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID)
	require.NoError(t, err)
	require.False(t, pilot.AllReady)
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions))
	p0, a0, n0 := f.counts(t)
	replay, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
	require.NoError(t, err)
	require.Equal(t, first.ID, replay.ID)
	p, a, n := f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound)
	detail, err := f.store.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, first.ID)
	require.NoError(t, err)
	require.Equal(t, first.Evidence.AssessedAt, detail.Evidence.AssessedAt)
	require.Equal(t, first.Assignment.ID, detail.Assignment.ID)
	items, next, err := f.store.UpdatePromotions(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Empty(t, next)
	_, err = f.store.UpdatePromotionDetails(ctx, "viewer", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, first.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	for _, value := range []any{first, q, detail} {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(raw))
		require.NotContains(t, fmt.Sprintf("%#v", value), f.device.ID)
	}
}
func TestUpdatePromotionRechecksCurrentPilotAndReviewedDestinationBeforeWrites(t *testing.T) {
	for _, condition := range []string{"unknown-pilot", "policy-error", "pilot-exception", "destination-policy", "new-member", "plan-revision", "grant-revision", "viewer", "wrong-target"} {
		t.Run(condition, func(t *testing.T) {
			f, _, q := ownedUpdatePromotionFixture(t)
			ctx := t.Context()
			actor := "operator"
			switch condition {
			case "unknown-pilot":
				_, err := f.store.db.Exec(`DELETE FROM mdm_apple_os_observations WHERE device_id=$1`, f.device.ID)
				require.NoError(t, err)
			case "policy-error":
				_, err := f.store.db.Exec(`UPDATE mdm_apple_update_policies SET error='Owned policy failure' WHERE device_id=$1`, f.device.ID)
				require.NoError(t, err)
			case "pilot-exception":
				_, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, ownedExceptionRequest(t, f, "pause"))
				require.NoError(t, err)
			case "destination-policy":
				policy := f.plan.Definition.Policy()
				for _, target := range q.Targets {
					if target.DeviceID != f.device.ID {
						require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{target.DeviceID}, &policy, "operator", f.permissions))
					}
				}
			case "new-member":
				d, _ := testEnroll(t, f.store, f.scope, "Owned later broad member")
				drainCommands(t, f.store, d, nil)
			case "plan-revision":
				q.DestinationRevision++
			case "grant-revision":
				require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil))
			case "viewer":
				actor = "viewer"
			case "wrong-target":
				q.Targets[0].DeviceID = uuid.NewString()
			}
			p0, a0, n0 := f.counts(t)
			r, err := f.store.PromoteUpdatePlanGroup(ctx, actor, f.permissions, f.scope, f.sources, q)
			require.Error(t, err)
			require.Nil(t, r)
			p, a, n := f.counts(t)
			require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
			var count int
			require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_promotions`).Scan(&count))
			require.Zero(t, count)
		})
	}
}
