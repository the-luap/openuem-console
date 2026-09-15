package apple

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDeadlineRequirementNeedsOSReportAfterLatestPossibleInstant(t *testing.T) {
	now := time.Date(2026, 10, 25, 2, 0, 0, 0, time.UTC)
	policy := &UpdatePolicy{Deadline: "2026-10-25T02:30:00"}
	zone := &TimeZoneObservation{Name: "Europe/Berlin", Source: "device_information", RecordedAt: now.Add(-time.Minute)}
	d := UpdateGroupDeviceProgress{Result: "update_required", Deadline: assessUpdateDeadline(true, policy, zone, now)}
	require.Equal(t, "elapsed", d.Deadline.State)
	for _, example := range []struct {
		name     string
		observed time.Time
		required bool
	}{
		{"before both occurrences", now.Add(-2 * time.Hour), false},
		{"between occurrences", now.Add(-time.Hour), false},
		{"at latest occurrence", now.Add(-30 * time.Minute), true},
		{"after both occurrences", now.Add(-time.Minute), true},
	} {
		t.Run(example.name, func(t *testing.T) {
			d.RecordedAt = &example.observed
			require.Equal(t, example.required, updateRequirementAfterDeadline(d))
		})
	}
	d.Result = "target_reported"
	require.False(t, updateRequirementAfterDeadline(d))
	d.Result, d.RecordedAt = "update_required", nil
	require.False(t, updateRequirementAfterDeadline(d))
}

func TestDeadlineAssessmentKeepsOriginalAndCurrentPolicySeparate(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	definition := f.plan.Definition
	definition.Deadline = time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05")
	plan, err := f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	original, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, plan.ID, plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection)
	require.NoError(t, err)
	drainTimeZoneInventory(t, f.store, f.device, "UTC", true)
	read := func() (*UpdateGroupProgress, *UpdateAssessment) {
		t.Helper()
		group, err := f.store.UpdatePlanGroupProgress(ctx, "operator", f.permissions, f.scope, plan.ID, original.ID)
		require.NoError(t, err)
		device, err := f.store.AssessDeviceUpdate(ctx, "viewer", f.permissions, f.scope, f.device.ID)
		require.NoError(t, err)
		return group, device
	}
	group, device := read()
	require.Equal(t, "elapsed", device.Deadline.State)
	require.Equal(t, "update_required", device.Compliance)
	require.Equal(t, 1, group.Counts.DeadlineElapsed)
	require.Equal(t, 1, group.Counts.UpdateRequiredAfterDeadline)
	require.Equal(t, "UTC", group.Devices[0].Deadline.TimeZone.Name)
	policy := plan.Definition.Policy()
	policy.Deadline = time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05")
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	group, device = read()
	require.Equal(t, "pending", device.Deadline.State)
	require.Equal(t, "elapsed", group.Devices[0].Deadline.State)
	require.Equal(t, 1, group.Counts.PolicyDifferent)
	for _, condition := range []string{"stale", "future", "missing"} {
		query := `UPDATE mdm_apple_timezone_observations SET recorded_at=clock_timestamp()-interval '25 hours' WHERE device_id=$1`
		if condition == "future" {
			query = `UPDATE mdm_apple_timezone_observations SET recorded_at=clock_timestamp()+interval '1 hour' WHERE device_id=$1`
		}
		if condition == "missing" {
			query = `DELETE FROM mdm_apple_timezone_observations WHERE device_id=$1`
		}
		_, err = f.store.db.Exec(query, f.device.ID)
		require.NoError(t, err)
		group, device = read()
		require.Equal(t, "unverified", device.Deadline.State)
		require.Equal(t, 1, group.Counts.DeadlineUnverified)
		require.Zero(t, group.Counts.UpdateRequiredAfterDeadline)
		require.Equal(t, 1, group.Counts.UpdateRequired, "Missing zone evidence must not replace fresh OS evidence")
	}
	drainTimeZoneInventory(t, f.store, f.device, "Europe/Berlin", true)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	group, err = f.store.UpdatePlanGroupProgress(ctx, "operator", f.permissions, f.scope, plan.ID, original.ID)
	require.NoError(t, err)
	require.Nil(t, group.Devices[0].Deadline.TimeZone)
	require.Equal(t, "device_unavailable", group.Devices[0].Deadline.Reason)
	require.Empty(t, group.Devices[0].Name)
}
