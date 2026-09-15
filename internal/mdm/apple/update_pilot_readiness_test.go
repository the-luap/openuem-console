package apple

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdatePilotReadinessRequiresCompleteHealthyOriginalCohort(t *testing.T) {
	for _, condition := range []string{"ready", "unavailable", "exception", "absent", "different", "unknown-policy", "policy-error", "update-required", "unknown-os", "unverified-deadline", "notification-pending", "missing-time", "before-exception-end", "after-exception-end"} {
		t.Run(condition, func(t *testing.T) {
			observed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
			d := UpdateGroupDeviceProgress{DeviceID: "10000000-0000-4000-8000-000000000001", Availability: "available", PolicyState: "matches", Result: "target_reported", NotificationStatus: "acknowledged", RecordedAt: &observed}
			switch condition {
			case "unavailable":
				d.Availability = "identity_expired"
			case "exception":
				d.ExceptionActive = true
			case "absent":
				d.PolicyState = "absent"
			case "different":
				d.PolicyState = "different"
			case "unknown-policy":
				d.PolicyState = "unknown"
			case "policy-error":
				d.PolicyHasError = true
			case "update-required":
				d.Result = "update_required"
			case "unknown-os":
				d.Result = "unverified"
			case "unverified-deadline":
				d.Deadline = &UpdateDeadlineAssessment{State: "unverified"}
			case "notification-pending":
				d.NotificationStatus = "queued"
			case "missing-time":
				d.RecordedAt = nil
			case "before-exception-end":
				d.Exception = &UpdateException{Kind: "resume", CreatedAt: observed.Add(time.Minute)}
			case "after-exception-end":
				d.Exception = &UpdateException{Kind: "resume", CreatedAt: observed.Add(-time.Minute)}
			}
			expected := condition == "ready" || condition == "unverified-deadline" || condition == "notification-pending" || condition == "after-exception-end"
			result := assessUpdatePilotDevice(d)
			require.Equal(t, expected, result.Ready)
			require.Equal(t, expected, result.Reason == "")
			p := &UpdateGroupProgress{Assignment: UpdatePlanGroupAssignment{Commands: []UpdatePlanGroupCommand{{Selection: UpdatePlanGroupSelection{DeviceID: d.DeviceID}}}}, Devices: []UpdateGroupDeviceProgress{d}}
			require.Equal(t, expected, assessUpdatePilotReadiness(p).AllReady)
			p.Devices = nil
			require.False(t, assessUpdatePilotReadiness(p).AllReady)
		})
	}
}
func ownedPilotOSReport(t *testing.T, f updateScheduleFixture, fields map[string]any) {
	t.Helper()
	payload, err := json.Marshal(StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": fields}}})
	require.NoError(t, err)
	_, err = f.store.DeclarativeManagement(t.Context(), f.device, map[string]any{"UDID": f.device.UDID, "Endpoint": "status", "Data": payload})
	require.NoError(t, err)
}
func TestUpdatePilotReadinessUsesFreshPacketProofAndCurrentPolicy(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	read := func() *UpdatePilotReadiness {
		t.Helper()
		r, err := f.store.ReviewUpdatePilotReadiness(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID)
		require.NoError(t, err)
		return r
	}
	require.False(t, read().AllReady)
	drainCommands(t, f.store, f.device, nil)
	require.False(t, read().AllReady)
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1"})
	r := read()
	require.False(t, r.AllReady)
	require.Equal(t, "missing_build", r.Progress.Devices[0].Reason)
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	r = read()
	require.True(t, r.AllReady)
	require.Equal(t, 1, r.Ready)
	require.Equal(t, "unverified", r.Progress.Devices[0].Deadline.State)
	// Editing or archiving a reusable plan does not alter the original pilot.
	definition := f.plan.Definition
	definition.Archived = true
	_, err := f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	require.True(t, read().AllReady)
	policy := original.Plan.Definition.Policy()
	policy.Deadline = "2026-11-01T18:00:00"
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	r = read()
	require.False(t, r.AllReady)
	require.Equal(t, "policy_different", r.Devices[0].Reason)
	require.Equal(t, 1, r.Progress.Counts.TargetReported)
	for _, value := range []any{r, r.Devices[0]} {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(raw))
		require.NotContains(t, fmt.Sprintf("%#v", value), f.device.ID)
	}
	_, err = f.store.ReviewUpdatePilotReadiness(ctx, "viewer", f.permissions, f.scope, f.plan.ID, original.ID)
	require.ErrorIs(t, err, access.ErrDenied)
}
func TestUpdatePilotReadinessRejectsStaleProofExceptionsAndReadAuditFailure(t *testing.T) {
	for _, condition := range []string{"stale", "future", "moved", "expired", "exception", "policy-error", "audit"} {
		t.Run(condition, func(t *testing.T) {
			f, original := ownedUpdateRemovalFixture(t)
			ctx := t.Context()
			ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
			var query string
			switch condition {
			case "stale":
				query = `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()-interval '25 hours' WHERE device_id=$1`
			case "future":
				query = `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()+interval '1 hour' WHERE device_id=$1`
			case "moved":
				query = `UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`
			case "expired":
				query = `UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`
			case "policy-error":
				query = `UPDATE mdm_apple_update_policies SET error='Owned current failure' WHERE device_id=$1`
			case "exception":
				_, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, ownedExceptionRequest(t, f, "pause"))
				require.NoError(t, err)
			case "audit":
				_, err := f.store.db.Exec(`CREATE FUNCTION owned_pilot_read_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.pilot.readiness' THEN RAISE EXCEPTION 'owned readiness read failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_pilot_read_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_pilot_read_failure()`)
				require.NoError(t, err)
			}
			if query != "" {
				_, err := f.store.db.Exec(query, f.device.ID)
				require.NoError(t, err)
			}
			r, err := f.store.ReviewUpdatePilotReadiness(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID)
			if condition == "audit" {
				require.Error(t, err)
				require.Nil(t, r)
			} else {
				require.NoError(t, err)
				require.False(t, r.AllReady)
				require.Equal(t, 1, r.Blocked)
			}
		})
	}
}
