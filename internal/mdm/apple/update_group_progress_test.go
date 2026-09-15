package apple

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdateGroupProgressRequiresFreshPostAdmissionOSAndIndependentPolicyState(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	receipt, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection)
	require.NoError(t, err)
	read := func() *UpdateGroupProgress {
		t.Helper()
		p, err := f.store.UpdatePlanGroupProgress(ctx, "operator", f.permissions, f.scope, f.plan.ID, receipt.ID)
		require.NoError(t, err)
		require.Len(t, p.Devices, 1)
		return p
	}
	p := read()
	require.Equal(t, 1, p.Counts.Unverified)
	require.Equal(t, "before_assignment", p.Devices[0].Reason)
	require.Equal(t, "matches", p.Devices[0].PolicyState)
	// An acknowledged DDM notification alone cannot establish installation.
	drainCommands(t, f.store, f.device, nil)
	p = read()
	require.Equal(t, 1, p.Counts.Unverified)
	require.Equal(t, "acknowledged", p.Devices[0].NotificationStatus)
	report := func(fields map[string]any) {
		t.Helper()
		payload, err := json.Marshal(StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": fields}}})
		require.NoError(t, err)
		_, err = f.store.DeclarativeManagement(ctx, f.device, map[string]any{"UDID": f.device.UDID, "Endpoint": "status", "Data": payload})
		require.NoError(t, err)
	}
	report(map[string]any{"version": "18.7.1"})
	p = read()
	require.Equal(t, "missing_build", p.Devices[0].Reason)
	require.Zero(t, p.Counts.TargetReported)
	report(map[string]any{"version": "18.7.1", "build-version": "22H100"})
	p = read()
	require.Equal(t, 1, p.Counts.TargetReported)
	require.Equal(t, 1, p.Counts.PolicyMatches)
	require.Empty(t, p.Devices[0].Reason)
	definition := f.plan.Definition
	definition.Name = "Later plan"
	definition.Archived = true
	_, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	groupDefinition := f.group.DeviceGroupDefinition
	groupDefinition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, f.store.db, f.permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, f.group.ID, f.group.Revision, groupDefinition)
	require.NoError(t, err)
	second, _ := testEnroll(t, f.store, f.scope, "Owned later cohort member")
	drainCommands(t, f.store, second, nil)
	current := f.plan.Definition.Policy()
	current.Deadline = "2026-11-01T18:00:00"
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &current, "operator", f.permissions))
	p = read()
	require.Equal(t, 1, p.Counts.Total)
	require.Equal(t, 1, p.Counts.PolicyDifferent)
	require.Equal(t, 1, p.Counts.TargetReported)
	require.Equal(t, f.plan.Definition, p.Assignment.Plan.Definition)
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions))
	p = read()
	require.Equal(t, 1, p.Counts.PolicyAbsent)
	require.Equal(t, 1, p.Counts.TargetReported)
	for _, value := range []any{p, p.Counts, p.Devices[0]} {
		data, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(data))
		require.NotContains(t, fmt.Sprintf("%#v", value), f.device.ID)
	}
}

func TestUpdateGroupProgressScopeFreshnessAndAuditBoundaries(t *testing.T) {
	for _, condition := range []string{"moved", "revoked", "expired-identity", "stale", "future", "missing", "higher-version", "wrong-build", "required", "policy-error", "oversized-policy", "audit"} {
		t.Run(condition, func(t *testing.T) {
			f := ownedUpdateScheduleFixture(t)
			ctx := t.Context()
			receipt, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, 1, f.group.ID, f.group.Revision, uuid.NewString(), f.selection)
			require.NoError(t, err)
			require.NoError(t, f.store.saveStatus(ctx, f.device, &StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": map[string]any{"version": "18.7.1", "build-version": "22H100"}}}}))
			var query string
			switch condition {
			case "moved":
				query = `UPDATE mdm_apple_devices SET site_id=2,name='Other site protected name' WHERE id=$1`
			case "revoked":
				query = `UPDATE mdm_apple_devices SET status='revoked' WHERE id=$1`
			case "expired-identity":
				query = `UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE id=$1`
			case "stale":
				query = `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()-INTERVAL '25 hours' WHERE device_id=$1`
			case "future":
				query = `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()+INTERVAL '1 hour' WHERE device_id=$1`
			case "missing":
				query = `DELETE FROM mdm_apple_os_observations WHERE device_id=$1`
			case "higher-version":
				query = `UPDATE mdm_apple_os_observations SET version='19.0',build='' WHERE device_id=$1`
			case "wrong-build":
				query = `UPDATE mdm_apple_os_observations SET build='22H99' WHERE device_id=$1`
			case "required":
				query = `UPDATE mdm_apple_os_observations SET version='18.6.2',build='22G100' WHERE device_id=$1`
			case "policy-error":
				query = `UPDATE mdm_apple_update_policies SET status='failed',error='Protected device failure details' WHERE device_id=$1`
			case "oversized-policy":
				query = `UPDATE mdm_apple_update_policies SET details_url=repeat('x',8193) WHERE device_id=$1`
			case "audit":
				_, err = f.store.db.Exec(`CREATE FUNCTION owned_group_progress_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.progress' THEN RAISE EXCEPTION 'owned progress audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_group_progress_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_group_progress_audit_failure()`)
				require.NoError(t, err)
			}
			if query != "" {
				_, err = f.store.db.Exec(query, f.device.ID)
				require.NoError(t, err)
			}
			p, err := f.store.UpdatePlanGroupProgress(ctx, "operator", f.permissions, f.scope, f.plan.ID, receipt.ID)
			if condition == "oversized-policy" || condition == "audit" {
				require.Error(t, err)
				require.Nil(t, p)
				return
			}
			require.NoError(t, err)
			require.Len(t, p.Devices, 1)
			switch condition {
			case "moved":
				require.Equal(t, 1, p.Counts.Unavailable)
				require.Empty(t, p.Devices[0].Name)
				require.Nil(t, p.Devices[0].CurrentPolicy)
				require.Empty(t, p.Devices[0].ReportedVersion)
			case "revoked", "expired-identity":
				require.Equal(t, 1, p.Counts.Unavailable)
				require.Equal(t, 1, p.Counts.Unverified)
			case "stale", "future", "missing":
				require.Equal(t, 1, p.Counts.Unverified)
			case "higher-version":
				require.Equal(t, 1, p.Counts.TargetReported)
			case "wrong-build", "required":
				require.Equal(t, 1, p.Counts.UpdateRequired)
			case "policy-error":
				require.Equal(t, 1, p.Counts.PolicyAttention)
				require.Equal(t, 1, p.Counts.TargetReported)
				require.Empty(t, p.Devices[0].CurrentPolicy.Error)
			}
		})
	}
}

func TestUpdateGroupProgressUsesCurrentAuthorityAndOriginalScope(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	receipt, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, 1, f.group.ID, f.group.Revision, uuid.NewString(), f.selection)
	require.NoError(t, err)
	for _, actor := range []string{"viewer", "missing"} {
		p, err := f.store.UpdatePlanGroupProgress(ctx, actor, f.permissions, f.scope, f.plan.ID, receipt.ID)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, p)
	}
	p, err := f.store.UpdatePlanGroupProgress(ctx, "admin", nil, f.scope, f.plan.ID, receipt.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, p)
	_, err = f.store.UpdatePlanGroupProgress(ctx, "admin", f.permissions, Scope{TenantID: 2, SiteID: 2}, f.plan.ID, receipt.ID)
	require.Error(t, err)
	_, err = f.store.UpdatePlanGroupProgress(ctx, "admin", f.permissions, f.scope, uuid.NewString(), receipt.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestUpdateGroupResultAssessesCompleteBuildAndExplicitObservationTime(t *testing.T) {
	now := time.Now().UTC()
	admitted := now.Add(-48 * time.Hour)
	old := now.Add(-25 * time.Hour)
	d := UpdateGroupDeviceProgress{Availability: "available", ReportedVersion: "18.7.1", ReportedBuild: "22H100", RecordedAt: &old}
	assessUpdateGroupResult(&d, UpdatePlan{Definition: ownedUpdatePlanDefinition()}, admitted, now)
	require.Equal(t, "stale_report", d.Reason)
}
