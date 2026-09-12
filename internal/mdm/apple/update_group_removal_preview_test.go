package apple

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedUpdateRemovalFixture(t *testing.T) (updateScheduleFixture, *UpdatePlanGroupAssignment) {
	t.Helper()
	f := ownedUpdateScheduleFixture(t)
	r, err := f.store.AssignUpdatePlanFromGroup(t.Context(), "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection)
	require.NoError(t, err)
	return f, r
}

func TestUpdateGroupRemovalPreviewRetainsOriginalTargetsWithoutDeviceWork(t *testing.T) {
	f, r := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	definition := f.plan.Definition
	definition.Archived = true
	_, err := f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	group := f.group.DeviceGroupDefinition
	group.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, f.store.db, f.permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, f.group.ID, f.group.Revision, group)
	require.NoError(t, err)
	other, _ := testEnroll(t, f.store, f.scope, f.device.Name)
	drainCommands(t, f.store, other, nil)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_software_catalog SET document='{}',fetched_at=NULL WHERE singleton=true`)
	require.NoError(t, err)
	var before, after int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands`).Scan(&before))
	p, err := f.store.PreviewUpdateGroupRemoval(ctx, "operator", f.permissions, f.scope, f.plan.ID, r.ID)
	require.NoError(t, err)
	require.Len(t, p.Devices, 1)
	require.Equal(t, r.ID, p.Assignment.ID)
	require.Equal(t, f.device.ID, p.Devices[0].Selection.DeviceID)
	require.Empty(t, p.Devices[0].Reason)
	require.True(t, p.Devices[0].NotificationAvailable)
	require.Len(t, updateGroupRemovalSelection(p), 1)
	require.Equal(t, updateGroupRemovalToken(f.scope, f.device.ID, p.Devices[0].CurrentPolicy, true), p.Devices[0].Selection.PolicyToken)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands`).Scan(&after))
	require.Equal(t, before, after)
	for _, value := range []any{p, p.Devices[0]} {
		body, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(body))
		require.NotContains(t, fmt.Sprintf("%#v", value), f.device.ID)
	}
}

func TestUpdateGroupRemovalPreviewExclusionsAndBoundedSources(t *testing.T) {
	for _, condition := range []string{"different", "absent", "revoked", "expired", "moved", "unsupported", "large-metadata", "large-status-error", "large-policy", "audit", "moved-site"} {
		t.Run(condition, func(t *testing.T) {
			f, r := ownedUpdateRemovalFixture(t)
			ctx := t.Context()
			var query, reason string
			switch condition {
			case "different":
				query, reason = `UPDATE mdm_apple_update_policies SET deadline='2026-11-01T18:00:00' WHERE device_id=$1`, "different"
			case "absent":
				query, reason = `DELETE FROM mdm_apple_update_policies WHERE device_id=$1`, "absent"
			case "revoked":
				query, reason = `UPDATE mdm_apple_devices SET status='revoked' WHERE id=$1`, "not_managed"
			case "expired":
				query, reason = `UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, "identity_expired"
			case "moved":
				query, reason = `UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`, "unavailable"
			case "unsupported":
				query = `UPDATE mdm_apple_devices SET os_version='14.0' WHERE id=$1`
			case "large-metadata":
				query = `UPDATE mdm_apple_devices SET name=repeat('N',2048),inventory=jsonb_build_object('owned',repeat('X',1048576)) WHERE id=$1`
			case "large-status-error":
				query = `UPDATE mdm_apple_update_policies SET status=repeat('S',8193),error=repeat('E',8193) WHERE device_id=$1`
			case "large-policy":
				query = `UPDATE mdm_apple_update_policies SET details_url=repeat('X',8193) WHERE device_id=$1`
			case "audit":
				_, err := f.store.db.Exec(`CREATE FUNCTION owned_removal_preview_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.removal.preview' THEN RAISE EXCEPTION 'owned removal preview audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_removal_preview_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_removal_preview_audit_failure()`)
				require.NoError(t, err)
			case "moved-site":
				_, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
				require.NoError(t, err)
			}
			if query != "" {
				_, err := f.store.db.Exec(query, f.device.ID)
				require.NoError(t, err)
			}
			p, err := f.store.PreviewUpdateGroupRemoval(ctx, "operator", f.permissions, f.scope, f.plan.ID, r.ID)
			if condition == "large-policy" || condition == "audit" || condition == "moved-site" {
				require.Error(t, err)
				require.Nil(t, p)
				return
			}
			require.NoError(t, err)
			require.Len(t, p.Devices, 1)
			d := p.Devices[0]
			require.Equal(t, reason, d.Reason)
			if reason != "" {
				require.Empty(t, updateGroupRemovalSelection(p))
				require.Empty(t, d.Selection.PolicyToken)
			}
			if condition == "moved" {
				require.Empty(t, d.Name)
				require.Nil(t, d.CurrentPolicy)
				require.Nil(t, d.device)
			}
			if condition == "unsupported" {
				require.Len(t, updateGroupRemovalSelection(p), 1)
				require.False(t, d.NotificationAvailable)
			}
			if condition == "large-metadata" {
				require.Empty(t, d.Name)
				require.Nil(t, d.device.Inventory)
			}
			if condition == "large-status-error" {
				require.Empty(t, d.CurrentPolicy.Status)
				require.Empty(t, d.CurrentPolicy.Error)
			}
		})
	}
}

func TestUpdateGroupRemovalPreviewRequiresCurrentReadAndUpdateAuthority(t *testing.T) {
	f, r := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	for _, scope := range []Scope{{TenantID: 1}, {TenantID: 2, SiteID: 2}} {
		_, err := f.store.PreviewUpdateGroupRemoval(ctx, "operator", f.permissions, scope, f.plan.ID, r.ID)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	_, err := f.store.PreviewUpdateGroupRemoval(ctx, "viewer", f.permissions, f.scope, f.plan.ID, r.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.PreviewUpdateGroupRemoval(ctx, "admin", nil, f.scope, f.plan.ID, r.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil))
	_, err = f.store.PreviewUpdateGroupRemoval(ctx, "operator", f.permissions, f.scope, f.plan.ID, r.ID)
	require.ErrorIs(t, err, access.ErrDenied)
}
