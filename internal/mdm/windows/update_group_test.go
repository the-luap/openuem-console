package windows

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

// The protocol fixture uses a small shared-console schema. Add the inventory
// projection tables and the real group migration; registered route tests use
// the complete Ent schema and all inventory migrations.
func updateGroupFixture(t *testing.T) (syncMLStoreFixture, *inventory.DeviceGroup) {
	t.Helper()
	f := syncMLTestStore(t)
	ctx := t.Context()
	_, err := f.store.db.Exec(`CREATE TABLE agents(oid TEXT PRIMARY KEY,nickname TEXT,hostname TEXT,os TEXT,agent_status TEXT,last_contact TIMESTAMPTZ);
 CREATE TABLE site_agents(agent_id TEXT,site_id BIGINT);
 CREATE TABLE computers(agent_computer TEXT,serial TEXT,model TEXT);
 CREATE TABLE operating_systems(agent_operatingsystem TEXT,version TEXT);
 INSERT INTO agents VALUES('owned-desktop','','Owned desktop','windows','Enabled',clock_timestamp());
 INSERT INTO site_agents VALUES('owned-desktop',11)`)
	require.NoError(t, err)
	migration, err := os.ReadFile("../../inventory/migrations/009_device_groups.sql")
	require.NoError(t, err)
	_, err = f.store.db.Exec(string(migration))
	require.NoError(t, err)
	audits, err := audit.NewStore(f.store.db, f.store.permissions)
	require.NoError(t, err)
	require.NoError(t, audits.Migrate(ctx))
	group, err := inventory.SaveDeviceGroup(ctx, f.store.db, f.store.permissions, "operator", f.identity.Scope, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <pilot group>", Rule: inventory.DeviceGroupRule{Platform: "windows"}})
	require.NoError(t, err)
	return f, group
}

func TestUpdateGroupAdmissionReplayAndDeliveryProvenance(t *testing.T) {
	f, group := updateGroupFixture(t)
	ctx := t.Context()
	sources := inventory.DeviceSources{Windows: true}
	preview, err := f.store.PreviewUpdateGroup(ctx, "operator", f.identity.Scope, sources, group.ID, 1)
	require.NoError(t, err)
	for _, protected := range []any{preview, preview.Source} {
		encoded, err := json.Marshal(protected)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(encoded))
	}
	require.Equal(t, []string{f.identity.DeviceID}, preview.Targets)
	require.Len(t, preview.Excluded, 1)
	require.Equal(t, "owned-desktop", preview.Excluded[0].ID)
	ring := updateTestRing(t, f, updateTestFullPolicy())
	key := uuid.NewString()
	assign := func(request string, targets []string) (*UpdateRollout, error) {
		return f.store.AssignUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, request, targets, false, time.Hour, sources, group.ID, 1)
	}
	rollout, err := assign(key, preview.Targets)
	require.NoError(t, err)
	require.Equal(t, group.Name, rollout.Group.Name)
	require.Len(t, rollout.Runs, 1)
	revised := group.DeviceGroupDefinition
	revised.Name = "Changed group"
	revised.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, f.store.db, f.store.permissions, "operator", f.identity.Scope, group.ID, 1, revised)
	require.NoError(t, err)
	replay, err := assign(key, preview.Targets)
	require.NoError(t, err)
	require.Equal(t, rollout.ID, replay.ID)
	require.Equal(t, group.Name, replay.Group.Name)
	_, err = assign(uuid.NewString(), preview.Targets)
	require.ErrorIs(t, err, ErrUpdateGroupConflict)
	_, err = f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, preview.Targets, false, time.Hour)
	require.ErrorIs(t, err, ErrUpdateRingConflict)
	read, err := f.store.UpdateRolloutDetails(ctx, "operator", f.identity.Scope, rollout.ID)
	require.NoError(t, err)
	require.Equal(t, group.Name, read.Group.Name)
	encoded, err := json.Marshal(read)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), group.Name)
	var stored string
	require.NoError(t, f.store.db.QueryRow(`SELECT row_to_json(r)::text FROM mdm_windows_update_rollouts r WHERE id=$1`, rollout.ID).Scan(&stored))
	require.NotContains(t, stored, group.Name)
	// Group changes cannot rewrite already admitted source intent or delivery.
	_, response := cspTestStart(t, f)
	for range 7 {
		request := syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), ring.Policy, false, false))
		response, err = f.process(request)
		require.NoError(t, err)
	}
	require.Equal(t, "verified", updateTestRead(t, f, rollout.Runs[0].ID).Phase)
}

func TestUpdateGroupMembershipChangesAndAuditRollback(t *testing.T) {
	f, group := updateGroupFixture(t)
	ctx := t.Context()
	sources := inventory.DeviceSources{Windows: true}
	ring := updateTestRing(t, f, updateTestPolicy())
	preview, err := f.store.PreviewUpdateGroup(ctx, "operator", f.identity.Scope, sources, group.ID, 1)
	require.NoError(t, err)
	_, enrollment, _ := managementTestEnrollment(t, f.store, f.options)
	second := syncMLTestEnrolled(t, f.store, enrollment, f.options)
	_, err = f.store.AssignUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), preview.Targets, false, time.Hour, sources, group.ID, 1)
	require.ErrorIs(t, err, ErrUpdateGroupConflict)
	preview, err = f.store.PreviewUpdateGroup(ctx, "operator", f.identity.Scope, sources, group.ID, 1)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 2)
	require.Contains(t, preview.Targets, second.identity.DeviceID)
	for _, table := range []string{"mdm_windows_update_rollouts", "mdm_windows_update_runs", "mdm_windows_csp_commands"} {
		var n int
		require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
		require.Zero(t, n)
	}
	_, err = f.store.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_group_read_failure CHECK(action<>'inventory.groups.read') NOT VALID`)
	require.NoError(t, err)
	got, err := f.store.PreviewUpdateGroup(ctx, "operator", f.identity.Scope, sources, group.ID, 1)
	require.Error(t, err)
	require.Nil(t, got)
	rollout, err := f.store.AssignUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), preview.Targets, false, time.Hour, sources, group.ID, 1)
	require.Error(t, err)
	require.Nil(t, rollout)
	_, err = f.store.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_group_read_failure`)
	require.NoError(t, err)
	_, err = f.store.PreviewUpdateGroup(ctx, "viewer", f.identity.Scope, sources, group.ID, 1)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.PreviewUpdateGroup(ctx, "admin", access.Scope{TenantID: 1, SiteID: 12}, sources, group.ID, 1)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, f.store.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil))
	_, err = f.store.AssignUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), preview.Targets, false, time.Hour, sources, group.ID, 1)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestUpdateGroupSnapshotCapacityAndSourceAuthentication(t *testing.T) {
	f, group := updateGroupFixture(t)
	ctx := t.Context()
	sources := inventory.DeviceSources{Windows: true}
	_, err := f.store.db.Exec(`INSERT INTO agents(oid,nickname,hostname,os,agent_status) SELECT 'owned-extra-'||i::text,'','Owned extra','windows','Enabled' FROM generate_series(1,98) i;
 INSERT INTO site_agents SELECT oid,11 FROM agents WHERE oid LIKE 'owned-extra-%'`)
	require.NoError(t, err)
	preview, err := f.store.PreviewUpdateGroup(ctx, "operator", f.identity.Scope, sources, group.ID, 1)
	require.NoError(t, err)
	require.Len(t, preview.Excluded, 99)
	_, err = f.store.db.Exec(`INSERT INTO agents VALUES('owned-over','','Owned excess','windows','Enabled',NULL);INSERT INTO site_agents VALUES('owned-over',11)`)
	require.NoError(t, err)
	_, err = f.store.PreviewUpdateGroup(ctx, "operator", f.identity.Scope, sources, group.ID, 1)
	require.ErrorIs(t, err, ErrUpdateGroupLarge)
	_, err = f.store.db.Exec(`DELETE FROM site_agents WHERE agent_id='owned-over';DELETE FROM agents WHERE oid='owned-over'`)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`UPDATE agents SET hostname=$1 WHERE oid='owned-desktop'`, strings.Repeat("x", 4097))
	require.NoError(t, err)
	_, err = f.store.PreviewUpdateGroup(ctx, "operator", f.identity.Scope, sources, group.ID, 1)
	require.ErrorIs(t, err, ErrUpdateGroupLarge)
}

func TestUpdateGroupSourceRejectsInvalidProtectedVersions(t *testing.T) {
	f, group := updateGroupFixture(t)
	ctx := t.Context()
	sources := inventory.DeviceSources{Windows: true}
	ring := updateTestRing(t, f, updateTestPolicy())
	rollout, err := f.store.AssignUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, time.Hour, sources, group.ID, 1)
	require.NoError(t, err)
	for _, mode := range []string{"legacy-with-group", "missing-group", "invalid-revision", "ciphertext"} {
		stored, err := scanUpdateRollout(f.store.db.QueryRow(`SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE id=$1`, rollout.ID))
		require.NoError(t, err)
		source := sealUpdateGroupSource(rollout.Group)
		intent := updateRolloutTargets{Version: 2, Group: source, Devices: []string{f.identity.DeviceID}}
		switch mode {
		case "legacy-with-group":
			intent.Version = 1
		case "missing-group":
			intent.Group = nil
		case "invalid-revision":
			intent.Group.Revision = 0
		}
		plain, err := json.Marshal(intent)
		require.NoError(t, err)
		stored.encrypted, err = f.store.secrets.sealBounded(plain, updateRolloutPurpose(stored), 8192)
		require.NoError(t, err)
		if mode == "ciphertext" {
			stored.encrypted[len(stored.encrypted)-1] ^= 1
		}
		require.Error(t, f.store.openUpdateRollout(stored), mode)
	}
}
