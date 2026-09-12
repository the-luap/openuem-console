package apple

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	sharedaudit "github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func profileGroupFixture(t *testing.T) (*Store, *access.Store, *Profile, *Device, *inventory.DeviceGroup) {
	t.Helper()
	s, permissions, p, d := profileAssignmentAccessFixture(t)
	_, err := s.db.Exec(`CREATE TABLE agents(oid TEXT PRIMARY KEY,nickname TEXT,hostname TEXT,os TEXT,agent_status TEXT,last_contact TIMESTAMPTZ);
 CREATE TABLE site_agents(agent_id TEXT,site_id BIGINT);
 CREATE TABLE computers(agent_computer TEXT,serial TEXT,model TEXT);
 CREATE TABLE operating_systems(agent_operatingsystem TEXT,version TEXT);
 INSERT INTO agents VALUES('owned-desktop','','Owned desktop','windows','Enabled',clock_timestamp());
 INSERT INTO site_agents VALUES('owned-desktop',1)`)
	require.NoError(t, err)
	migration, err := os.ReadFile("../../inventory/migrations/009_device_groups.sql")
	require.NoError(t, err)
	_, err = s.db.Exec(string(migration))
	require.NoError(t, err)
	audits, err := sharedaudit.NewStore(s.db, permissions)
	require.NoError(t, err)
	require.NoError(t, audits.Migrate(t.Context()))
	group, err := inventory.SaveDeviceGroup(t.Context(), s.db, permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned Apple pilot"})
	require.NoError(t, err)
	return s, permissions, p, d, group
}

func TestProfileGroupPreviewPreservesCommandsAndReportsPrerequisites(t *testing.T) {
	s, permissions, p, d, group := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	sources := inventory.DeviceSources{Apple: true}
	preview, err := s.PreviewProfileGroup(ctx, "operator", permissions, scope, sources, p.ID, p.Revision, group.ID, group.Revision, "installed")
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	require.Equal(t, d.ID, preview.Targets[0].DeviceID)
	require.Len(t, preview.Excluded, 1)
	require.Equal(t, "not_apple_mdm", preview.Excluded[0].Reason)
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)
	for _, protected := range []any{preview, preview.Targets[0]} {
		encoded, err := json.Marshal(protected)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(encoded))
	}
	require.NoError(t, s.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, []string{d.ID}, "installed", "operator", permissions))
	for _, desired := range []string{"installed", "removed"} {
		preview, err = s.PreviewProfileGroup(ctx, "operator", permissions, scope, sources, p.ID, p.Revision, group.ID, group.Revision, desired)
		require.NoError(t, err)
		require.Len(t, preview.Targets, 1)
	}
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1 AND status='queued' AND request_type='InstallProfile'`, p.ID).Scan(&count))
	require.Equal(t, 1, count)
	assignments, err := s.Assignments(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Equal(t, "installed", assignments[0].Desired)
	macPolicy := saveSystemExtensionProfile(t, s, "com.example.group.mac", "listed", false)
	preview, err = s.PreviewProfileGroup(ctx, "operator", permissions, scope, sources, macPolicy.ID, macPolicy.Revision, group.ID, group.Revision, "installed")
	require.NoError(t, err)
	require.Empty(t, preview.Targets)
	require.Len(t, preview.Excluded, 2)
	require.Equal(t, "profile_prerequisite", preview.Excluded[1].Reason)
	_, err = s.PreviewProfileGroup(ctx, "viewer", permissions, scope, sources, p.ID, p.Revision, group.ID, group.Revision, "installed")
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.PreviewProfileGroup(ctx, "operator", permissions, scope, sources, p.ID, p.Revision+1, group.ID, group.Revision, "installed")
	require.ErrorIs(t, err, ErrConflict)
}

func TestProfileGroupPreviewDetectsMemberResourceConflictsWithoutClaims(t *testing.T) {
	s, permissions, _, _, group := profileGroupFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	second, _ := testEnroll(t, s, scope, "Owned second ACME target")
	drainCommands(t, s, second, nil)
	p := saveACMETemplate(t, s, "com.example.group.acme", "System", "owned-group-client")
	preview, err := s.PreviewProfileGroup(t.Context(), "operator", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, group.Revision, "installed")
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	require.Len(t, preview.Excluded, 2)
	require.Equal(t, "profile_prerequisite", preview.Excluded[1].Reason)
	for _, table := range []string{"mdm_apple_profile_assignments", "mdm_apple_acme_clients"} {
		var count int
		require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
		require.Zero(t, count)
	}
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)
	_, err = s.db.Exec(`CREATE FUNCTION owned_group_preview_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='apple.profile.group.preview' THEN RAISE EXCEPTION 'owned profile preview audit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER owned_group_preview_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_group_preview_audit_failure()`)
	require.NoError(t, err)
	preview, err = s.PreviewProfileGroup(t.Context(), "operator", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, group.Revision, "installed")
	require.Error(t, err)
	require.Nil(t, preview)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)
}

func TestProfileGroupPreviewResolvesCanonicalMacToCurrentNativeChannel(t *testing.T) {
	s, permissions, p, _, _ := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	r, err := registry.NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	require.NoError(t, err)
	require.NoError(t, r.Migrate(ctx))
	require.NoError(t, s.MigrateMacLinks(ctx))
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Owned linked group Mac", "Mac16,1", "15.0")
	drainMacHardwareInventory(t, s, d, map[string]any{"SerialNumber": "ABCD123456", "ProvisioningUDID": "00006001-001234567890ABCD"})
	agent := enrollMacAgent(t, r, registry.Scope{TenantID: 1, SiteID: 1})
	proof := deliverMacProof(t, s, d)
	recordMacProof(t, s, agent, proof)
	require.NoError(t, s.ReconcileMacLinks(ctx))
	macs, err := s.MacDevices(ctx, scope)
	require.NoError(t, err)
	require.Len(t, macs, 1)
	group, err := inventory.SaveDeviceGroup(ctx, s.db, permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned linked Macs", Rule: inventory.DeviceGroupRule{Platform: "macos"}})
	require.NoError(t, err)
	preview, err := s.PreviewProfileGroup(ctx, "operator", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, group.Revision, "installed")
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	require.Empty(t, preview.Excluded)
	require.Equal(t, d.ID, preview.Targets[0].DeviceID)
	require.Equal(t, "mac", preview.Targets[0].Entry.Kind)
	require.Equal(t, macs[0].ID, preview.Targets[0].Entry.ID)
	require.NotEqual(t, agent.ID, preview.Targets[0].DeviceID)
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)
	definition := group.DeviceGroupDefinition
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, group.ID, group.Revision, definition)
	require.NoError(t, err)
	preview, err = s.PreviewProfileGroup(ctx, "operator", permissions, scope, inventory.DeviceSources{Apple: true}, p.ID, p.Revision, group.ID, group.Revision, "installed")
	require.ErrorIs(t, err, inventory.ErrGroupConflict)
	require.Nil(t, preview)
}

func TestProfileGroupCatalogMetadataRequiresCurrentAuthorityAndAudit(t *testing.T) {
	s, permissions, p, _, _ := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	catalog, err := s.ProfileForGroup(ctx, "operator", permissions, scope, p.ID, p.Revision)
	require.NoError(t, err)
	require.Equal(t, p.Name, catalog.Name)
	encoded, err := json.Marshal(catalog)
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(encoded))
	_, err = s.ProfileForGroup(ctx, "viewer", permissions, scope, p.ID, p.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.ProfileForGroup(ctx, "operator", nil, scope, p.ID, p.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.ProfileForGroup(ctx, "operator", permissions, scope, p.ID, p.Revision+1)
	require.ErrorIs(t, err, ErrConflict)
	_, err = s.db.Exec(`CREATE FUNCTION reject_group_catalog_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.group.catalog' THEN RAISE EXCEPTION 'owned catalog audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_group_catalog_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_group_catalog_audit()`)
	require.NoError(t, err)
	catalog, err = s.ProfileForGroup(ctx, "operator", permissions, scope, p.ID, p.Revision)
	require.Error(t, err)
	require.Nil(t, catalog)
}
