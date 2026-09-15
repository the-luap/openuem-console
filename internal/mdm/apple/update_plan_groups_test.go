package apple

import (
	"encoding/json"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdatePlanGroupPreviewPreservesPoliciesAndCapturesConfiguredState(t *testing.T) {
	s, permissions, _, d, group := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	sources := inventory.DeviceSources{Apple: true}
	plan, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, ownedUpdatePlanDefinition())
	require.NoError(t, err)
	chosen, err := s.UpdatePlanForGroup(ctx, "operator", permissions, scope, plan.ID, plan.Revision)
	require.NoError(t, err)
	require.Equal(t, plan.Definition, chosen.Definition)
	_, err = s.UpdatePlanForGroup(ctx, "viewer", permissions, scope, plan.ID, plan.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.UpdatePlanForGroup(ctx, "operator", permissions, scope, plan.ID, plan.Revision+1)
	require.ErrorIs(t, err, ErrConflict)
	preview, err := s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	require.Len(t, preview.Excluded, 1)
	require.Equal(t, d.ID, preview.Targets[0].Selection.DeviceID)
	require.Nil(t, preview.Targets[0].CurrentPolicy)
	emptyToken := preview.Targets[0].Selection.PolicyToken
	require.Equal(t, 64, len(emptyToken))
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement' AND status='queued'`).Scan(&count))
	require.Zero(t, count)
	policy := plan.Definition.Policy()
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, scope, []string{d.ID}, &policy, "operator", permissions))
	preview, err = s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	require.NotEqual(t, emptyToken, preview.Targets[0].Selection.PolicyToken)
	require.Equal(t, policy.TargetVersion, preview.Targets[0].CurrentPolicy.TargetVersion)
	configuredToken := preview.Targets[0].Selection.PolicyToken
	_, err = s.db.Exec(`UPDATE mdm_apple_update_policies SET status='downloading',error='owned observation',updated_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	require.NoError(t, err)
	preview, err = s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.NoError(t, err)
	require.Equal(t, configuredToken, preview.Targets[0].Selection.PolicyToken)
	_, err = s.db.Exec(`UPDATE mdm_apple_update_policies SET deadline='2026-11-01T18:00:00' WHERE device_id=$1`, d.ID)
	require.NoError(t, err)
	preview, err = s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.NoError(t, err)
	require.NotEqual(t, configuredToken, preview.Targets[0].Selection.PolicyToken)
	for _, protected := range []any{preview, preview.Targets[0], preview.Targets[0].Selection} {
		encoded, err := json.Marshal(protected)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(encoded))
	}
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement' AND status='queued'`).Scan(&count))
	require.Equal(t, 1, count)
	_, err = s.PreviewUpdatePlanGroup(ctx, "viewer", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision+1, group.ID, group.Revision)
	require.ErrorIs(t, err, ErrConflict)
	definition := plan.Definition
	definition.Archived = true
	plan, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, plan.ID, plan.Revision, definition)
	require.NoError(t, err)
	_, err = s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.ErrorIs(t, err, ErrConflict)
}

func TestUpdatePlanGroupPreviewExclusionsAndFailedReadAudit(t *testing.T) {
	for _, condition := range []string{"platform", "prerequisite", "release", "catalog-unavailable", "catalog-integrity", "audit", "member-limit"} {
		t.Run(condition, func(t *testing.T) {
			s, permissions, _, d, group := profileGroupFixture(t)
			ctx := t.Context()
			scope := Scope{TenantID: 1, SiteID: 1}
			definition := ownedUpdatePlanDefinition()
			if condition == "platform" {
				definition.Platform = "ipados"
			}
			if condition == "release" {
				definition.TargetVersion = "99.0"
				definition.TargetBuild = "99A1"
			}
			plan, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, definition)
			require.NoError(t, err)
			switch condition {
			case "prerequisite":
				_, err = s.db.Exec(`UPDATE mdm_apple_devices SET os_version='16.7' WHERE id=$1`, d.ID)
			case "catalog-unavailable":
				_, err = s.db.Exec(`UPDATE mdm_apple_software_catalog SET fetched_at=NULL`)
			case "catalog-integrity":
				_, err = s.db.Exec(`UPDATE mdm_apple_software_catalog SET document='"owned invalid catalog"'::jsonb`)
			case "audit":
				_, err = s.db.Exec(`CREATE FUNCTION owned_update_group_preview_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.preview' THEN RAISE EXCEPTION 'owned update group preview audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_update_group_preview_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_update_group_preview_audit_failure()`)
			case "member-limit":
				_, err = s.db.Exec(`INSERT INTO agents(oid,hostname,os,agent_status) SELECT 'owned-group-'||n,'Owned group member','windows','Enabled' FROM generate_series(1,100) n; INSERT INTO site_agents(agent_id,site_id) SELECT oid,1 FROM agents WHERE oid LIKE 'owned-group-%'`)
			}
			require.NoError(t, err)
			preview, err := s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, inventory.DeviceSources{Apple: true}, plan.ID, plan.Revision, group.ID, group.Revision)
			switch condition {
			case "catalog-integrity":
				require.ErrorIs(t, err, ErrUpdatePlanGroupIntegrity)
				require.Nil(t, preview)
			case "audit":
				require.Error(t, err)
				require.Nil(t, preview)
			case "member-limit":
				require.ErrorIs(t, err, inventory.ErrGroupSnapshotLarge)
				require.Nil(t, preview)
			default:
				require.NoError(t, err)
				require.Empty(t, preview.Targets)
				require.Len(t, preview.Excluded, 2)
				reason := map[string]string{"platform": "different_platform", "prerequisite": "update_prerequisite", "release": "release_unavailable", "catalog-unavailable": "release_unavailable"}[condition]
				require.Equal(t, reason, preview.Excluded[1].Reason)
			}
			var count int
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestUpdatePolicyGroupTokenBindsScopeAndEveryConfiguredValue(t *testing.T) {
	scope := Scope{TenantID: 1, SiteID: 1}
	p := ownedUpdatePlanDefinition().Policy()
	id := "10000000-0000-0000-0000-000000000001"
	original := updatePolicyGroupToken(scope, id, &p)
	require.NotEqual(t, original, updatePolicyGroupToken(Scope{TenantID: 2, SiteID: 1}, id, &p))
	require.NotEqual(t, original, updatePolicyGroupToken(Scope{TenantID: 1, SiteID: 2}, id, &p))
	require.NotEqual(t, original, updatePolicyGroupToken(scope, "10000000-0000-0000-0000-000000000002", &p))
	for _, field := range []string{"version", "build", "deadline", "url"} {
		copy := p
		switch field {
		case "version":
			copy.TargetVersion = "18.8"
		case "build":
			copy.TargetBuild = "22I1"
		case "deadline":
			copy.Deadline = "2026-11-01T18:00:00"
		case "url":
			copy.DetailsURL = "https://example.test/changed"
		}
		require.NotEqual(t, original, updatePolicyGroupToken(scope, id, &copy))
	}
	p.Status = "downloading"
	p.Error = "owned status error"
	require.Equal(t, original, updatePolicyGroupToken(scope, id, &p))
}
