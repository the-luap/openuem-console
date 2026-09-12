package apple

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func updateGroupSelection(preview *UpdatePlanGroupPreview) []UpdatePlanGroupSelection {
	selected := make([]UpdatePlanGroupSelection, len(preview.Targets))
	for i, target := range preview.Targets {
		selected[i] = target.Selection
	}
	return selected
}
func TestUpdateGroupConcurrentReplayAndProtocolEvidence(t *testing.T) {
	s, permissions, _, d, group := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	sources := inventory.DeviceSources{Apple: true}
	plan, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, ownedUpdatePlanDefinition())
	require.NoError(t, err)
	preview, err := s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.NoError(t, err)
	selected := updateGroupSelection(preview)
	request := uuid.NewString()
	var wg sync.WaitGroup
	results := make(chan *UpdatePlanGroupAssignment, 2)
	failures := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.AssignUpdatePlanFromGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision, request, selected)
			results <- r
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
	first, second := <-results, <-results
	require.Equal(t, first.ID, second.ID)
	require.Len(t, first.Commands, 1)
	require.Equal(t, selected[0], first.Commands[0].Selection)
	drainCommands(t, s, d, nil)
	response, err := s.DeclarativeManagement(ctx, d, map[string]any{"UDID": d.UDID, "Endpoint": "declaration/configuration/eu.openuem.apple." + d.ID + ".update"})
	require.NoError(t, err)
	declaration := response.(Declaration)
	require.Equal(t, plan.Definition.TargetVersion, declaration.Payload["TargetOSVersion"])
	require.Equal(t, plan.Definition.TargetBuild, declaration.Payload["TargetBuildVersion"])
	require.Equal(t, plan.Definition.Deadline, declaration.Payload["TargetLocalDateTime"])
	report, err := json.Marshal(StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": map[string]any{"version": plan.Definition.TargetVersion, "build-version": plan.Definition.TargetBuild}}}})
	require.NoError(t, err)
	_, err = s.DeclarativeManagement(ctx, d, map[string]any{"UDID": d.UDID, "Endpoint": "status", "Data": report})
	require.NoError(t, err)
	currentDevice, err := s.Device(ctx, scope, d.ID)
	require.NoError(t, err)
	currentPolicy, err := s.UpdatePolicy(ctx, scope, d.ID)
	require.NoError(t, err)
	require.Equal(t, "compliant", UpdateCompliance(*currentDevice, *currentPolicy, time.Now()))
	groupDefinition := group.DeviceGroupDefinition
	groupDefinition.Name = "Later group"
	groupDefinition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, s.db, permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, group.ID, group.Revision, groupDefinition)
	require.NoError(t, err)
	planDefinition := plan.Definition
	planDefinition.Name = "Later plan"
	planDefinition.Archived = true
	_, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, plan.ID, plan.Revision, planDefinition)
	require.NoError(t, err)
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, scope, []string{d.ID}, nil, "operator", permissions))
	var before, after, count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, d.ID).Scan(&before))
	replay, err := s.AssignUpdatePlanFromGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision, request, selected)
	require.NoError(t, err)
	require.Equal(t, first.ID, replay.ID)
	require.Equal(t, plan.Definition, replay.Plan.Definition)
	require.Equal(t, group.Name, replay.Group.Name)
	_, err = s.UpdatePolicy(ctx, scope, d.ID)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, d.ID).Scan(&after))
	require.Equal(t, before, after)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_group_assignments`).Scan(&count))
	require.Equal(t, 1, count)
	for _, protected := range []any{replay, replay.Commands[0]} {
		data, err := json.Marshal(protected)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(data))
	}
	_, err = s.UpdatePlanGroupAssignmentDetails(ctx, "viewer", permissions, scope, plan.ID, first.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	detail, err := s.UpdatePlanGroupAssignmentDetails(ctx, "operator", permissions, scope, plan.ID, first.ID)
	require.NoError(t, err)
	require.Equal(t, plan.Definition, detail.Plan.Definition)
	require.NoError(t, permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err = s.AssignUpdatePlanFromGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision, request, selected)
	require.ErrorIs(t, err, ErrConflict)
}

func TestUpdateGroupChangedInputsAndLateAuditRollback(t *testing.T) {
	for _, condition := range []string{"policy", "members", "group", "plan", "audit"} {
		t.Run(condition, func(t *testing.T) {
			s, permissions, _, d, group := profileGroupFixture(t)
			ctx := t.Context()
			scope := Scope{TenantID: 1, SiteID: 1}
			sources := inventory.DeviceSources{Apple: true}
			plan, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, ownedUpdatePlanDefinition())
			require.NoError(t, err)
			preview, err := s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
			require.NoError(t, err)
			switch condition {
			case "policy":
				policy := plan.Definition.Policy()
				require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, scope, []string{d.ID}, &policy, "operator", permissions))
			case "members":
				second, _ := testEnroll(t, s, scope, "Owned additional update target")
				drainCommands(t, s, second, nil)
			case "group":
				definition := group.DeviceGroupDefinition
				definition.Name = "Changed group"
				_, err = inventory.SaveDeviceGroup(ctx, s.db, permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, group.ID, group.Revision, definition)
				require.NoError(t, err)
			case "plan":
				definition := plan.Definition
				definition.Deadline = "2026-11-01T18:00:00"
				_, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, plan.ID, plan.Revision, definition)
				require.NoError(t, err)
			case "audit":
				_, err = s.db.Exec(`CREATE FUNCTION owned_update_group_created_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.created' THEN RAISE EXCEPTION 'owned update group created audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_update_group_created_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_update_group_created_failure()`)
				require.NoError(t, err)
			}
			var before, after int
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement'`).Scan(&before))
			r, err := s.AssignUpdatePlanFromGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision, uuid.NewString(), updateGroupSelection(preview))
			require.Error(t, err)
			require.Nil(t, r)
			if condition != "audit" {
				if condition == "group" {
					require.ErrorIs(t, err, inventory.ErrGroupConflict)
				} else {
					require.ErrorIs(t, err, ErrConflict)
				}
			}
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement'`).Scan(&after))
			require.Equal(t, before, after)
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_group_assignments`).Scan(&after))
			require.Zero(t, after)
			if condition != "policy" {
				require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies`).Scan(&after))
				require.Zero(t, after)
			}
		})
	}
}

func TestUpdateGroupHistoryAndCiphertextBinding(t *testing.T) {
	s, permissions, _, d, group := profileGroupFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	sources := inventory.DeviceSources{Apple: true}
	plan, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, ownedUpdatePlanDefinition())
	require.NoError(t, err)
	policy := plan.Definition.Policy()
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, scope, []string{d.ID}, &policy, "operator", permissions))
	preview, err := s.PreviewUpdatePlanGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision)
	require.NoError(t, err)
	var receipt *UpdatePlanGroupAssignment
	for i := 0; i < 26; i++ {
		receipt, err = s.AssignUpdatePlanFromGroup(ctx, "operator", permissions, scope, sources, plan.ID, plan.Revision, group.ID, group.Revision, uuid.NewString(), updateGroupSelection(preview))
		require.NoError(t, err)
	}
	first, next, err := s.UpdatePlanGroupAssignments(ctx, "operator", permissions, scope, plan.ID, "")
	require.NoError(t, err)
	require.Len(t, first, 25)
	require.NotEmpty(t, next)
	last, next, err := s.UpdatePlanGroupAssignments(ctx, "operator", permissions, scope, plan.ID, next)
	require.NoError(t, err)
	require.Len(t, last, 1)
	require.Empty(t, next)
	_, _, err = s.UpdatePlanGroupAssignments(ctx, "operator", permissions, scope, plan.ID, uuid.NewString())
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.db.Exec(`UPDATE mdm_apple_update_group_assignments SET actor='viewer' WHERE id=$1`, receipt.ID)
	require.Error(t, err)
	_, err = s.db.Exec(`DELETE FROM mdm_apple_update_group_assignments WHERE id=$1`, receipt.ID)
	require.Error(t, err)
	substituted := uuid.NewString()
	_, err = s.db.Exec(`INSERT INTO mdm_apple_update_group_assignments(id,tenant_id,site_id,request_key,plan_id,plan_revision,actor,actor_revision,created_at,encrypted_intent) SELECT $1,tenant_id,site_id,$2,plan_id,plan_revision,actor,actor_revision,created_at,encrypted_intent FROM mdm_apple_update_group_assignments WHERE id=$3`, substituted, uuid.NewString(), receipt.ID)
	require.NoError(t, err)
	r, err := s.UpdatePlanGroupAssignmentDetails(ctx, "operator", permissions, scope, plan.ID, substituted)
	require.ErrorIs(t, err, ErrUpdatePlanGroupIntegrity)
	require.Nil(t, r)
}
