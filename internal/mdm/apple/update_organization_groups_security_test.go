package apple

import (
	"context"
	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestUpdateOrganizationGroupChangedReviewAndLateAuditRollback(t *testing.T) {
	for _, condition := range []string{"policy", "members", "group", "plan", "source-permission", "audit"} {
		t.Run(condition, func(t *testing.T) {
			f := ownedOrganizationUpdateFixture(t)
			s, ctx := f.store, t.Context()
			switch condition {
			case "policy":
				policy := f.plan.Definition.Policy()
				require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
			case "members":
				second, _ := testEnroll(t, s, f.scope, "Owned later organization member")
				drainCommands(t, s, second, nil)
			case "group":
				definition := f.group.DeviceGroupDefinition
				definition.Name = "Changed organization rule"
				_, err := inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "organization", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
				require.NoError(t, err)
			case "plan":
				definition := f.plan.Definition
				definition.Deadline = "2026-11-01T18:00:00"
				_, err := s.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
				require.NoError(t, err)
			case "source-permission":
				require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
			case "audit":
				_, err := s.db.Exec(`CREATE FUNCTION reject_organization_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.created' THEN RAISE EXCEPTION 'owned organization update audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_organization_update_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_organization_update_audit()`)
				require.NoError(t, err)
			}
			p0, a0, n0 := f.counts(t)
			result, err := s.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, 1, uuid.NewString(), f.selection)
			require.Error(t, err)
			require.Nil(t, result)
			switch condition {
			case "group":
				require.ErrorIs(t, err, inventory.ErrGroupConflict)
			case "source-permission":
				require.ErrorIs(t, err, access.ErrDenied)
			case "audit":
			default:
				require.ErrorIs(t, err, ErrConflict)
			}
			p, a, n := f.counts(t)
			require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
		})
	}
}

func TestUpdateOrganizationGroupKeepsSourceTargetAndAuthorityLockedThroughFinalAudit(t *testing.T) {
	f := ownedOrganizationUpdateFixture(t)
	s, permissions, scope, ctx := f.store, f.permissions, f.scope, t.Context()
	definition, group, d := f.group.DeviceGroupDefinition, f.group, f.device
	const gate = 673810056
	conn, err := s.db.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, gate)
	_, err = s.db.Exec(`CREATE SEQUENCE organization_update_audit_entered; CREATE FUNCTION gate_organization_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.created' THEN PERFORM nextval('organization_update_audit_entered'); PERFORM pg_advisory_xact_lock(673810056); END IF; RETURN NEW; END; $$; CREATE TRIGGER gate_organization_update_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION gate_organization_update_audit()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.AssignUpdatePlanFromOrganizationGroup(ctx, "organization", permissions, scope, f.sources, f.plan.ID, f.plan.Revision, group.ID, 1, uuid.NewString(), f.selection)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var entered bool
		err := s.db.QueryRow(`SELECT is_called FROM organization_update_audit_entered`).Scan(&entered)
		return err == nil && entered
	}, 3*time.Second, 10*time.Millisecond)
	for _, change := range []string{"group", "site", "device", "permission"} {
		t.Run(change, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			var err error
			switch change {
			case "group":
				definition.Archived = true
				_, err = inventory.SaveDeviceGroup(bounded, s.db, permissions, "organization", access.Scope{TenantID: 1}, group.ID, 1, definition)
			case "site":
				_, err = s.db.ExecContext(bounded, `UPDATE sites SET tenant_sites=2 WHERE id=1`)
			case "device":
				_, err = s.db.ExecContext(bounded, `UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`, d.ID)
			case "permission":
				err = permissions.ReplaceGrants(bounded, "admin", "organization", 1, nil)
			}
			require.Error(t, err)
		})
	}
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	require.NoError(t, err)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("organization assignment did not finish after audit release")
	}
	var assigned bool
	err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM mdm_apple_update_group_assignments WHERE plan_id=$1)`, f.plan.ID).Scan(&assigned)
	require.NoError(t, err)
	require.True(t, assigned)
	require.NoError(t, permissions.ReplaceGrants(ctx, "admin", "organization", 1, nil))
	// The source grant must still be required after the original admission.
	result, err := s.PreviewUpdatePlanOrganizationGroup(ctx, "organization", permissions, scope, f.sources, f.plan.ID, f.plan.Revision, group.ID, 1)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, result)
}
