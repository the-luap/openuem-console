package apple

import (
	"context"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdateOrganizationScheduleBlocksChangedReviewAndRollsBackFinalAuditFailure(t *testing.T) {
	for _, condition := range []string{"policy", "members", "group", "archived", "source-grant", "target-grant", "site", "audit"} {
		t.Run(condition, func(t *testing.T) {
			f := ownedOrganizationUpdateFixture(t)
			s, ctx := f.store, t.Context()
			r := ownedOrganizationSchedule(t, f, time.Now().UTC().Truncate(time.Second))
			expected := "review_changed"
			switch condition {
			case "policy":
				policy := f.plan.Definition.Policy()
				require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
			case "members":
				second, _ := testEnroll(t, s, f.scope, "Owned later scheduled target")
				drainCommands(t, s, second, nil)
			case "group", "archived":
				definition := f.group.DeviceGroupDefinition
				definition.Name = "Changed organization source"
				definition.Archived = condition == "archived"
				_, err := inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "organization", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
				require.NoError(t, err)
			case "source-grant", "target-grant":
				grant := access.Grant{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}
				if condition == "target-grant" {
					grant = access.Grant{Role: access.Viewer, Scope: access.Scope{TenantID: 1}}
				}
				require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{grant}))
				expected = "authority_changed"
			case "site":
				_, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
				require.NoError(t, err)
				expected = "scope_changed"
			case "audit":
				_, err := s.db.Exec(`CREATE FUNCTION reject_organization_schedule_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.schedule.activated' THEN RAISE EXCEPTION 'owned organization schedule audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_organization_schedule_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_organization_schedule_audit()`)
				require.NoError(t, err)
			}
			p0, a0, n0 := f.counts(t)
			result, err := s.ProcessDueUpdateSchedules(ctx, f.permissions, f.sources, 25)
			if condition == "audit" {
				require.Error(t, err)
				require.Equal(t, 1, result.Failed)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, result.Blocked)
			}
			require.Zero(t, result.Activated)
			p, a, n := f.counts(t)
			require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
			// Read the original authenticated record directly for the moved-site
			// fixture; ordinary site routes correctly deny its previous scope.
			stored, err := s.scanUpdateSchedule(s.db.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1`, r.ID))
			require.NoError(t, err)
			if condition == "audit" {
				require.Equal(t, "scheduled", stored.Phase)
				require.Equal(t, 1, stored.Revision)
			} else {
				require.Equal(t, expected, stored.Reason)
			}
		})
	}
}

func TestUpdateOrganizationScheduleRetainsSourceAndTargetLocksThroughFinalAudit(t *testing.T) {
	f := ownedOrganizationUpdateFixture(t)
	s, ctx := f.store, t.Context()
	r := ownedOrganizationSchedule(t, f, time.Now().UTC().Truncate(time.Second))
	const gate = 673810057
	conn, err := s.db.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, gate)
	_, err = s.db.Exec(`CREATE SEQUENCE organization_schedule_audit_entered; CREATE FUNCTION gate_organization_schedule_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.schedule.activated' THEN PERFORM nextval('organization_schedule_audit_entered'); PERFORM pg_advisory_xact_lock(673810057); END IF; RETURN NEW; END; $$; CREATE TRIGGER gate_organization_schedule_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION gate_organization_schedule_audit()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.ProcessDueUpdateSchedules(ctx, f.permissions, f.sources, 25)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var entered bool
		err := s.db.QueryRow(`SELECT is_called FROM organization_schedule_audit_entered`).Scan(&entered)
		return err == nil && entered
	}, 3*time.Second, 10*time.Millisecond)
	for _, change := range []string{"group", "site", "policy", "permission", "cancellation"} {
		t.Run(change, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			var err error
			switch change {
			case "group":
				definition := f.group.DeviceGroupDefinition
				definition.Archived = true
				_, err = inventory.SaveDeviceGroup(bounded, s.db, f.permissions, "organization", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
			case "site":
				_, err = s.db.ExecContext(bounded, `UPDATE sites SET tenant_sites=2 WHERE id=1`)
			case "policy":
				err = s.SetUpdatePolicyWithAccess(bounded, f.scope, []string{f.device.ID}, nil, "operator", f.permissions)
			case "permission":
				err = f.permissions.ReplaceGrants(bounded, "admin", "organization", 1, nil)
			case "cancellation":
				err = s.CancelUpdateSchedule(bounded, "operator", f.permissions, f.scope, f.plan.ID, r.ID, r.Revision)
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
		t.Fatal("organization schedule did not finish after audit release")
	}
	require.Equal(t, "activated", f.details(t, r.ID).Phase)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, nil))
	_, err = s.UpdateScheduleDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, r.ID)
	require.NoError(t, err)
}
