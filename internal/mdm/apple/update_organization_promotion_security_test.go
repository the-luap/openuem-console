package apple

import (
	"context"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdateOrganizationPromotionRejectsChangedProofSourceAndPolicyWithAtomicAudit(t *testing.T) {
	for _, condition := range []string{"pilot", "policy", "group", "plan", "source-grant", "audit"} {
		t.Run(condition, func(t *testing.T) {
			f, _, q := ownedOrganizationPromotionFixture(t)
			s, ctx := f.store, t.Context()
			switch condition {
			case "pilot":
				ownedPilotOSReport(t, f, map[string]any{"version": "18.6.2", "build-version": "22G100"})
			case "policy":
				policy := f.plan.Definition.Policy()
				for _, target := range q.Targets {
					if target.DeviceID != f.device.ID {
						require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, f.scope, []string{target.DeviceID}, &policy, "operator", f.permissions))
					}
				}
			case "group":
				definition := f.group.DeviceGroupDefinition
				definition.Archived = true
				_, err := inventory.SaveDeviceGroup(ctx, s.db, f.permissions, "organization", access.Scope{TenantID: 1}, f.group.ID, 1, definition)
				require.NoError(t, err)
			case "plan":
				definition := f.plan.Definition
				definition.Name = "Later destination plan"
				_, err := s.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, q.DestinationPlanID, q.DestinationRevision, definition)
				require.NoError(t, err)
			case "source-grant":
				require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
			case "audit":
				_, err := s.db.Exec(`CREATE FUNCTION reject_organization_promotion_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.promotion.created' THEN RAISE EXCEPTION 'owned organization promotion audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_organization_promotion_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_organization_promotion_audit()`)
				require.NoError(t, err)
			}
			p0, a0, n0 := f.counts(t)
			r, err := s.PromoteUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, q)
			require.Error(t, err)
			require.Nil(t, r)
			switch condition {
			case "pilot":
				require.ErrorIs(t, err, ErrUpdatePromotionNotReady)
			case "group":
				require.ErrorIs(t, err, inventory.ErrGroupConflict)
			case "source-grant":
				require.ErrorIs(t, err, access.ErrDenied)
			case "audit":
			default:
				require.ErrorIs(t, err, ErrConflict)
			}
			p, a, n := f.counts(t)
			require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
			var parents int
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_promotions`).Scan(&parents))
			require.Zero(t, parents)
		})
	}
}

func TestUpdateOrganizationPromotionRetainsSourceAndPilotLocksThroughFinalAudit(t *testing.T) {
	f, _, q := ownedOrganizationPromotionFixture(t)
	s, ctx := f.store, t.Context()
	const gate = 673810058
	conn, err := s.db.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, gate)
	_, err = s.db.Exec(`CREATE SEQUENCE organization_promotion_audit_entered; CREATE FUNCTION gate_organization_promotion_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.promotion.created' THEN PERFORM nextval('organization_promotion_audit_entered'); PERFORM pg_advisory_xact_lock(673810058); END IF; RETURN NEW; END; $$; CREATE TRIGGER gate_organization_promotion_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION gate_organization_promotion_audit()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.PromoteUpdatePlanOrganizationGroup(ctx, "organization", f.permissions, f.scope, f.sources, q)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var entered bool
		err := s.db.QueryRow(`SELECT is_called FROM organization_promotion_audit_entered`).Scan(&entered)
		return err == nil && entered
	}, 3*time.Second, 10*time.Millisecond)
	for _, change := range []string{"group", "site", "pilot-policy", "destination-policy", "permission"} {
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
			case "pilot-policy", "destination-policy":
				id := f.device.ID
				if change == "destination-policy" {
					for _, target := range q.Targets {
						if target.DeviceID != f.device.ID {
							id = target.DeviceID
						}
					}
				}
				err = s.SetUpdatePolicyWithAccess(bounded, f.scope, []string{id}, nil, "operator", f.permissions)
			case "permission":
				err = f.permissions.ReplaceGrants(bounded, "admin", "organization", 1, nil)
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
		t.Fatal("organization promotion did not finish after audit release")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "organization", 1, nil))
	items, _, err := s.UpdatePromotions(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, "")
	require.NoError(t, err)
	require.Len(t, items, 1)
}
