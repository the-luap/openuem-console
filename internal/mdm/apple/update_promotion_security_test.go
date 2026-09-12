package apple

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdatePromotionFinalAuditFailureAndIdentityExpiryRollbackAllWork(t *testing.T) {
	for _, condition := range []string{"parent-audit", "child-audit", "pilot-expiry", "destination-expiry"} {
		t.Run(condition, func(t *testing.T) {
			f, _, q := ownedUpdatePromotionFixture(t)
			ctx := t.Context()
			action := "apple.update.plan.promotion.created"
			body := `RAISE EXCEPTION 'owned promotion audit failure';`
			if condition == "child-audit" {
				action = "apple.update.plan.group.created"
			}
			if condition == "pilot-expiry" || condition == "destination-expiry" {
				id := f.device.ID
				if condition == "destination-expiry" {
					for _, target := range q.Targets {
						if target.DeviceID != f.device.ID {
							id = target.DeviceID
							break
						}
					}
				}
				_, err := f.store.db.Exec(`CREATE TABLE owned_promotion_expiry(device_id UUID);`)
				require.NoError(t, err)
				_, err = f.store.db.Exec(`INSERT INTO owned_promotion_expiry VALUES($1)`, id)
				require.NoError(t, err)
				_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1`, id)
				require.NoError(t, err)
				body = `PERFORM pg_sleep(GREATEST(EXTRACT(EPOCH FROM ((SELECT certificate_expires_at FROM mdm_apple_devices WHERE id=(SELECT device_id FROM owned_promotion_expiry))-clock_timestamp())),0)+0.02);`
			}
			_, err := f.store.db.Exec(`CREATE SEQUENCE owned_promotion_audit_entered; CREATE FUNCTION owned_promotion_final_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='` + action + `' THEN PERFORM nextval('owned_promotion_audit_entered'); ` + body + ` END IF; RETURN NEW; END $$; CREATE TRIGGER owned_promotion_final_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_promotion_final_audit()`)
			require.NoError(t, err)
			p0, a0, n0 := f.counts(t)
			r, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
			require.Error(t, err)
			require.Nil(t, r)
			if condition == "pilot-expiry" || condition == "destination-expiry" {
				require.ErrorIs(t, err, ErrUpdatePromotionNotReady)
			}
			var entered bool
			require.NoError(t, f.store.db.QueryRow(`SELECT is_called FROM owned_promotion_audit_entered`).Scan(&entered))
			require.True(t, entered, "the action must reach its final audit before failing")
			p, a, n := f.counts(t)
			require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
			var count int
			require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_promotions`).Scan(&count))
			require.Zero(t, count)
		})
	}
}
func TestUpdatePromotionKeepsBothCohortsAndAuthorityLockedThroughAudit(t *testing.T) {
	f, _, q := ownedUpdatePromotionFixture(t)
	ctx := t.Context()
	const gate = 673810052
	blocker, err := f.store.db.Conn(ctx)
	require.NoError(t, err)
	defer blocker.Close()
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	_, err = f.store.db.Exec(`CREATE FUNCTION owned_promotion_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.promotion.created' THEN PERFORM pg_advisory_xact_lock(673810052); END IF; RETURN NEW; END $$; CREATE TRIGGER owned_promotion_audit_wait BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_promotion_audit_wait()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		err := f.store.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=$1 AND NOT granted)`, gate).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	for _, target := range q.Targets {
		change, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		err := f.store.SetUpdatePolicyWithAccess(change, f.scope, []string{target.DeviceID}, nil, "operator", f.permissions)
		cancel()
		require.Error(t, err)
	}
	change, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	err = f.permissions.ReplaceGrants(change, "admin", "operator", 1, nil)
	cancel()
	require.Error(t, err)
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	require.NoError(t, err)
	select {
	case err = <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("promotion did not finish after releasing its audit")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil))
	_, err = f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
	require.ErrorIs(t, err, access.ErrDenied)
}
func TestUpdatePromotionOverlappingPilotsUseOneCanonicalDeviceLockOrder(t *testing.T) {
	f, firstPilot := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	other, _ := testEnroll(t, f.store, f.scope, "Owned independent second pilot")
	drainCommands(t, f.store, other, nil)
	secondGroup, err := inventory.SaveDeviceGroup(ctx, f.store.db, f.permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned second pilot", Rule: inventory.DeviceGroupRule{Search: "Owned independent second pilot"}})
	require.NoError(t, err)
	secondPreview, err := f.store.PreviewUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, secondGroup.ID, secondGroup.Revision)
	require.NoError(t, err)
	require.Len(t, secondPreview.Targets, 1)
	secondPilot, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, secondGroup.ID, secondGroup.Revision, uuid.NewString(), updateGroupSelection(secondPreview))
	require.NoError(t, err)
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	otherFixture := f
	otherFixture.device = other
	ownedPilotOSReport(t, otherFixture, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	requests := []UpdatePromotionRequest{}
	for _, pilot := range []*UpdatePlanGroupAssignment{firstPilot, secondPilot} {
		preview, err := f.store.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, pilot.ID, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
		require.NoError(t, err)
		require.True(t, preview.Ready)
		q := UpdatePromotionRequest{RequestKey: uuid.NewString(), PilotPlanID: f.plan.ID, PilotAssignmentID: pilot.ID, DestinationPlanID: f.plan.ID, DestinationRevision: f.plan.Revision, GroupID: f.group.ID, GroupRevision: f.group.Revision}
		for _, target := range preview.Destination.Targets {
			q.Targets = append(q.Targets, target.Selection)
		}
		requests = append(requests, q)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	start := make(chan struct{})
	for _, q := range requests {
		wg.Go(func() {
			<-start
			_, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
			failures <- err
		})
	}
	close(start)
	wg.Wait()
	require.NoError(t, <-failures)
	require.NoError(t, <-failures)
	var count int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_promotions`).Scan(&count))
	require.Equal(t, 2, count)
}
func TestUpdatePromotionHistoricalProofAndCiphertextRejectSourceSubstitution(t *testing.T) {
	for _, condition := range []string{"actor", "grant", "key", "pilot", "destination", "created", "ciphertext"} {
		t.Run(condition, func(t *testing.T) {
			f, _, q := ownedUpdatePromotionFixture(t)
			ctx := t.Context()
			r, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
			require.NoError(t, err)
			_, err = f.store.db.Exec(`UPDATE mdm_apple_update_promotions SET actor='other' WHERE id=$1`, r.ID)
			require.Error(t, err)
			_, err = f.store.db.Exec(`DELETE FROM mdm_apple_update_promotions WHERE id=$1`, r.ID)
			require.Error(t, err)
			replacementID := ""
			if condition == "destination" {
				preview, err := f.store.PreviewUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision)
				require.NoError(t, err)
				replacement, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision, uuid.NewString(), updateGroupSelection(preview))
				require.NoError(t, err)
				replacementID = replacement.ID
			}
			_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_update_promotions DISABLE TRIGGER mdm_apple_keep_update_promotion`)
			require.NoError(t, err)
			assignment := "actor='another owned actor'"
			switch condition {
			case "grant":
				assignment = "actor_revision=actor_revision+1"
			case "key":
				assignment = "request_key=gen_random_uuid()"
			case "pilot":
				assignment = "pilot_plan_id=destination_plan_id,pilot_assignment_id=assignment_id,assignment_id=pilot_assignment_id,destination_plan_id=pilot_plan_id"
			case "destination":
				assignment = "assignment_id=$2"
			case "created":
				assignment = "created_at=created_at+interval '1 second'"
			case "ciphertext":
				assignment = "encrypted_intent=decode(repeat('00',40),'hex')"
			}
			args := []any{r.ID}
			if replacementID != "" {
				args = append(args, replacementID)
			}
			_, err = f.store.db.Exec(`UPDATE mdm_apple_update_promotions SET `+assignment+` WHERE id=$1`, args...)
			_, restoreErr := f.store.db.Exec(`ALTER TABLE mdm_apple_update_promotions ENABLE TRIGGER mdm_apple_keep_update_promotion`)
			require.NoError(t, err)
			require.NoError(t, restoreErr)
			_, err = f.store.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, r.ID)
			require.Error(t, err)
			_, _, err = f.store.UpdatePromotions(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, r.ID)
			require.Error(t, err)
			require.NotContains(t, fmt.Sprint(err), "Owned broad")
			if condition == "pilot" {
				_, err = f.store.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.DestinationPlanID, r.AssignmentID, r.ID)
				require.ErrorIs(t, err, ErrUpdatePromotionIntegrity)
			}
		})
	}
}
