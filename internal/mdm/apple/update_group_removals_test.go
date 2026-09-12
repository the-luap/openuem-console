package apple

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedUpdateRemovalReview(t *testing.T, f updateScheduleFixture, original *UpdatePlanGroupAssignment) []UpdatePlanGroupSelection {
	t.Helper()
	p, err := f.store.PreviewUpdateGroupRemoval(t.Context(), "operator", f.permissions, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	return updateGroupRemovalSelection(p)
}

func TestUpdateGroupRemovalConcurrentReplayPreservesLaterPolicy(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	selection := ownedUpdateRemovalReview(t, f, original)
	request := uuid.NewString()
	var wg sync.WaitGroup
	results := make(chan *UpdateGroupRemoval, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			r, err := f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, request, selection)
			results <- r
			failures <- err
		})
	}
	wg.Wait()
	for range 2 {
		require.NoError(t, <-failures)
	}
	first, second := <-results, <-results
	require.Equal(t, first.ID, second.ID)
	require.Len(t, first.Commands, 1)
	require.NotEmpty(t, first.Commands[0].CommandID)
	require.NotEqual(t, original.Commands[0].CommandID, first.Commands[0].CommandID)
	_, err := f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound)
	drainCommands(t, f.store, f.device, nil)
	declarations, err := f.store.DeclarativeManagement(ctx, f.device, map[string]any{"UDID": f.device.UDID, "Endpoint": "declaration-items"})
	require.NoError(t, err)
	body, err := json.Marshal(declarations)
	require.NoError(t, err)
	require.NotContains(t, string(body), ".update\"")
	policy := original.Plan.Definition.Policy()
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	definition := f.plan.Definition
	definition.Archived = true
	_, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	var before, after int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands`).Scan(&before))
	replay, err := f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, request, selection)
	require.NoError(t, err)
	require.Equal(t, first.ID, replay.ID)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands`).Scan(&after))
	require.Equal(t, before, after)
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.NoError(t, err)
	detail, err := f.store.UpdateGroupRemovalDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, first.ID)
	require.NoError(t, err)
	require.Equal(t, first.Commands, detail.Commands)
	items, next, err := f.store.UpdateGroupRemovals(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Empty(t, next)
	_, err = f.store.RemoveUpdateGroupPolicies(ctx, "admin", f.permissions, f.scope, f.plan.ID, original.ID, request, selection)
	require.ErrorIs(t, err, ErrConflict)
	_, err = f.store.db.Exec(`DELETE FROM mdm_apple_update_group_removals WHERE id=$1`, first.ID)
	require.Error(t, err)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_update_group_removals SET actor='owned changed actor' WHERE id=$1`, first.ID)
	require.Error(t, err)
	body, err = json.Marshal(first)
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(body))
	require.NotContains(t, fmt.Sprintf("%#v", first), f.device.ID)
}

func TestUpdateGroupRemovalRejectsChangedSelectionAndLateAuditFailure(t *testing.T) {
	for _, condition := range []string{"policy", "removed", "moved", "revoked", "expired", "notification", "token", "audit"} {
		t.Run(condition, func(t *testing.T) {
			f, original := ownedUpdateRemovalFixture(t)
			ctx := t.Context()
			selection := ownedUpdateRemovalReview(t, f, original)
			var query string
			switch condition {
			case "policy":
				query = `UPDATE mdm_apple_update_policies SET deadline='2026-11-01T18:00:00' WHERE device_id=$1`
			case "removed":
				query = `DELETE FROM mdm_apple_update_policies WHERE device_id=$1`
			case "moved":
				query = `UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`
			case "revoked":
				query = `UPDATE mdm_apple_devices SET status='revoked' WHERE id=$1`
			case "expired":
				query = `UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`
			case "notification":
				query = `UPDATE mdm_apple_devices SET os_version='14.0' WHERE id=$1`
			case "token":
				p := original.Plan.Definition.Policy()
				selection[0].PolicyToken = updatePolicyGroupToken(f.scope, f.device.ID, &p)
			case "audit":
				_, err := f.store.db.Exec(`CREATE FUNCTION owned_group_removal_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.removal.created' THEN RAISE EXCEPTION 'owned removal audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_group_removal_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_group_removal_audit_failure()`)
				require.NoError(t, err)
			}
			if query != "" {
				_, err := f.store.db.Exec(query, f.device.ID)
				require.NoError(t, err)
			}
			var before, after, policies, receipts int
			require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands`).Scan(&before))
			r, err := f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection)
			require.Error(t, err)
			require.Nil(t, r)
			if condition != "audit" {
				require.ErrorIs(t, err, ErrConflict)
			}
			require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands`).Scan(&after))
			require.Equal(t, before, after)
			require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies`).Scan(&policies))
			if condition == "removed" {
				require.Zero(t, policies)
			} else {
				require.Equal(t, 1, policies)
			}
			require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_group_removals`).Scan(&receipts))
			require.Zero(t, receipts)
		})
	}
}

func TestUpdateGroupRemovalWithoutCurrentNotificationCapability(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	_, err := f.store.db.Exec(`UPDATE mdm_apple_devices SET os_version='14.0' WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	selection := ownedUpdateRemovalReview(t, f, original)
	r, err := f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection)
	require.NoError(t, err)
	require.Len(t, r.Commands, 1)
	require.Empty(t, r.Commands[0].CommandID)
	_, err = f.store.UpdateGroupRemovalDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, r.ID)
	require.NoError(t, err)
	var queued int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement' AND status='queued'`).Scan(&queued))
	require.Zero(t, queued)
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestUpdateGroupRemovalRequiresCurrentAuthority(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	selection := ownedUpdateRemovalReview(t, f, original)
	_, err := f.store.RemoveUpdateGroupPolicies(t.Context(), "viewer", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.RemoveUpdateGroupPolicies(t.Context(), "admin", nil, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestUpdateGroupRemovalRequiresCompleteReviewedCohort(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	second, _ := testEnroll(t, f.store, f.scope, f.device.Name)
	drainCommands(t, f.store, second, nil)
	preview, err := f.store.PreviewUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 2)
	original, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), updateGroupSelection(preview))
	require.NoError(t, err)
	selection := ownedUpdateRemovalReview(t, f, original)
	require.Len(t, selection, 2)
	_, err = f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection[:1])
	require.ErrorIs(t, err, ErrConflict)
	_, err = f.store.db.Exec(`CREATE FUNCTION owned_second_removal_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.policy' AND NEW.resource_id=(SELECT id::text FROM mdm_apple_devices WHERE status='enrolled' ORDER BY id DESC LIMIT 1) THEN RAISE EXCEPTION 'owned second removal audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_second_removal_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_second_removal_audit_failure()`)
	require.NoError(t, err)
	_, err = f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection)
	require.Error(t, err)
	var policies, queued, receipts int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies`).Scan(&policies))
	require.Equal(t, 2, policies)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement' AND status='queued'`).Scan(&queued))
	require.Equal(t, 2, queued)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_group_removals`).Scan(&receipts))
	require.Zero(t, receipts)
}

func TestUpdateGroupRemovalHistoryAuthenticatesRowsAndCursor(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	policy := original.Plan.Definition.Policy()
	selection := ownedUpdateRemovalReview(t, f, original)
	for range 26 {
		_, err := f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection)
		require.NoError(t, err)
		require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	}
	first, next, err := f.store.UpdateGroupRemovals(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, "")
	require.NoError(t, err)
	require.Len(t, first, 25)
	require.Equal(t, first[24].ID, next)
	second, end, err := f.store.UpdateGroupRemovals(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, next)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Empty(t, end)
	for _, entry := range first {
		require.NotEqual(t, entry.ID, second[0].ID)
	}
	_, _, err = f.store.UpdateGroupRemovals(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString())
	require.ErrorIs(t, err, ErrNotFound)
	_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_update_group_removals DISABLE TRIGGER mdm_apple_keep_update_group_removal`)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_update_group_removals SET created_at=created_at-interval '1 day' WHERE id=$1`, next)
	require.NoError(t, err)
	_, _, err = f.store.UpdateGroupRemovals(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, next)
	require.Error(t, err, "The page anchor must authenticate before it controls pagination")
	_, err = f.store.UpdateGroupRemovalDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, next)
	require.Error(t, err)
}

func TestUpdateGroupRemovalRejectsCiphertextAndParentMutation(t *testing.T) {
	for _, condition := range []string{"ciphertext", "actor", "parent"} {
		t.Run(condition, func(t *testing.T) {
			f, original := ownedUpdateRemovalFixture(t)
			ctx := t.Context()
			selection := ownedUpdateRemovalReview(t, f, original)
			key := uuid.NewString()
			r, err := f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, key, selection)
			require.NoError(t, err)
			_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_update_group_removals DISABLE TRIGGER mdm_apple_keep_update_group_removal; ALTER TABLE mdm_apple_update_group_assignments DISABLE TRIGGER mdm_apple_keep_update_group_assignment`)
			require.NoError(t, err)
			switch condition {
			case "ciphertext":
				_, err = f.store.db.Exec(`UPDATE mdm_apple_update_group_removals SET encrypted_intent=set_byte(encrypted_intent,0,(get_byte(encrypted_intent,0)+1)%256) WHERE id=$1`, r.ID)
			case "actor":
				_, err = f.store.db.Exec(`UPDATE mdm_apple_update_group_removals SET actor='owned other actor' WHERE id=$1`, r.ID)
			case "parent":
				_, err = f.store.db.Exec(`UPDATE mdm_apple_update_group_assignments SET encrypted_intent=set_byte(encrypted_intent,0,(get_byte(encrypted_intent,0)+1)%256) WHERE id=$1`, original.ID)
			}
			require.NoError(t, err)
			_, err = f.store.UpdateGroupRemovalDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, r.ID)
			require.Error(t, err)
			_, _, err = f.store.UpdateGroupRemovals(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, "")
			require.Error(t, err)
			_, err = f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, key, selection)
			require.Error(t, err)
		})
	}
}

func TestUpdateGroupRemovalRechecksIdentityAfterFinalAudit(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	selection := ownedUpdateRemovalReview(t, f, original)
	const gate = 673810048
	blocker, err := f.store.db.Conn(ctx)
	require.NoError(t, err)
	defer blocker.Close()
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	_, err = f.store.db.Exec(`CREATE FUNCTION owned_group_removal_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.removal.created' THEN PERFORM pg_advisory_xact_lock(673810048); END IF; RETURN NEW; END $$; CREATE TRIGGER owned_group_removal_audit_wait BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_group_removal_audit_wait()`)
	require.NoError(t, err)
	var expires time.Time
	require.NoError(t, f.store.db.QueryRow(`UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1 RETURNING certificate_expires_at`, f.device.ID).Scan(&expires))
	done := make(chan error, 1)
	go func() {
		_, err := f.store.RemoveUpdateGroupPolicies(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID, uuid.NewString(), selection)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		err := f.store.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=$1 AND NOT granted)`, gate).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		var expired bool
		err := f.store.db.QueryRow(`SELECT clock_timestamp()>$1`, expires).Scan(&expired)
		return err == nil && expired
	}, 7*time.Second, 25*time.Millisecond)
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	require.NoError(t, err)
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrConflict)
	case <-time.After(3 * time.Second):
		t.Fatal("Removal did not finish after releasing its final audit")
	}
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.NoError(t, err)
	var receipts, originalQueued int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_group_removals`).Scan(&receipts))
	require.Zero(t, receipts)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE id=$1 AND status='queued'`, original.Commands[0].CommandID).Scan(&originalQueued))
	require.Equal(t, 1, originalQueued)
}
