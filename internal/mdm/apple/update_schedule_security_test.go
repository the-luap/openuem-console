package apple

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdateScheduleCreationBoundsAndExactRequestIdentity(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	at := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	for _, condition := range []string{"past", "future", "precision", "short", "long", "fraction", "duplicate", "token", "empty", "viewer", "scope", "source"} {
		t.Run(condition, func(t *testing.T) {
			before, window, actor, scope, sources, targets := at, time.Hour, "operator", f.scope, f.sources, append([]UpdatePlanGroupSelection(nil), f.selection...)
			switch condition {
			case "past":
				before = at.Add(-2 * time.Hour)
			case "future":
				before = at.Add(91 * 24 * time.Hour)
			case "precision":
				before = at.Add(time.Nanosecond)
			case "short":
				window = time.Second
			case "long":
				window = 8 * 24 * time.Hour
			case "fraction":
				window += time.Nanosecond
			case "duplicate":
				targets = append(targets, targets[0])
			case "token":
				targets[0].PolicyToken = "bad"
			case "empty":
				targets = nil
			case "viewer":
				actor = "viewer"
			case "scope":
				scope.SiteID = 0
			case "source":
				sources.Apple = false
			}
			r, err := f.store.ScheduleUpdatePlanFromGroup(ctx, actor, f.permissions, scope, sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), targets, before, window)
			require.Error(t, err)
			require.Nil(t, r)
		})
	}
	key := uuid.NewString()
	results := make(chan *UpdateSchedule, 2)
	failures := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			r, err := f.store.ScheduleUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, key, f.selection, at, time.Hour)
			results <- r
			failures <- err
		})
	}
	workers.Wait()
	require.NoError(t, <-failures)
	require.NoError(t, <-failures)
	require.Equal(t, (<-results).ID, (<-results).ID)
	_, err := f.store.ScheduleUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, key, f.selection, at.Add(time.Minute), time.Hour)
	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err = f.store.ScheduleUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, key, f.selection, at, time.Hour)
	require.ErrorIs(t, err, ErrConflict)
}

func TestUpdateScheduleHistoryLimitAndImmutableLifecycle(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	at := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	first := f.schedule(t, at)
	r, err := f.store.scanUpdateSchedule(f.store.db.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1`, first.ID))
	require.NoError(t, err)
	tx, err := f.store.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	for range 255 {
		copy := *r
		copy.ID, copy.RequestKey, copy.activationKey = uuid.NewString(), uuid.NewString(), uuid.NewString()
		require.NoError(t, f.store.insertUpdateSchedule(ctx, tx, &copy))
	}
	require.NoError(t, tx.Commit())
	_, err = f.store.ScheduleUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection, at, time.Hour)
	require.ErrorIs(t, err, ErrUpdateScheduleFull)
	seen := map[string]bool{}
	cursor := ""
	for {
		items, next, err := f.store.UpdateSchedules(ctx, "operator", f.permissions, f.scope, f.plan.ID, cursor)
		require.NoError(t, err)
		require.LessOrEqual(t, len(items), 25)
		for _, item := range items {
			require.False(t, seen[item.ID])
			seen[item.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	require.Len(t, seen, 256)
	for _, query := range []string{`DELETE FROM mdm_apple_update_schedules WHERE id=$1`, `UPDATE mdm_apple_update_schedules SET not_before=not_before+INTERVAL '1 minute' WHERE id=$1`, `UPDATE mdm_apple_update_schedules SET request_key=gen_random_uuid() WHERE id=$1`, `UPDATE mdm_apple_update_schedules SET revision=revision+2 WHERE id=$1`} {
		_, err = f.store.db.Exec(query, first.ID)
		require.Error(t, err)
	}
	require.NoError(t, f.store.CancelUpdateSchedule(ctx, "operator", f.permissions, f.scope, f.plan.ID, first.ID, 1))
	_, err = f.store.db.Exec(`UPDATE mdm_apple_update_schedules SET phase='waiting',revision=revision+1,completed_at=NULL WHERE id=$1`, first.ID)
	require.Error(t, err)
	f.schedule(t, at)
}

func TestUpdateScheduleCiphertextAndStateBindingContinueOtherSelectedRecords(t *testing.T) {
	for _, field := range []string{"intent", "state"} {
		t.Run(field, func(t *testing.T) {
			f := ownedUpdateScheduleFixture(t)
			ctx := t.Context()
			now := time.Now().UTC().Truncate(time.Second)
			first, second := f.schedule(t, now), f.schedule(t, now)
			column := "encrypted_intent"
			if field == "state" {
				column = "encrypted_state"
			}
			// Owned corruption fixture: simulate storage substitution. Ordinary SQL
			// mutations remain forbidden by the lifecycle trigger tested separately.
			_, err := f.store.db.Exec(`ALTER TABLE mdm_apple_update_schedules DISABLE TRIGGER mdm_apple_update_schedule_identity`)
			require.NoError(t, err)
			_, err = f.store.db.Exec(`UPDATE mdm_apple_update_schedules SET `+column+`=(SELECT `+column+` FROM mdm_apple_update_schedules WHERE id=$2) WHERE id=$1`, first.ID, second.ID)
			require.NoError(t, err)
			_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_update_schedules ENABLE TRIGGER mdm_apple_update_schedule_identity`)
			require.NoError(t, err)
			detail, err := f.store.UpdateScheduleDetails(ctx, "admin", f.permissions, f.scope, f.plan.ID, first.ID)
			require.ErrorIs(t, err, ErrUpdateScheduleIntegrity)
			require.Nil(t, detail)
			progress, err := f.store.ProcessDueUpdateSchedules(ctx, f.permissions, f.sources, 25)
			require.ErrorIs(t, err, ErrUpdateScheduleIntegrity)
			require.Equal(t, 1, progress.Failed)
			require.Equal(t, 1, progress.Activated)
			require.Equal(t, "activated", f.details(t, second.ID).Phase)
		})
	}
}

func TestUpdateScheduleDoesNotAdoptPrematureOriginalReceipt(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	r := f.schedule(t, time.Now().UTC().Add(time.Hour).Truncate(time.Second))
	stored, err := f.store.scanUpdateSchedule(f.store.db.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1`, r.ID))
	require.NoError(t, err)
	// Only the owned test can access the private activation key. Even this
	// pre-existing receipt cannot become evidence of a later activation.
	receipt, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, stored.activationKey, f.selection)
	require.NoError(t, err)
	stored.Phase, stored.AssignmentID = "activated", receipt.ID
	completed := r.NotBefore.Add(time.Second)
	stored.CompletedAt = &completed
	require.False(t, matchesUpdateScheduleAssignment(stored, receipt))
	require.Zero(t, f.process(t).Processed)
	// Public JSON and formatted values never expose the private activation key.
	data, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(data), stored.activationKey)
}

func TestUpdateScheduleRecoverableContentionBackoffAndAuditAtomicity(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	r := f.schedule(t, time.Now().UTC().Truncate(time.Second))
	_, err := f.store.db.Exec(`CREATE FUNCTION owned_schedule_contention() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.group.created' THEN RAISE EXCEPTION 'owned temporary lock failure' USING ERRCODE='55P03'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_schedule_contention BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_schedule_contention()`)
	require.NoError(t, err)
	p, a, n := f.counts(t)
	require.Equal(t, 1, f.process(t).Waiting)
	waiting := f.details(t, r.ID)
	require.Equal(t, "waiting", waiting.Phase)
	require.Nil(t, waiting.CompletedAt)
	require.True(t, waiting.NextAttemptAt.After(waiting.UpdatedAt))
	require.Zero(t, f.process(t).Processed)
	p2, a2, n2 := f.counts(t)
	require.Equal(t, []int{p, a, n}, []int{p2, a2, n2})
	_, err = f.store.db.Exec(`CREATE FUNCTION owned_schedule_cancel_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.schedule.canceled' THEN RAISE EXCEPTION 'owned cancellation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_schedule_cancel_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_schedule_cancel_audit()`)
	require.NoError(t, err)
	require.Error(t, f.store.CancelUpdateSchedule(ctx, "admin", f.permissions, f.scope, f.plan.ID, r.ID, waiting.Revision))
	require.Equal(t, waiting.Revision, f.details(t, r.ID).Revision)
}

func TestAppleUpdateScheduleRunnerImmediateBoundedPassAndRedactedErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var log bytes.Buffer
	calls := 0
	runAppleUpdateSchedules(ctx, time.Millisecond, time.Second, func(pass context.Context, limit int) (UpdateScheduleProgress, error) {
		calls++
		require.Equal(t, 25, limit)
		deadline, ok := pass.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), time.Second)
		if calls == 2 {
			cancel()
		}
		return UpdateScheduleProgress{}, errors.New("owned-secret-source")
	}, slog.New(slog.NewTextHandler(&log, nil)))
	require.Equal(t, 2, calls)
	require.Contains(t, log.String(), "Apple update schedule processing failed")
	require.NotContains(t, log.String(), "owned-secret-source")
}
