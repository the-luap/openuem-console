package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestUpdateScheduleQueueBackoffThenAtomicRetry(t *testing.T) {
	f := syncMLTestStore(t)
	var last *CSPCommand
	for n := 0; n < 250; n++ {
		last = cspTestQueue(t, f, CSPCommandSpec{Kind: "Get", URI: "./Device/Vendor/MSFT/Synthetic/Value"})
	}
	ring := updateTestRing(t, f, updateTestFullPolicy())
	schedule := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	ctx := context.Background()
	if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || p.Waiting != 1 {
		t.Fatal("full queue did not defer the entire schedule", p, err)
	}
	waiting := updateTestScheduleRead(t, f, schedule.ID)
	if waiting.Phase != "waiting" || waiting.Reason != "device_queue_full" || waiting.Attempts != 1 || waiting.NextAttemptAt.Sub(waiting.UpdatedAt) != time.Minute || waiting.RolloutID != "" {
		t.Fatal("queue backoff state was not preserved")
	}
	if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || p.Processed != 0 {
		t.Fatal("backoff was bypassed", p, err)
	}
	var runs int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_update_runs`).Scan(&runs); err != nil || runs != 0 {
		t.Fatal("waiting attempt left partial device runs", err)
	}
	if err := f.store.CancelCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, last.ID, last.Revision); err != nil {
		t.Fatal(err)
	}
	updateTestScheduleTime(t, f, schedule.ID, func(r *updateStoredSchedule, now time.Time) { r.NextAttemptAt = now })
	if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || p.Activated != 1 {
		t.Fatal("capacity recovery did not activate original intent", p, err)
	}
	done := updateTestScheduleRead(t, f, schedule.ID)
	if done.Attempts != 2 || done.Revision != 3 || done.RolloutID == "" {
		t.Fatal("retry lost its attempt history")
	}
	var queued int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_commands WHERE phase='queued'`).Scan(&queued); err != nil || queued != 256 {
		t.Fatal("retry did not reserve exactly one full policy", queued, err)
	}
}

func TestUpdateScheduleLateAuditRollsBackWholeActivation(t *testing.T) {
	for _, audit := range []string{"rollout", "schedule"} {
		t.Run(audit, func(t *testing.T) {
			f := syncMLTestStore(t)
			ring := updateTestRing(t, f, updateTestPolicy())
			schedule := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
			table, action := "mdm_windows_update_ring_audit", "rollout.created"
			if audit == "schedule" {
				table, action = "mdm_windows_update_schedule_audit", "schedule.activated"
			}
			if _, err := f.store.db.Exec(`CREATE SEQUENCE synthetic_activation_wait; CREATE FUNCTION delay_activation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='` + action + `' THEN PERFORM nextval('synthetic_activation_wait'); PERFORM pg_sleep(1.1); END IF; RETURN NEW; END; $$; CREATE TRIGGER delay_activation_audit BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION delay_activation_audit()`); err != nil {
				t.Fatal(err)
			}
			updateTestScheduleTime(t, f, schedule.ID, func(r *updateStoredSchedule, now time.Time) {
				r.ExpiresAt = now.Add(time.Second)
				r.NotBefore = r.ExpiresAt.Add(-time.Minute)
				r.CreatedAt = r.NotBefore
				r.UpdatedAt = r.CreatedAt
				r.NextAttemptAt = r.NotBefore
			})
			if p, err := f.store.ProcessDueUpdateSchedules(context.Background(), 25); err != nil || p.Expired != 1 || p.Activated != 0 {
				t.Fatal("expired activation was not rolled back", p, err)
			}
			var entered bool
			if err := f.store.db.QueryRow(`SELECT is_called FROM synthetic_activation_wait`).Scan(&entered); err != nil || !entered {
				t.Fatal("test did not reach the live audit wait", err)
			}
			var runs, commands, rollouts int
			if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_update_runs),(SELECT count(*) FROM mdm_windows_csp_commands),(SELECT count(*) FROM mdm_windows_update_rollouts)`).Scan(&runs, &commands, &rollouts); err != nil || runs != 0 || commands != 0 || rollouts != 0 {
				t.Fatal("late expiry left committed activation work", err)
			}
			if r := updateTestScheduleRead(t, f, schedule.ID); r.Phase != "expired" || r.RolloutID != "" {
				t.Fatal("late expiry retained an activation link")
			}
		})
	}
}

func TestUpdateScheduleAuditRollbackAndScope(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	schedule := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	ctx := context.Background()
	for _, actor := range []string{"viewer", "foreign", "missing"} {
		if r, err := f.store.UpdateScheduleDetails(ctx, actor, f.identity.Scope, schedule.ID); err == nil || r != nil {
			t.Fatal("unauthorized schedule read succeeded")
		}
		if err := f.store.CancelUpdateSchedule(ctx, actor, f.identity.Scope, schedule.ID, 1); err == nil {
			t.Fatal("unauthorized schedule cancellation succeeded")
		}
	}
	if r, err := f.store.UpdateScheduleDetails(ctx, "admin", access.Scope{TenantID: 2, SiteID: 21}, schedule.ID); err == nil || r != nil {
		t.Fatal("schedule read crossed scope")
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_schedule_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic schedule audit failure'; END; $$; CREATE TRIGGER reject_schedule_audit BEFORE INSERT ON mdm_windows_update_schedule_audit FOR EACH ROW EXECUTE FUNCTION reject_schedule_audit()`); err != nil {
		t.Fatal(err)
	}
	if r, err := f.store.UpdateScheduleDetails(ctx, "operator", f.identity.Scope, schedule.ID); err == nil || r != nil {
		t.Fatal("unaudited schedule payload returned")
	}
	if r, err := f.store.UpdateSchedules(ctx, "operator", f.identity.Scope, 0, 100); err == nil || r != nil {
		t.Fatal("unaudited schedule list returned")
	}
	if err := f.store.CancelUpdateSchedule(ctx, "operator", f.identity.Scope, schedule.ID, 1); err == nil {
		t.Fatal("unaudited cancellation committed")
	}
	if r, err := f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, schedule.RequestKey, []string{f.identity.DeviceID}, false, schedule.NotBefore, time.Hour, time.Hour); err == nil || r != nil {
		t.Fatal("unaudited schedule replay returned intent")
	}
	if r, err := f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, schedule.NotBefore, time.Hour, time.Hour); err == nil || r != nil {
		t.Fatal("unaudited schedule creation committed")
	}
	if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err == nil || p.Activated != 0 || p.Failed != 1 {
		t.Fatal("unaudited activation reported success", p, err)
	}
	var schedules, rollouts, commands int
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_update_schedules),(SELECT count(*) FROM mdm_windows_update_rollouts),(SELECT count(*) FROM mdm_windows_csp_commands)`).Scan(&schedules, &rollouts, &commands); err != nil || schedules != 1 || rollouts != 0 || commands != 0 {
		t.Fatal("audit rollback left partial scheduled work", err)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_schedule_audit ON mdm_windows_update_schedule_audit`); err != nil {
		t.Fatal(err)
	}
	if r := updateTestScheduleRead(t, f, schedule.ID); r.Phase != "scheduled" || r.Revision != 1 {
		t.Fatal("audit failure changed schedule state")
	}
	if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || p.Activated != 1 {
		t.Fatal("rolled-back activation could not retry", p, err)
	}
}

func TestUpdateScheduleTamperCannotChangeTimingOrStarveSelectedValidWork(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	bad := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	good := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	r, err := scanUpdateSchedule(f.store.db.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1`, bad.ID))
	if err != nil {
		t.Fatal(err)
	}
	changed := *r
	changed.NotBefore = changed.NotBefore.Add(-time.Second)
	if err := f.store.openUpdateSchedule(&changed); err == nil {
		t.Fatal("ciphertext authorized an earlier activation")
	}
	changed = *r
	changed.NextAttemptAt = changed.NextAttemptAt.Add(time.Minute)
	if err := f.store.openUpdateSchedule(&changed); err == nil {
		t.Fatal("mutable backoff escaped its authenticated state")
	}
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_update_schedules SET revision=revision+1,phase='waiting',not_before=not_before-INTERVAL '1 second' WHERE id=$1`, bad.ID); err == nil {
		t.Fatal("SQL changed immutable activation intent")
	}
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_update_schedules DISABLE TRIGGER mdm_windows_update_schedule_identity`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE mdm_windows_update_schedules SET encrypted_state=$2 WHERE id=$1`, bad.ID, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_update_schedules ENABLE TRIGGER mdm_windows_update_schedule_identity`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if p, err := f.store.ProcessDueUpdateSchedules(context.Background(), 25); !errors.Is(err, ErrAuthoritySecret) || p.Failed != 1 || p.Activated != 1 {
		t.Fatal("corrupt record blocked other selected work or gained authority", p, err)
	}
	done := updateTestScheduleRead(t, f, good.ID)
	source, err := scanUpdateRollout(f.store.db.QueryRow(`SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE id=$1`, done.RolloutID))
	if err != nil {
		t.Fatal(err)
	}
	source.ScheduleID = ""
	if err := f.store.openUpdateRollout(source); err == nil {
		t.Fatal("scheduled rollout became immediate authority")
	}
	if data, err := json.Marshal(done); err != nil || string(data) != "{}" {
		t.Fatal("generic serialization exposed schedule targets", err)
	}
}

func TestUpdateScheduleCancellationLockWinsBeforeWorkerActivation(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	schedule := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var id string
	var pid int
	if err := tx.QueryRow(`SELECT id,pg_backend_pid() FROM mdm_windows_update_schedules WHERE id=$1 FOR UPDATE`, schedule.ID).Scan(&id, &pid); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- f.store.CancelUpdateSchedule(context.Background(), "operator", f.identity.Scope, schedule.ID, 1)
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	if p, err := f.store.ProcessDueUpdateSchedules(context.Background(), 25); err != nil || p.Processed != 0 {
		t.Fatal("worker bypassed an in-progress cancellation lock", p, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if p, err := f.store.ProcessDueUpdateSchedules(context.Background(), 25); err != nil || p.Processed != 0 {
		t.Fatal("canceled schedule later activated", p, err)
	}
	if updateTestScheduleRead(t, f, schedule.ID).Phase != "canceled" {
		t.Fatal("cancellation did not persist")
	}
}

func TestUpdateScheduleAdmissionBoundsCapAndIdempotency(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	ctx := context.Background()
	notBefore := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	for _, bad := range []struct {
		start            time.Time
		window, lifetime time.Duration
	}{
		{time.Time{}, time.Hour, time.Hour},
		{notBefore.Add(time.Nanosecond), time.Hour, time.Hour},
		{notBefore, 59 * time.Second, time.Hour},
		{notBefore, 7*24*time.Hour + time.Second, time.Hour},
		{notBefore, time.Hour, 59 * time.Second},
		{notBefore, time.Hour, time.Hour + time.Nanosecond},
		{notBefore.Add(91 * 24 * time.Hour), time.Hour, time.Hour},
		{notBefore.Add(-2 * time.Hour), time.Hour, time.Hour},
	} {
		if value, err := f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, bad.start, bad.window, bad.lifetime); !errors.Is(err, ErrUpdateSchedule) || value != nil {
			t.Fatal("invalid scheduling boundary accepted", err)
		}
	}
	first := updateTestSchedule(t, f, ring, notBefore)
	for n := 1; n < 256; n++ {
		updateTestSchedule(t, f, ring, notBefore)
	}
	if value, err := f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, notBefore, time.Hour, time.Hour); !errors.Is(err, ErrUpdateScheduleFull) || value != nil {
		t.Fatal("active schedule cap was bypassed", err)
	}
	if retry, err := f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, first.RequestKey, []string{f.identity.DeviceID}, false, notBefore.In(time.FixedZone("Synthetic", 3600)), time.Hour, time.Hour); err != nil || retry.ID != first.ID {
		t.Fatal("full queue or equivalent timezone broke exact retry", err)
	}
	for _, changed := range []struct {
		start  time.Time
		window time.Duration
	}{
		{notBefore.Add(time.Second), time.Hour}, {notBefore, 2 * time.Hour},
	} {
		if value, err := f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, first.RequestKey, []string{f.identity.DeviceID}, false, changed.start, changed.window, time.Hour); !errors.Is(err, ErrUpdateScheduleConflict) || value != nil {
			t.Fatal("schedule retry changed its approved window", err)
		}
	}
	if err := f.store.CancelUpdateSchedule(ctx, "operator", f.identity.Scope, first.ID, 2); !errors.Is(err, ErrUpdateScheduleConflict) {
		t.Fatal("stale cancellation review succeeded", err)
	}
	if err := f.store.CancelUpdateSchedule(ctx, "operator", f.identity.Scope, first.ID, 1); err != nil {
		t.Fatal(err)
	}
	updateTestSchedule(t, f, ring, notBefore)
	var active int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_update_schedules WHERE phase IN ('scheduled','waiting')`).Scan(&active); err != nil || active != 256 {
		t.Fatal("cancellation did not release exactly one schedule slot", err)
	}
}

func TestUpdateScheduleMigrationPreservesActiveImmediateRingRun(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	ctx := context.Background()
	cohort, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request, response := cspTestStart(t, f)
	updateTestRemoveScheduleMigration(t, f.store)
	for n := 0; n < 2; n++ {
		if err := f.store.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
		t.Fatal("schedule migration changed existing ring delivery", err)
	}
	for step := 0; step < 5; step++ {
		response, err = f.process(syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), ring.Policy, false, false)))
		if err != nil {
			t.Fatal("existing immediate ring run failed after upgrade", step, err)
		}
	}
	if detail := updateTestRead(t, f, cohort.Runs[0].ID); detail.Phase != "verified" {
		t.Fatal("migration lost existing ring evidence", detail.Phase)
	}
	if previous, err := f.store.UpdateRolloutDetails(ctx, "operator", f.identity.Scope, cohort.ID); err != nil || previous.ScheduleID != "" {
		t.Fatal("migration attached unreviewed timing to old work", err)
	}
}
