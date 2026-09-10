package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func updateTestRemoveScheduleMigration(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`DROP TABLE mdm_windows_update_schedule_audit; ALTER TABLE mdm_windows_update_schedules DROP CONSTRAINT mdm_windows_update_schedule_rollout; ALTER TABLE mdm_windows_update_rollouts DROP COLUMN schedule_id; DROP TABLE mdm_windows_update_schedules; DROP FUNCTION mdm_windows_keep_update_schedule(); DELETE FROM mdm_windows_migrations WHERE name='migrations/009_update_schedules.sql'`); err != nil {
		t.Fatal(err)
	}
}

func updateTestSchedule(t *testing.T, f syncMLStoreFixture, ring *UpdateRingRevision, notBefore time.Time) *UpdateSchedule {
	t.Helper()
	r, err := f.store.ScheduleUpdateRing(context.Background(), "operator", f.identity.Scope, ring.RingID, ring.Revision, uuid.NewString(), []string{f.identity.DeviceID}, false, notBefore, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func updateTestScheduleRead(t *testing.T, f syncMLStoreFixture, id string) *UpdateSchedule {
	t.Helper()
	r, err := f.store.UpdateScheduleDetails(context.Background(), "operator", f.identity.Scope, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Only this owned test schema adjusts immutable timestamps to exercise exact
// deadlines without sleeping for production scheduling windows. Both encrypted
// target intent and mutable state are resealed with the fixture's test key.
func updateTestScheduleTime(t *testing.T, f syncMLStoreFixture, id string, adjust func(*updateStoredSchedule, time.Time)) *updateStoredSchedule {
	t.Helper()
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	r, err := scanUpdateSchedule(tx.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.openUpdateSchedule(r); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	adjust(r, now)
	data, err := json.Marshal(updateRolloutTargets{Version: 1, Devices: r.Targets})
	if err != nil {
		t.Fatal(err)
	}
	r.encryptedTargets, err = f.store.secrets.sealBounded(data, updateSchedulePurpose(r), 8192)
	clear(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.sealUpdateScheduleState(r); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_update_schedules DISABLE TRIGGER mdm_windows_update_schedule_identity`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE mdm_windows_update_schedules SET created_at=$2,not_before=$3,expires_at=$4,updated_at=$5,next_attempt_at=$6,encrypted_targets=$7,encrypted_state=$8 WHERE id=$1`, id, r.CreatedAt, r.NotBefore, r.ExpiresAt, r.UpdatedAt, r.NextAttemptAt, r.encryptedTargets, r.encryptedState); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE mdm_windows_update_schedules ENABLE TRIGGER mdm_windows_update_schedule_identity`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUpdateScheduleNotEarlyConcurrentActivationAndPinnedDelivery(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestFullPolicy())
	ctx := context.Background()
	schedule := updateTestSchedule(t, f, ring, time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond))
	if progress, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || progress.Processed != 0 {
		t.Fatal("future schedule ran early", err)
	}
	due := updateTestScheduleTime(t, f, schedule.ID, func(r *updateStoredSchedule, now time.Time) {
		r.NotBefore = now.Add(-time.Second)
		r.NextAttemptAt = r.NotBefore
		r.ExpiresAt = now.Add(time.Hour)
	})
	var workers sync.WaitGroup
	type result struct {
		p   UpdateScheduleProgress
		err error
	}
	results := make(chan result, 6)
	for i := 0; i < 6; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			p, err := f.store.ProcessDueUpdateSchedules(ctx, 25)
			results <- result{p, err}
		}()
	}
	workers.Wait()
	close(results)
	activated := 0
	for result := range results {
		if result.err != nil {
			t.Fatal("concurrent activation failed", result.err)
		}
		activated += result.p.Activated
	}
	if activated != 1 {
		t.Fatal("schedule did not activate exactly once", activated)
	}
	current := updateTestScheduleRead(t, f, schedule.ID)
	if current.Phase != "activated" || current.RolloutID == "" || current.Attempts != 1 {
		t.Fatal("activation state did not commit")
	}
	cohort, err := f.store.UpdateRolloutDetails(ctx, "operator", f.identity.Scope, current.RolloutID)
	if err != nil || cohort.ScheduleID != schedule.ID || len(cohort.Runs) != 1 {
		t.Fatal("activation lost exact cohort provenance", err)
	}
	if _, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, uuid.NewString(), 1, "Disabled after activation", ring.Policy, false); err != nil {
		t.Fatal(err)
	}
	f.store, err = NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || p.Processed != 0 {
		t.Fatal("restart activated a completed schedule again", err)
	}
	replay, err := f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, schedule.RequestKey, []string{f.identity.DeviceID}, false, due.NotBefore, due.ExpiresAt.Sub(due.NotBefore), time.Hour)
	if err != nil || !reflect.DeepEqual(replay, current) {
		t.Fatal("completed schedule retry changed the source", err)
	}
	_, response := cspTestStart(t, f)
	for step := 0; step < 7; step++ {
		request := syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), ring.Policy, false, false))
		response, err = f.process(request)
		if err != nil {
			t.Fatal("activated schedule did not deliver its pinned policy", step, err)
		}
		if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
			t.Fatal("scheduled command replay changed", err)
		}
	}
	if updateTestRead(t, f, cohort.Runs[0].ID).Phase != "verified" {
		t.Fatal("scheduled policy did not verify")
	}
	if err := f.store.CancelUpdateSchedule(ctx, "operator", f.identity.Scope, schedule.ID, current.Revision); !errors.Is(err, ErrCSPAlreadySent) {
		t.Fatal("cancel pretended to recall activated work", err)
	}
}

func TestUpdateScheduleChangedAuthorityRingAndDeviceBlockActivation(t *testing.T) {
	for _, cause := range []string{"permission", "ring", "device"} {
		t.Run(cause, func(t *testing.T) {
			f := syncMLTestStore(t)
			ring := updateTestRing(t, f, updateTestPolicy())
			schedule := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
			ctx := context.Background()
			want := ""
			switch cause {
			case "permission":
				if err := f.store.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: f.identity.Scope}}); err != nil {
					t.Fatal(err)
				}
				want = "authority_changed"
			case "ring":
				if _, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, uuid.NewString(), 1, "Changed ring", ring.Policy, true); err != nil {
					t.Fatal(err)
				}
				want = "ring_assignment_conflict"
			case "device":
				if _, err := f.store.db.Exec(`UPDATE mdm_windows_devices SET revoked_at=clock_timestamp() WHERE id=$1`, f.identity.DeviceID); err != nil {
					t.Fatal(err)
				}
				want = "device_unavailable"
			}
			if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || p.Blocked != 1 {
				t.Fatal("changed prerequisite did not block activation", p, err)
			}
			if r := updateTestScheduleRead(t, f, schedule.ID); r.Reason != want || r.RolloutID != "" {
				t.Fatal("blocked schedule lost its cause", r.Reason)
			}
			var count int
			if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_update_rollouts`).Scan(&count); err != nil || count != 0 {
				t.Fatal("blocked schedule left a partial rollout", err)
			}
		})
	}
}

func TestUpdateScheduleExpiredAndCanceledNeverCreateCommands(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	ctx := context.Background()
	expired := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	updateTestScheduleTime(t, f, expired.ID, func(r *updateStoredSchedule, now time.Time) {
		r.CreatedAt = now.Add(-2 * time.Minute)
		r.UpdatedAt = r.CreatedAt
		r.NotBefore = r.CreatedAt
		r.NextAttemptAt = r.NotBefore
		r.ExpiresAt = now.Add(-time.Minute)
	})
	canceled := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	if err := f.store.CancelUpdateSchedule(ctx, "operator", f.identity.Scope, canceled.ID, canceled.Revision); err != nil {
		t.Fatal(err)
	}
	if p, err := f.store.ProcessDueUpdateSchedules(ctx, 25); err != nil || p.Expired != 1 || p.Activated != 0 {
		t.Fatal("expired/canceled schedule created work", p, err)
	}
	if r := updateTestScheduleRead(t, f, expired.ID); r.Phase != "expired" || r.Reason != "activation_window_expired" {
		t.Fatal("expiry not retained")
	}
	list, err := f.store.UpdateSchedules(ctx, "operator", f.identity.Scope, 0, 100)
	if err != nil || len(list) != 2 {
		t.Fatal("scoped schedule history lost entries", err)
	}
	var count int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_commands`).Scan(&count); err != nil || count != 0 {
		t.Fatal("terminal schedules left commands", err)
	}
}
