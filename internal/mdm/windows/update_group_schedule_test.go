package windows

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/stretchr/testify/require"
)

func TestUpdateGroupScheduleActivationAndOriginalProvenance(t *testing.T) {
	f, group := updateGroupFixture(t)
	ctx := t.Context()
	sources := inventory.DeviceSources{Windows: true}
	ring := updateTestRing(t, f, updateTestFullPolicy())
	start := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	key := uuid.NewString()
	save := func() (*UpdateSchedule, error) {
		return f.store.ScheduleUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, []string{f.identity.DeviceID}, false, start, time.Hour, time.Hour, sources, group.ID, 1)
	}
	plan, err := save()
	require.NoError(t, err)
	require.Equal(t, group.Name, plan.Group.Name)
	var count int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_update_runs`).Scan(&count))
	require.Zero(t, count)
	progress, err := f.store.ProcessDueUpdateSchedules(ctx, 25)
	require.NoError(t, err)
	require.Equal(t, 1, progress.Activated)
	current := updateTestScheduleRead(t, f, plan.ID)
	require.Equal(t, "activated", current.Phase)
	rollout, err := f.store.UpdateRolloutDetails(ctx, "operator", f.identity.Scope, current.RolloutID)
	require.NoError(t, err)
	require.Equal(t, group.Name, rollout.Group.Name)
	require.Equal(t, plan.ID, rollout.ScheduleID)
	storedRollout, err := scanUpdateRollout(f.store.db.QueryRow(`SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE id=$1`, rollout.ID))
	require.NoError(t, err)
	require.NoError(t, f.store.openUpdateRollout(storedRollout))
	tx, err := f.store.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, f.store.validateUpdateRolloutSchedule(ctx, tx, storedRollout))
	storedRollout.Group.Name = "A different authenticated group label"
	require.ErrorIs(t, f.store.validateUpdateRolloutSchedule(ctx, tx, storedRollout), ErrAuthoritySecret)
	require.NoError(t, tx.Rollback())
	definition := group.DeviceGroupDefinition
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, f.store.db, f.store.permissions, "operator", f.identity.Scope, group.ID, 1, definition)
	require.NoError(t, err)
	replay, err := save()
	require.NoError(t, err)
	require.Equal(t, current.ID, replay.ID)
	require.Equal(t, "activated", replay.Phase)
	require.Equal(t, current.RolloutID, replay.RolloutID)
	_, err = f.store.ScheduleUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, []string{f.identity.DeviceID}, false, start, time.Hour, time.Hour)
	require.ErrorIs(t, err, ErrUpdateScheduleConflict)
	_, err = f.store.ScheduleUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, []string{f.identity.DeviceID}, false, start, time.Hour, time.Hour, sources, group.ID, 2)
	require.ErrorIs(t, err, ErrUpdateScheduleConflict)
	_, response := cspTestStart(t, f)
	for range 7 {
		request := syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), ring.Policy, false, false))
		response, err = f.process(request)
		require.NoError(t, err)
	}
	require.Equal(t, "verified", updateTestRead(t, f, rollout.Runs[0].ID).Phase)
	encoded, err := json.Marshal(replay)
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(encoded))
}

func TestUpdateGroupScheduleRejectsInvalidProtectedIntent(t *testing.T) {
	f, group := updateGroupFixture(t)
	sources := inventory.DeviceSources{Windows: true}
	ring := updateTestRing(t, f, updateTestPolicy())
	plan, err := f.store.ScheduleUpdateRingFromGroup(t.Context(), "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), time.Hour, time.Hour, sources, group.ID, 1)
	require.NoError(t, err)
	for _, mode := range []string{"legacy-with-group", "legacy-with-sources", "missing-group", "missing-sources", "disabled-windows", "invalid-revision", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			stored, err := scanUpdateSchedule(f.store.db.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1`, plan.ID))
			require.NoError(t, err)
			configured := sources
			intent := updateRolloutTargets{Version: 2, Group: sealUpdateGroupSource(plan.Group), Sources: &configured, Devices: plan.Targets}
			switch mode {
			case "legacy-with-group":
				intent.Version, intent.Sources = 1, nil
			case "legacy-with-sources":
				intent.Version, intent.Group = 1, nil
			case "missing-group":
				intent.Group = nil
			case "missing-sources":
				intent.Sources = nil
			case "disabled-windows":
				configured.Windows = false
			case "invalid-revision":
				intent.Group.Revision = 0
			}
			plain, err := json.Marshal(intent)
			require.NoError(t, err)
			stored.encryptedTargets, err = f.store.secrets.sealBounded(plain, updateSchedulePurpose(stored), 8192)
			require.NoError(t, err)
			if mode == "ciphertext" {
				stored.encryptedTargets[len(stored.encryptedTargets)-1] ^= 1
			}
			require.Error(t, f.store.openUpdateSchedule(stored))
		})
	}
}

func TestUpdateGroupSchedulesRetireChangedReviewedIntent(t *testing.T) {
	for _, change := range []string{"definition", "membership", "sources", "late-audit"} {
		t.Run(change, func(t *testing.T) {
			f, group := updateGroupFixture(t)
			ctx := t.Context()
			sources := inventory.DeviceSources{Windows: true}
			ring := updateTestRing(t, f, updateTestPolicy())
			start := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
			plan, err := f.store.ScheduleUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, start, time.Hour, time.Hour, sources, group.ID, 1)
			require.NoError(t, err)
			worker := f.store
			reason := "group_changed"
			switch change {
			case "definition":
				d := group.DeviceGroupDefinition
				d.Archived = true
				_, err = inventory.SaveDeviceGroup(ctx, f.store.db, f.store.permissions, "operator", f.identity.Scope, group.ID, 1, d)
				require.NoError(t, err)
			case "membership":
				managementTestEnrollment(t, f.store, f.options)
			case "sources":
				worker = f.store.WithGroupInventorySources(inventory.DeviceSources{Apple: true, Windows: true})
				reason = "group_sources_changed"
				require.Equal(t, sources, f.store.groupSources)
				// A restart with changed enabled stores still recognizes the
				// original request. Only new work needs the current configuration.
				replay, replayErr := worker.ScheduleUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, plan.RequestKey, plan.Targets, false, start, time.Hour, time.Hour, worker.groupSources, group.ID, 1)
				require.NoError(t, replayErr)
				require.Equal(t, plan.ID, replay.ID)
				_, replayErr = worker.ScheduleUpdateRingFromGroup(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), plan.Targets, false, start, time.Hour, time.Hour, sources, group.ID, 1)
				require.ErrorIs(t, replayErr, ErrUpdateGroupConflict)
			case "late-audit":
				_, err = f.store.db.Exec(`CREATE FUNCTION owned_group_schedule_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='schedule.activated' THEN RAISE EXCEPTION 'owned late group activation failure'; END IF;RETURN NEW;END$$;CREATE TRIGGER owned_group_schedule_audit_failure BEFORE INSERT ON mdm_windows_update_schedule_audit FOR EACH ROW EXECUTE FUNCTION owned_group_schedule_audit_failure()`)
				require.NoError(t, err)
			}
			progress, err := worker.ProcessDueUpdateSchedules(ctx, 25)
			if change == "late-audit" {
				require.Error(t, err)
				require.Zero(t, progress.Activated)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, progress.Blocked)
			}
			for _, table := range []string{"mdm_windows_update_rollouts", "mdm_windows_update_runs", "mdm_windows_csp_commands"} {
				var n int
				require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
				require.Zero(t, n)
			}
			read := updateTestScheduleRead(t, f, plan.ID)
			if change == "late-audit" {
				require.Equal(t, "scheduled", read.Phase)
			} else {
				require.Equal(t, "blocked", read.Phase)
				require.Equal(t, reason, read.Reason)
				progress, err = f.store.ProcessDueUpdateSchedules(ctx, 25)
				require.NoError(t, err)
				require.Zero(t, progress.Activated)
			}
		})
	}
}
