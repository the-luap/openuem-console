package apple

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateScheduleReceiptSourceCompatibilityAndStateBinding(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	s := f.store
	original := f.schedule(t, time.Now().UTC().Add(time.Hour).Truncate(time.Second))
	stored, err := s.scanUpdateSchedule(s.db.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1`, original.ID))
	require.NoError(t, err)
	plain, err := s.secrets.open(stored.encryptedIntent, updateSchedulePurpose(stored))
	require.NoError(t, err)
	defer clear(plain)
	var saved updateScheduleIntent
	require.NoError(t, json.Unmarshal(plain, &saved))
	require.Equal(t, 2, saved.Version)
	require.Equal(t, f.scope, *saved.GroupScope)
	for _, condition := range []string{"legacy", "current", "missing-source", "foreign-tenant", "foreign-site", "negative-site", "legacy-with-source", "unknown-version", "unbound-state"} {
		t.Run(condition, func(t *testing.T) {
			wire := saved
			source := f.scope
			wire.GroupScope = &source
			switch condition {
			case "legacy":
				wire.Version, wire.GroupScope = 1, nil
			case "missing-source":
				wire.GroupScope = nil
			case "foreign-tenant":
				source.TenantID = 2
			case "foreign-site":
				source.SiteID = 3
			case "negative-site":
				source.SiteID = -1
			case "legacy-with-source":
				wire.Version = 1
			case "unknown-version":
				wire.Version = 3
			case "unbound-state":
				source.SiteID = 0
			}
			data, err := json.Marshal(wire)
			require.NoError(t, err)
			defer clear(data)
			changed := *stored
			changed.encryptedIntent, err = s.secrets.seal(data, updateSchedulePurpose(stored))
			require.NoError(t, err)
			if condition != "unbound-state" {
				require.NoError(t, s.sealUpdateScheduleState(&changed))
			}
			columns := strings.Replace(updateScheduleColumns, "CASE WHEN octet_length(encrypted_intent)<=32796 THEN encrypted_intent ELSE NULL END", "$2::bytea", 1)
			columns = strings.Replace(columns, "CASE WHEN octet_length(encrypted_state)<=1052 THEN encrypted_state ELSE NULL END", "$3::bytea", 1)
			result, err := s.scanUpdateSchedule(s.db.QueryRow(`SELECT `+columns+` FROM mdm_apple_update_schedules WHERE id=$1`, original.ID, changed.encryptedIntent, changed.encryptedState))
			if condition == "legacy" || condition == "current" {
				require.NoError(t, err)
				require.Equal(t, &stored.UpdateSchedule, &result.UpdateSchedule)
			} else {
				require.ErrorIs(t, err, ErrUpdateScheduleIntegrity)
				require.Nil(t, result)
			}
		})
	}
}

func TestUpdateScheduleLegacyIntentStillActivatesOriginalSite(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	s := f.store
	original := f.schedule(t, time.Now().UTC().Truncate(time.Second))
	stored, err := s.scanUpdateSchedule(s.db.QueryRow(`SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1`, original.ID))
	require.NoError(t, err)
	plain, err := s.secrets.open(stored.encryptedIntent, updateSchedulePurpose(stored))
	require.NoError(t, err)
	defer clear(plain)
	var wire updateScheduleIntent
	require.NoError(t, json.Unmarshal(plain, &wire))
	wire.Version, wire.GroupScope = 1, nil
	legacy, err := json.Marshal(wire)
	require.NoError(t, err)
	defer clear(legacy)
	stored.encryptedIntent, err = s.secrets.seal(legacy, updateSchedulePurpose(stored))
	require.NoError(t, err)
	require.NoError(t, s.sealUpdateScheduleState(stored))
	// Simulate a correctly authenticated schedule written by the old console.
	// Only this owned fixture bypasses the immutable-input trigger.
	_, err = s.db.Exec(`ALTER TABLE mdm_apple_update_schedules DISABLE TRIGGER mdm_apple_update_schedule_identity`)
	require.NoError(t, err)
	_, changeErr := s.db.Exec(`UPDATE mdm_apple_update_schedules SET encrypted_intent=$1,encrypted_state=$2 WHERE id=$3`, stored.encryptedIntent, stored.encryptedState, original.ID)
	_, restoreErr := s.db.Exec(`ALTER TABLE mdm_apple_update_schedules ENABLE TRIGGER mdm_apple_update_schedule_identity`)
	require.NoError(t, restoreErr)
	require.NoError(t, changeErr)
	require.Equal(t, 1, f.process(t).Activated)
	current := f.details(t, original.ID)
	require.Equal(t, f.scope, current.GroupScope)
	receipt, err := s.UpdatePlanGroupAssignmentDetails(t.Context(), "operator", f.permissions, f.scope, f.plan.ID, current.AssignmentID)
	require.NoError(t, err)
	require.Equal(t, f.scope, receipt.GroupScope)
	require.Equal(t, f.device.ID, receipt.Commands[0].Selection.DeviceID)
}
