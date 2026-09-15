package apple

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"howett.net/plist"
)

func drainTimeZoneInventory(t *testing.T, s *Store, d *Device, zone any, present bool) {
	t.Helper()
	ctx := t.Context()
	require.NoError(t, s.RefreshInventory(ctx, Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID, "owned timezone collector"))
	message := map[string]any{"UDID": d.UDID, "Status": "Idle"}
	seen := false
	for range 30 {
		payload, err := s.Connect(ctx, d, message)
		require.NoError(t, err)
		if len(payload) == 0 {
			require.True(t, seen)
			return
		}
		var envelope map[string]any
		_, err = plist.Unmarshal(payload, &envelope)
		require.NoError(t, err)
		command := envelope["Command"].(map[string]any)
		message = map[string]any{"UDID": d.UDID, "Status": "Acknowledged", "CommandUUID": envelope["CommandUUID"]}
		switch command["RequestType"] {
		case "DeviceInformation":
			seen = true
			queries, ok := command["Queries"].([]any)
			require.True(t, ok)
			require.Equal(t, supportsTimeZoneQuery(*d), slices.Contains(queries, any("TimeZone")))
			info := map[string]any{"DeviceName": d.Name, "ProductName": d.Model, "OSVersion": d.OSVersion, "BuildVersion": d.BuildVersion, "IsSupervised": true}
			if present {
				info["TimeZone"] = zone
			}
			message["QueryResponses"] = info
		case "SecurityInfo":
			message["SecurityInfo"] = map[string]any{}
		case "InstalledApplicationList":
			message["InstalledApplicationList"] = []any{}
		case "ProfileList":
			message["ProfileList"] = []any{}
		case "AvailableOSUpdates":
			message["AvailableOSUpdates"] = []any{}
		}
	}
	t.Fatal("owned time zone inventory did not drain")
}

func TestTimeZoneObservationCollectsAuthenticatedQueriesWithoutMergedFallback(t *testing.T) {
	s, _, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_timezone_observations`).Scan(&count))
	require.Zero(t, count)
	read := func() (string, time.Time) {
		t.Helper()
		var name, source string
		var at time.Time
		require.NoError(t, s.db.QueryRow(`SELECT name,source,recorded_at FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID).Scan(&name, &source, &at))
		require.Equal(t, "device_information", source)
		return name, at
	}
	drainTimeZoneInventory(t, s, d, "Europe/Berlin", true)
	name, at := read()
	require.Equal(t, "Europe/Berlin", name)
	require.NoError(t, s.saveStatus(ctx, d, &StatusReport{StatusItems: map[string]any{"softwareupdate": map[string]any{"install-state": "idle"}}}))
	_, same := read()
	require.True(t, at.Equal(same))
	drainTimeZoneInventory(t, s, d, "Asia/Kathmandu", true)
	name, updated := read()
	require.Equal(t, "Asia/Kathmandu", name)
	require.False(t, updated.Before(at))
	for _, bad := range []any{"Local", "../UTC", "Unknown/Zone", true, map[string]any{"name": "UTC"}} {
		drainTimeZoneInventory(t, s, d, "Europe/Berlin", true)
		drainTimeZoneInventory(t, s, d, bad, true)
		require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID).Scan(&count))
		require.Zero(t, count)
	}
	drainTimeZoneInventory(t, s, d, "UTC", true)
	drainTimeZoneInventory(t, s, d, nil, false)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID).Scan(&count))
	require.Zero(t, count)
}

func TestTimeZoneObservationRollsBackWithLateProtocolFailure(t *testing.T) {
	s, _, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	drainTimeZoneInventory(t, s, d, "Europe/Berlin", true)
	var originalTime time.Time
	require.NoError(t, s.db.QueryRow(`SELECT recorded_at FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID).Scan(&originalTime))
	tx, err := s.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	id, err := s.enqueue(ctx, tx, d, "DeviceInformation", map[string]any{"Queries": inventoryQueriesFor(*d)}, nil, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	_, err = s.Connect(ctx, d, map[string]any{"UDID": d.UDID, "Status": "Idle"})
	require.NoError(t, err)
	_, err = s.db.Exec(`CREATE FUNCTION owned_timezone_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned timezone late protocol failure'; END $$; CREATE TRIGGER owned_timezone_late_failure BEFORE UPDATE OF last_seen ON mdm_apple_devices FOR EACH ROW EXECUTE FUNCTION owned_timezone_late_failure()`)
	require.NoError(t, err)
	_, err = s.Connect(ctx, d, map[string]any{"UDID": d.UDID, "Status": "Acknowledged", "CommandUUID": id, "QueryResponses": map[string]any{"ProductName": d.Model, "OSVersion": d.OSVersion, "TimeZone": "Asia/Kathmandu"}})
	require.Error(t, err)
	var name, status string
	var at time.Time
	require.NoError(t, s.db.QueryRow(`SELECT name,recorded_at FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID).Scan(&name, &at))
	require.Equal(t, "Europe/Berlin", name)
	require.True(t, originalTime.Equal(at))
	require.NoError(t, s.db.QueryRow(`SELECT status FROM mdm_apple_commands WHERE id=$1`, id).Scan(&status))
	require.Equal(t, "sent", status)
}

func TestTimeZoneQueryUsesDeclaredPlatformVersionGates(t *testing.T) {
	for _, tc := range []struct {
		model, version string
		supported      bool
	}{
		{"iPhone16,1", "13.7", false}, {"iPhone16,1", "14.0", true}, {"iPad14,1", "14.0", true},
		{"Mac16,1", "15.0", false}, {"Mac16,1", "26.0", true}, {"Mac16,1", "invalid", false},
		{"Unknown", "26.0", false},
	} {
		d := Device{Model: tc.model, OSVersion: tc.version}
		require.Equal(t, tc.supported, supportsTimeZoneQuery(d))
		require.Equal(t, tc.supported, slices.Contains(inventoryQueriesFor(d), "TimeZone"))
	}
}

func TestTimeZoneObservationKeepsUnsupportedMacUnknown(t *testing.T) {
	for _, version := range []string{"15.0", "26.0"} {
		t.Run(version, func(t *testing.T) {
			s := testStore(t)
			testSettings(t, s, 1)
			d, _, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Owned timezone Mac", "Mac16,1", version)
			drainTimeZoneInventory(t, s, d, "Europe/Berlin", true)
			var count int
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID).Scan(&count))
			if version == "26.0" {
				require.Equal(t, 1, count)
			} else {
				require.Zero(t, count)
			}
			drainTimeZoneInventory(t, s, d, nil, false)
			require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID).Scan(&count))
			require.Zero(t, count)
		})
	}
}
