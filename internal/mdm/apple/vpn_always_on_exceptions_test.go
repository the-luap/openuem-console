package apple

import (
	"fmt"
	"testing"

	"howett.net/plist"
)

func TestAlwaysOnExceptionRevisionsAndRestorationGuardEveryTarget(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Always On exception phone", "iPhone16,1", "18.0")
	pad, _, _ := testEnrollPlatformWithKey(t, s, scope, "Always On exception iPad", "iPad14,3", "18.0")
	for i, tc := range []struct {
		key, below, at string
		value          any
	}{
		{"ServiceExceptions", "11.2.6", "11.3", []any{map[string]any{"ServiceName": "CellularServices", "Action": "Drop"}}},
		{"ApplicationExceptions", "13.5.1", "13.6", []any{map[string]any{"BundleIdentifier": "com.example.App", "LimitToProtocols": []any{"UDP"}}}},
		{"ServiceExceptions", "17.3.1", "17.4", []any{map[string]any{"ServiceName": "DeviceCommunication", "Action": "Allow"}}},
	} {
		identifier := fmt.Sprintf("com.example.always-on-exceptions.%d", i)
		for _, id := range []string{phone.ID, pad.ID} {
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2,supervised=true,supervised_reported=true,inventory_at=clock_timestamp() WHERE id=$1`, id, tc.below)
		}
		p, err := s.SaveProfile(t.Context(), 1, "", 0, vpnConfigurationProfileData(t, "System", identifier, vpnSettings("AlwaysOn")), "admin")
		if err != nil {
			t.Fatal(err)
		}
		assign := func(desired string) error {
			return s.AssignProfile(t.Context(), scope, p.ID, []string{phone.ID, pad.ID}, desired, "admin")
		}
		if err = assign("installed"); err != nil {
			t.Fatal(err)
		}
		first := revisionHistory(t, s, p.ID)[0]
		commandCount := func() int {
			t.Helper()
			var count int
			if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1)+(SELECT count(*) FROM mdm_apple_user_commands WHERE profile_id=$1)`, p.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			return count
		}
		assertUnchanged := func(revision, commands int, uuid string) {
			t.Helper()
			stored, err := s.Profile(t.Context(), 1, p.ID)
			if err != nil || stored.Revision != revision || stored.UUID != uuid || len(revisionHistory(t, s, p.ID)) != revision || commandCount() != commands {
				t.Fatal("rejected exception change modified catalog, history or commands", err)
			}
		}
		changed := vpnSettings("AlwaysOn")
		changed["AlwaysOn"].(map[string]any)[tc.key] = tc.value
		data := vpnConfigurationProfileData(t, "System", identifier, changed)
		// One eligible target must not hide the second target's older OS.
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, phone.ID, tc.at)
		before := commandCount()
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, data, "admin"); err == nil {
			t.Fatal("exception revision reached an unsupported assigned iPad")
		}
		assertUnchanged(1, before, p.UUID)
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, pad.ID, tc.at)
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, data, "admin"); err != nil {
			t.Fatal("exception rejected with eligible targets", err)
		}
		modern := revisionHistory(t, s, p.ID)[0]
		restored, err := s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Synthetic baseline restoration", "admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, pad.ID, tc.below)
		before = commandCount()
		if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, modern.ID, 3, "Synthetic exception restoration check", "admin", nil); err == nil {
			t.Fatal("exception restoration reached an unsupported assigned iPad")
		}
		assertUnchanged(3, before, restored.UUID)
		// Historical encrypted rows are revalidated before new installation;
		// malformed exceptions must not make profile removal unavailable.
		var root map[string]any
		if _, err = plist.Unmarshal(restored.Payload, &root); err != nil {
			t.Fatal(err)
		}
		root["PayloadContent"].([]any)[0].(map[string]any)["AlwaysOn"].(map[string]any)["AllowedCaptiveNetworkPlugins"] = []any{map[string]any{"BundleIdentifier": "com.example.*"}}
		bad, err := plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := s.secrets.seal(bad, secretPurpose(1, p.ID, "profile"))
		if err != nil {
			t.Fatal(err)
		}
		adeExec(t, s, `UPDATE mdm_apple_profiles SET payload=$2 WHERE id=$1`, p.ID, sealed)
		before = commandCount()
		if err = assign("installed"); err == nil {
			t.Fatal("legacy malformed exception bypassed assignment validation")
		}
		assertUnchanged(3, before, restored.UUID)
		if err = assign("removed"); err != nil {
			t.Fatal("legacy exception prevented removal", err)
		}
	}
}
