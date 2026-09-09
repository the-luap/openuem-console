package apple

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func TestIKEv2OnDemandUploadRevisionAndLegacyAssignment(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "On-demand Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	u := testUserEnroll(t, s, mac, "alice")
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "On-demand phone", "iPhone16,1", "18.0")
	adeExec(t, s, `UPDATE mdm_apple_devices SET supervised=true,supervised_reported=true,inventory_at=clock_timestamp() WHERE id=$1`, phone.ID)
	for i, tc := range []struct{ kind, channel string }{
		{"com.apple.vpn.managed", "System"}, {"com.apple.vpn.managed", "User"},
		{"com.apple.vpn.managed.applayer", "System"}, {"com.apple.vpn.managed.applayer", "User"}, {"AlwaysOn", "System"},
	} {
		identifier := fmt.Sprintf("com.example.on-demand.%d", i)
		data := func(rules any) []byte {
			t.Helper()
			payload := vpnSettings("IKEv2")
			c := payload["IKEv2"].(map[string]any)
			if tc.kind == "AlwaysOn" {
				payload = vpnSettings("AlwaysOn")
				c = payload["AlwaysOn"].(map[string]any)["TunnelConfigurations"].([]any)[0].(map[string]any)
			} else {
				payload["PayloadType"], payload["VPNUUID"] = tc.kind, uuid.NewString()
			}
			c["OnDemandEnabled"], c["OnDemandRules"] = 0, rules
			return vpnConfigurationProfileData(t, tc.channel, identifier, payload)
		}
		bad := data([]any{map[string]any{"Action": "Connect", "ActionParameters": []any{}}})
		if _, err := s.SaveProfile(t.Context(), 1, "", 0, bad, "admin"); err == nil {
			t.Fatal("misplaced action parameters accepted on upload", tc)
		}
		p, err := s.SaveProfile(t.Context(), 1, "", 0, data([]any{}), "admin")
		if err != nil {
			t.Fatal(err)
		}
		assign := func(desired string) error {
			if tc.channel == "User" {
				return s.AssignUserProfile(t.Context(), scope, mac.ID, u.ID, p.ID, desired, "admin")
			}
			id := mac.ID
			if tc.kind == "AlwaysOn" {
				id = phone.ID
			}
			return s.AssignProfile(t.Context(), scope, p.ID, []string{id}, desired, "admin")
		}
		if err = assign("installed"); err != nil {
			t.Fatal(err)
		}
		count := func() int {
			t.Helper()
			var n int
			if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1)+(SELECT count(*) FROM mdm_apple_user_commands WHERE profile_id=$1)`, p.ID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := count()
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, bad, "admin"); err == nil {
			t.Fatal("malformed rules accepted on revision", tc)
		}
		stored, err := s.Profile(t.Context(), 1, p.ID)
		if err != nil || stored.UUID != p.UUID || stored.Revision != 1 || len(revisionHistory(t, s, p.ID)) != 1 || count() != before {
			t.Fatal("invalid rules changed profile, history or commands", err)
		}
		modern, err := s.SaveProfile(t.Context(), 1, p.ID, 1, data([]any{vpnOnDemandRuleFixture()}), "admin")
		if err != nil {
			t.Fatal("valid ordered rules rejected", tc, err)
		}
		var root map[string]any
		if _, err = plist.Unmarshal(modern.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payload := root["PayloadContent"].([]any)[0].(map[string]any)
		c, _ := payload["IKEv2"].(map[string]any)
		if tc.kind == "AlwaysOn" {
			c = payload["AlwaysOn"].(map[string]any)["TunnelConfigurations"].([]any)[0].(map[string]any)
		}
		c["OnDemandRules"] = []any{map[string]any{"Action": "invalid-legacy-action"}}
		legacy, err := plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := s.secrets.seal(legacy, secretPurpose(1, p.ID, "profile"))
		if err != nil {
			t.Fatal(err)
		}
		adeExec(t, s, `UPDATE mdm_apple_profiles SET payload=$2 WHERE id=$1`, p.ID, sealed)
		before = count()
		if err = assign("installed"); err == nil {
			t.Fatal("legacy malformed rules bypassed target validation", tc)
		}
		if count() != before || len(revisionHistory(t, s, p.ID)) != 2 {
			t.Fatal("rejected legacy assignment queued commands or changed history")
		}
		if err = assign("removed"); err != nil {
			t.Fatal("legacy rules prevented removal", err)
		}
	}
}
