package apple

import (
	"testing"
)

func TestIKEv2RevisionsCheckTLSMTUAndModernAlgorithmOptions(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "IKEv2 revision Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	u := testUserEnroll(t, s, mac, "alice")
	for _, channel := range []string{"System", "User"} {
		for _, tc := range []struct {
			name, below, at string
			settings        map[string]any
		}{
			{"tls", "10.12", "10.13", map[string]any{"TLSMinimumVersion": "1.2", "TLSMaximumVersion": "1.2", "ExtendedAuthEnabled": 1}},
			{"mtu", "10.15.7", "11.0", map[string]any{"MTU": 1280}},
			{"strict", "15.4", "15.5", map[string]any{"EnforceStrictAlgorithmSelection": 0}},
			{"postquantum", "15.6", "26.0", map[string]any{"IKESecurityAssociationParameters": map[string]any{"PostQuantumKeyExchangeMethods": []any{36, 37}}}},
		} {
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, mac.ID, tc.below)
			identifier := "com.example.ikev2." + channel + "." + tc.name
			p, err := s.SaveProfile(t.Context(), 1, "", 0, vpnConfigurationProfileData(t, channel, identifier, vpnSettings("IKEv2")), "admin")
			if err != nil {
				t.Fatal(err)
			}
			assign := func(desired string) error {
				if channel == "User" {
					return s.AssignUserProfile(t.Context(), scope, mac.ID, u.ID, p.ID, desired, "admin")
				}
				return s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, desired, "admin")
			}
			if err = assign("installed"); err != nil {
				t.Fatal(err)
			}
			changed := vpnSettings("IKEv2")
			for key, value := range tc.settings {
				changed["IKEv2"].(map[string]any)[key] = value
			}
			data := vpnConfigurationProfileData(t, channel, identifier, changed)
			var before, after int
			query := `SELECT (SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1)+(SELECT count(*) FROM mdm_apple_user_commands WHERE profile_id=$1)`
			if err = s.db.QueryRow(query, p.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, data, "admin"); err == nil {
				t.Fatal("unsupported IKEv2 revision accepted", tc.name, channel)
			}
			if err = s.db.QueryRow(query, p.ID).Scan(&after); err != nil || before != after || len(revisionHistory(t, s, p.ID)) != 1 {
				t.Fatal("failed IKEv2 revision leaked commands or history", err)
			}
			stored, err := s.Profile(t.Context(), 1, p.ID)
			if err != nil || stored.UUID != p.UUID || stored.Revision != 1 {
				t.Fatal("failed IKEv2 revision changed catalog", err)
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, mac.ID, tc.at)
			if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, data, "admin"); err != nil {
				t.Fatal("supported IKEv2 revision rejected", tc.name, channel, err)
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, mac.ID, tc.below)
			if err = assign("installed"); err == nil {
				t.Fatal("IKEv2 reassignment bypassed target validation")
			}
			if err = assign("removed"); err != nil {
				t.Fatal("IKEv2 target validation prevented removal", err)
			}
		}
	}
}

func TestIKEv2AlgorithmRemovalAndMalformedRevisionDoNotCorruptHistory(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "IKEv2 legacy Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	u := testUserEnroll(t, s, mac, "alice")
	for _, channel := range []string{"System", "User"} {
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='15.6' WHERE id=$1`, mac.ID)
		identifier := "com.example.ikev2-legacy." + channel
		payload := vpnSettings("IKEv2")
		payload["IKEv2"].(map[string]any)["IKESecurityAssociationParameters"] = map[string]any{"EncryptionAlgorithm": "3DES", "IntegrityAlgorithm": "SHA1-96", "DiffieHellmanGroup": 5}
		p, err := s.SaveProfile(t.Context(), 1, "", 0, vpnConfigurationProfileData(t, channel, identifier, payload), "admin")
		if err != nil {
			t.Fatal(err)
		}
		assign := func(desired string) error {
			if channel == "User" {
				return s.AssignUserProfile(t.Context(), scope, mac.ID, u.ID, p.ID, desired, "admin")
			}
			return s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, desired, "admin")
		}
		if err = assign("installed"); err != nil {
			t.Fatal(err)
		}
		payload["IKEv2"].(map[string]any)["ExtendedAuthEnabled"] = true
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, vpnConfigurationProfileData(t, channel, identifier, payload), "admin"); err == nil || len(revisionHistory(t, s, p.ID)) != 1 {
			t.Fatal("invalid IKEv2 wire type created a revision")
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='26.0' WHERE id=$1`, mac.ID)
		if err = assign("installed"); err == nil {
			t.Fatal("removed IKEv2 algorithms reached OS 26")
		}
		modern := vpnSettings("IKEv2")
		modern["IKEv2"].(map[string]any)["EnforceStrictAlgorithmSelection"] = 1
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, vpnConfigurationProfileData(t, channel, identifier, modern), "admin"); err != nil {
			t.Fatal("modern IKEv2 replacement failed", err)
		}
		history := revisionHistory(t, s, p.ID)
		if len(history) != 2 {
			t.Fatal("modern replacement lost legacy history")
		}
		if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, history[1].ID, 2, "Synthetic legacy restoration check", "admin", nil); err == nil {
			t.Fatal("restored legacy algorithms reached OS 26")
		}
		stored, err := s.Profile(t.Context(), 1, p.ID)
		if err != nil || stored.Revision != 2 || len(revisionHistory(t, s, p.ID)) != 2 {
			t.Fatal("failed legacy restoration changed catalog or history", err)
		}
		if err = assign("removed"); err != nil {
			t.Fatal(err)
		}
	}
}
