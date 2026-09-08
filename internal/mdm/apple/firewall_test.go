package apple

import (
	"bytes"
	"strings"
	"testing"

	"howett.net/plist"
)

func firewallProfileFixture(t *testing.T, settings map[string]any) ([]byte, *Profile) {
	t.Helper()
	data, err := BuildProfile("Mac firewall", "com.example.firewall", "macos-firewall", settings)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	return data, p
}

func TestFirewallProfileEditorAndPlatformGates(t *testing.T) {
	data, p := firewallProfileFixture(t, map[string]any{"EnableFirewall": true, "BlockAllIncoming": false, "EnableStealthMode": true, "AllowedApplications": "com.example.service\r\n\ncom.example.other", "BlockedApplications": "com.example.blocked"})
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	payload := root["PayloadContent"].([]any)[0].(map[string]any)
	apps := payload["Applications"].([]any)
	if p.Scope != "System" || payload["PayloadType"] != "com.apple.security.firewall" || payload["EnableFirewall"] != true || payload["EnableStealthMode"] != true || len(apps) != 3 || apps[2].(map[string]any)["Allowed"] != false {
		t.Fatal("incorrect firewall profile", payload)
	}
	if _, exists := payload["AllowSignedApp"]; exists {
		t.Fatal("implicit version-specific setting")
	}
	for _, target := range []struct {
		model, version string
		allowed        bool
	}{{"Mac16,1", "10.12", true}, {"Mac16,1", "26.0", true}, {"Mac16,1", "10.11", false}, {"Mac16,1", "", false}, {"iPhone16,1", "18.0", false}, {"iPad16,6", "18.0", false}, {"", "15.0", false}} {
		err := validateFirewallProfile(p, &Device{Model: target.model, OSVersion: target.version})
		if (err == nil) != target.allowed {
			t.Fatal("wrong firewall platform gate", target, err)
		}
	}
	_, signed := firewallProfileFixture(t, map[string]any{"EnableFirewall": true, "AllowSignedApp": false})
	for _, version := range []string{"12.2", "12.3", "15.0"} {
		err := validateFirewallProfile(signed, &Device{Model: "Mac16,1", OSVersion: version})
		if (err == nil) != (version != "12.2") {
			t.Fatal("signed software version gate", version, err)
		}
	}
	payload["EnableLogging"] = false
	for _, version := range []string{"11.7", "12.0", "14.6", "15.0"} {
		err := validateFirewallPayload(payload, "System", &Device{Model: "Mac16,1", OSVersion: version})
		if (err == nil) != (version == "12.0" || version == "14.6") {
			t.Fatal("removed logging setting accepted", version, err)
		}
	}
}

func TestFirewallRejectsAmbiguousEditorAndUploadedRules(t *testing.T) {
	for _, settings := range []map[string]any{
		{}, {"EnableFirewall": "true"}, {"EnableFirewall": true, "PayloadScope": "User"},
		{"EnableFirewall": true, "AllowSigned": "false"},
		{"EnableFirewall": true, "AllowedApplications": "com.example.one", "BlockedApplications": "COM.EXAMPLE.ONE"},
		{"EnableFirewall": true, "AllowedApplications": "com.example.*"},
		{"EnableFirewall": true, "AllowedApplications": "com.example.app name"},
		{"EnableFirewall": true, "AllowedApplications": strings.Repeat("a", 256)},
		{"EnableFirewall": true, "AllowedApplications": strings.Repeat("a", 16385)},
	} {
		if _, err := BuildProfile("Firewall", "com.example.firewall", "macos-firewall", settings); err == nil {
			t.Fatal("invalid firewall editor accepted", settings)
		}
	}
	data, _ := firewallProfileFixture(t, map[string]any{"EnableFirewall": false})
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	payload := root["PayloadContent"].([]any)[0].(map[string]any)
	tooMany := make([]any, 65)
	for i := range tooMany {
		tooMany[i] = map[string]any{"BundleID": "com.example.app", "Allowed": true}
	}
	for _, apps := range []any{
		"com.example.app", []any{"com.example.app"},
		[]any{map[string]any{"BundleID": "com.example.app", "Allowed": "true"}},
		[]any{map[string]any{"BundleID": "com.example.app", "Allowed": true}, map[string]any{"BundleID": "com.example.app", "Allowed": false}},
		tooMany,
	} {
		payload["Applications"] = apps
		encoded, err := plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ParseProfile(encoded); err == nil {
			t.Fatal("invalid uploaded firewall rules accepted")
		}
	}
}

func TestFirewallAssignmentRevisionAndRemovalWithPostgres(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Firewall Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Firewall iPhone", "iPhone16,1", "18.0")
	data, _ := firewallProfileFixture(t, map[string]any{"EnableFirewall": true})
	p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "installed", "admin"); err == nil {
		t.Fatal("mixed-platform firewall assignment accepted")
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id=$1`, p.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected batch left an assignment", count, err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Name: p.Name, Managed: true}})
	assignments, err := s.Assignments(t.Context(), scope, mac.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" {
		t.Fatal("firewall profile did not verify", assignments, err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_devices SET os_version='12.2' WHERE id=$1`, mac.ID); err != nil {
		t.Fatal(err)
	}
	revision, _ := firewallProfileFixture(t, map[string]any{"EnableFirewall": true, "AllowSignedApp": false})
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, p.Revision, revision, "admin"); err == nil {
		t.Fatal("incompatible revision deployed")
	}
	profiles, err := s.Profiles(t.Context(), 1)
	if err != nil || len(profiles) != 1 || profiles[0].Revision != p.Revision || !bytes.Equal(profiles[0].Payload, p.Payload) {
		t.Fatal("rejected revision replaced the saved profile", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{})
	assignments, err = s.Assignments(t.Context(), scope, mac.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" || assignments[0].Desired != "removed" {
		t.Fatal("firewall removal did not verify", assignments, err)
	}
}
