package apple

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestPlatformSSOProviderDataPreservesTypesAndRejectsAmbiguity(t *testing.T) {
	data, err := ParsePlatformSSOProviderData(`{"flag":true,"count":42,"negative":-2,"real":1.25,"nested":{"items":["value",false]},"text":"line\nline"}`)
	if err != nil || data["flag"] != true || data["count"] != uint64(42) || data["negative"] != int64(-2) || data["real"] != 1.25 {
		t.Fatal("provider data types changed", err)
	}
	for _, raw := range []string{`null`, `[]`, `{"a":null}`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{"a":1} {}`, `{"a":1e309}`, `{"a":18446744073709551616}`, `{"a":"\u0000"}`, strings.Repeat(`{"a":`, 18) + `true` + strings.Repeat(`}`, 18), `{"a":[` + strings.Repeat(`true,`, 1024) + `true]}`} {
		if _, err = ParsePlatformSSOProviderData(raw); err == nil {
			t.Fatal("invalid or unbounded provider data accepted")
		}
	}
	settings := platformSSOSettings()
	settings["ExtensionData"] = data
	platformSSOProfile(t, settings)
}

func FuzzPlatformSSOProviderData(f *testing.F) {
	for _, seed := range []string{`{"ProviderFlag":true}`, `{"nested":[1,"text",false]}`, `null`, `{"a":1,"a":2}`, `{"integer":18446744073709551615}`, "\xff", strings.Repeat(" ", 16385)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		data, err := ParsePlatformSSOProviderData(raw)
		if len(raw) > 16384 && err == nil {
			t.Fatal("oversized provider input accepted")
		}
		if err != nil || data == nil {
			return
		}
		encoded, err := plist.Marshal(data, plist.XMLFormat)
		if err != nil {
			t.Fatal("accepted provider data cannot be encoded as a profile dictionary", err)
		}
		var decoded map[string]any
		if _, err = plist.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal("accepted provider data produced an invalid plist", err)
		}
	})
}

func TestPlatformSSOStoredAssignmentAndRevisionSafety(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Platform SSO Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Platform SSO iPhone", "iPhone16,1", "18.0")
	draft := platformSSOProfile(t, platformSSOSettings())
	p, err := s.SaveProfile(t.Context(), 1, "", 0, draft.Payload, "admin")
	if err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err = s.db.QueryRow(`SELECT payload FROM mdm_apple_profiles WHERE id=$1`, p.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-provider-token")) {
		t.Fatal("registration token was not encrypted at rest", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "installed", "admin"); err == nil {
		t.Fatal("mixed-platform SSO assignment accepted")
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id=$1`, p.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected SSO assignment left a partial batch", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT payload FROM mdm_apple_commands WHERE device_id=$1 AND profile_id=$2 AND request_type='InstallProfile'`, mac.ID, p.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-provider-token")) {
		t.Fatal("SSO command token was not encrypted", err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Name: p.Name, Managed: true}})
	assignments, err := s.Assignments(t.Context(), scope, mac.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" {
		t.Fatal("SSO profile delivery did not verify", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='13.0',security_at=NULL WHERE id=$1`, mac.ID)
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, p.Revision, draft.Payload, "admin"); err == nil {
		t.Fatal("incompatible SSO revision accepted")
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.Revision != p.Revision || !bytes.Equal(stored.Payload, p.Payload) {
		t.Fatal("failed SSO revision changed stored policy", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "removed", "admin"); err != nil {
		t.Fatal("changed prerequisites blocked SSO profile removal", err)
	}
}

func platformSSOSettings() map[string]any {
	return map[string]any{"ExtensionIdentifier": "com.example.Identity.ssoextension", "TeamIdentifier": "ABCDEFGHIJ", "URLs": []any{"https://login.example.test/"}, "AuthenticationMethod": "UserSecureEnclaveKey", "AccountDisplayName": "Example identity", "RegistrationToken": "synthetic-provider-token", "ExtensionData": map[string]any{"ProviderSetting": "example", "ProviderBoolean": true}}
}

func platformSSOProfile(t *testing.T, settings map[string]any) *Profile {
	t.Helper()
	data, err := BuildProfile("Company identity", "com.example.identity", "macos-platform-sso", settings)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlatformSSOEditorPreservesTypedProviderSettings(t *testing.T) {
	p := platformSSOProfile(t, platformSSOSettings())
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		t.Fatal(err)
	}
	payload := root["PayloadContent"].([]any)[0].(map[string]any)
	configuration := payload["PlatformSSO"].(map[string]any)
	if payload["PayloadType"] != "com.apple.extensiblesso" || payload["Type"] != "Redirect" || payload["AuthenticationMethod"] != nil || configuration["AuthenticationMethod"] != "UserSecureEnclaveKey" || payload["RegistrationToken"] != "synthetic-provider-token" {
		t.Fatal("editor placed Platform SSO settings incorrectly")
	}
	if payload["ExtensionData"].(map[string]any)["ProviderBoolean"] != true || configuration["EnableCreateFirstUserDuringSetup"] != nil || configuration["EnableRegistrationDuringSetup"] != nil {
		t.Fatal("editor altered provider types or implicitly changed setup")
	}
	settings := platformSSOSettings()
	settings["PayloadScope"] = "User"
	if _, err := BuildProfile("identity", "com.example.identity", "macos-platform-sso", settings); err == nil {
		t.Fatal("device editor accepted user scope")
	}
}

func TestPlatformSSOValidationRejectsInvalidProviderAndAccountPolicies(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(s map[string]any) { s["TeamIdentifier"] = "wrong" },
		func(s map[string]any) { s["ExtensionIdentifier"] = "not an extension" },
		func(s map[string]any) { s["AuthenticationMethod"] = "invalid" },
		func(s map[string]any) { s["AuthenticationMethod"] = true },
		func(s map[string]any) { s["RegistrationToken"] = "synthetic\nprovider-token" },
		func(s map[string]any) { s["RegistrationToken"] = strings.Repeat("x", 8193) },
		func(s map[string]any) { s["URLs"] = []any{"https://login.example.test/?token=secret"} },
		func(s map[string]any) { s["URLs"] = []any{"https://login.example.test/?"} },
		func(s map[string]any) { s["URLs"] = []any{"https://login.example.test/#"} },
		func(s map[string]any) { s["URLs"] = []any{"https://user:secret@login.example.test/"} },
		func(s map[string]any) { s["URLs"] = []any{"javascript:alert(1)"} },
		func(s map[string]any) {
			s["URLs"] = []any{"https://login.example.test/", "https://LOGIN.example.test/"}
		},
		func(s map[string]any) { s["URLs"] = []any{true} },
		func(s map[string]any) { s["URLs"] = []any{} },
		func(s map[string]any) { s["EnableCreateUserAtLogin"] = true },
		func(s map[string]any) { s["UseSharedDeviceKeys"] = true; s["EnableCreateUserAtLogin"] = true },
		func(s map[string]any) { s["UseSharedDeviceKeys"] = "true" },
		func(s map[string]any) { s["ExtensionData"] = "not a dictionary" },
	} {
		settings := platformSSOSettings()
		change(settings)
		if _, err := BuildProfile("identity", "com.example.identity", "macos-platform-sso", settings); err == nil {
			t.Fatal("invalid Platform SSO policy accepted")
		} else if strings.Contains(err.Error(), "synthetic-provider-token") {
			t.Fatal("validation disclosed registration token")
		}
	}
	settings := platformSSOSettings()
	settings["UseSharedDeviceKeys"] = true
	settings["EnableCreateUserAtLogin"] = true
	settings["AuthenticationMethod"] = "Password"
	platformSSOProfile(t, settings)
}

func TestPlatformSSOEditorPreparesExplicitUnattendedSetup(t *testing.T) {
	for _, method := range []string{"Password", "SmartCard"} {
		settings := platformSSOSettings()
		settings["AuthenticationMethod"] = method
		settings["UseSharedDeviceKeys"] = true
		settings["EnableCreateUserAtLogin"] = true
		settings["UnattendedSetup"] = true
		p := platformSSOProfile(t, settings)
		if err := validateADEPlatformSSOProfile(p); err != nil {
			t.Fatal("editor did not produce an eligible unattended profile", err)
		}
		for _, key := range []string{"UseSharedDeviceKeys", "EnableCreateUserAtLogin"} {
			settings[key] = false
			if _, err := BuildProfile("unattended", "com.example.unattended", "macos-platform-sso", settings); err == nil {
				t.Fatal("unattended editor accepted incomplete account setup")
			}
			settings[key] = true
		}
		settings["AuthenticationMethod"] = "UserSecureEnclaveKey"
		if _, err := BuildProfile("unattended", "com.example.unattended", "macos-platform-sso", settings); err == nil {
			t.Fatal("unattended account creation accepted incompatible authentication")
		}
	}
	settings := platformSSOSettings()
	settings["UnattendedSetup"] = "true"
	if _, err := BuildProfile("unattended", "com.example.unattended", "macos-platform-sso", settings); err == nil {
		t.Fatal("untyped unattended switch accepted")
	}
}

func TestPlatformSSOAssignmentVersionAndApprovalBoundaries(t *testing.T) {
	p := platformSSOProfile(t, platformSSOSettings())
	now := time.Now()
	d := Device{Model: "Mac16,1", OSVersion: "14.0", SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true}}}
	if err := validatePlatformSSOProfile(p, &d); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"13.6", "10.15", "unknown"} {
		d.OSVersion = version
		if err := validatePlatformSSOProfile(p, &d); err == nil {
			t.Fatal("modern Platform SSO assigned to unsupported macOS", version)
		}
	}
	d.OSVersion = "14.0"
	d.Model = "iPhone16,1"
	if err := validatePlatformSSOProfile(p, &d); err == nil {
		t.Fatal("Platform SSO assigned to iPhone")
	}
	d.Model = "Mac16,1"
	d.SecurityAt = nil
	if err := validatePlatformSSOProfile(p, &d); err == nil {
		t.Fatal("Platform SSO accepted missing approval evidence")
	}
	d.SecurityAt = &now
	d.SecurityInventory = nil
	if err := validatePlatformSSOProfile(p, &d); err == nil {
		t.Fatal("Platform SSO accepted unapproved MDM")
	}
}

func TestPlatformSSOUploadHonorsLegacyUserChannelAndSetupKeys(t *testing.T) {
	p := platformSSOProfile(t, platformSSOSettings())
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		t.Fatal(err)
	}
	payload := root["PayloadContent"].([]any)[0].(map[string]any)
	configuration := payload["PlatformSSO"].(map[string]any)
	now := time.Now()
	d := Device{Model: "Mac16,1", OSVersion: "14.0", SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true}}}
	if err := validateUserPayload(payload, &d); err != nil {
		t.Fatal("eligible user Platform SSO rejected", err)
	}
	configuration["UseSharedDeviceKeys"] = false
	if err := validateUserPayload(payload, &d); err == nil {
		t.Fatal("device-only key accepted on user channel")
	}
	delete(configuration, "UseSharedDeviceKeys")
	configuration["EnableRegistrationDuringSetup"] = true
	configuration["EnableCreateFirstUserDuringSetup"] = false
	if err := validatePlatformSSOPayload(payload, "System", &d); err == nil {
		t.Fatal("macOS 26 setup keys accepted on macOS 14")
	}
	d.OSVersion = "26.0"
	if err := validatePlatformSSOPayload(payload, "System", &d); err != nil {
		t.Fatal(err)
	}
	configuration["EnableRegistrationDuringSetup"] = "true"
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseProfile(data); err == nil {
		t.Fatal("uploaded profile bypassed switch type validation")
	}
	delete(payload, "PlatformSSO")
	payload["AuthenticationMethod"] = "Password"
	d.OSVersion = "13.0"
	if err := validatePlatformSSOPayload(payload, "System", &d); err != nil {
		t.Fatal("legacy macOS 13 payload rejected", err)
	}
	delete(payload, "AuthenticationMethod")
	delete(payload, "RegistrationToken")
	payload["Type"] = "Credential"
	if err := validatePlatformSSOPayload(payload, "User", nil); err != nil {
		t.Fatal("ordinary SSO inherited Platform SSO restrictions", err)
	}
}
