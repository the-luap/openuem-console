package apple

import (
	"bytes"
	"errors"
	"testing"

	"howett.net/plist"
)

func TestGatekeeperEditorKeepsAssessmentAndFinderPayloadsSeparate(t *testing.T) {
	for _, override := range []any{nil, false, true} {
		settings := map[string]any{"EnableAssessment": true, "AllowIdentifiedDevelopers": false, "EnableXProtectMalwareUpload": false}
		if override != nil {
			settings["DisableOverride"] = override
		}
		data, err := BuildProfile("Company Gatekeeper", "com.example.gatekeeper", "macos-gatekeeper", settings)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParseProfile(data)
		if err != nil || p.Scope != "System" {
			t.Fatal("Gatekeeper editor produced an invalid profile", err)
		}
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		content := root["PayloadContent"].([]any)
		want := 1
		if override != nil {
			want = 2
		}
		if len(content) != want {
			t.Fatal("Finder default added an unintended payload")
		}
		assessment := content[0].(map[string]any)
		if assessment["PayloadType"] != "com.apple.systempolicy.control" || assessment["EnableAssessment"] != true || assessment["AllowIdentifiedDevelopers"] != false || assessment["EnableXProtectMalwareUpload"] != false || assessment["DisableOverride"] != nil {
			t.Fatal("Gatekeeper settings changed payload or type")
		}
		if override != nil {
			finder := content[1].(map[string]any)
			if finder["PayloadType"] != "com.apple.systempolicy.managed" || finder["DisableOverride"] != override || finder["PayloadUUID"] == assessment["PayloadUUID"] || finder["PayloadIdentifier"] == assessment["PayloadIdentifier"] {
				t.Fatal("Finder exception policy lost its separate identity")
			}
		}
	}
	data, err := BuildProfile("Gatekeeper", "com.example.defaults", "macos-gatekeeper", map[string]any{"EnableAssessment": false})
	if err != nil || bytes.Contains(data, []byte("AllowIdentifiedDevelopers")) || bytes.Contains(data, []byte("EnableXProtectMalwareUpload")) {
		t.Fatal("editor invented optional Gatekeeper settings", err)
	}
	for _, settings := range []map[string]any{{}, {"EnableAssessment": "true"}, {"EnableAssessment": true, "DisableOverride": "false"}, {"EnableAssessment": true, "PayloadScope": "User"}, {"EnableAssessment": true, "EnableXProtectMalwareUpload": 0}} {
		if _, err = BuildProfile("Gatekeeper", "com.example.invalid", "macos-gatekeeper", settings); err == nil {
			t.Fatal("invalid Gatekeeper editor input accepted")
		}
	}
}

func TestGatekeeperUserUploadValidation(t *testing.T) {
	user := userProfileData(t, "com.apple.systempolicy.managed", map[string]any{"DisableOverride": true})
	if _, err := ParseProfile(user); err != nil {
		t.Fatal("Finder override user payload rejected", err)
	}
	user = userProfileData(t, "com.apple.systempolicy.managed", map[string]any{"DisableOverride": "true"})
	if _, err := ParseProfile(user); err == nil {
		t.Fatal("user upload bypassed Finder boolean validation")
	}
	user = userProfileData(t, "com.apple.systempolicy.control", map[string]any{"EnableAssessment": true})
	if _, err := ParseProfile(user); err == nil {
		t.Fatal("assessment payload accepted on user channel")
	}
}

func TestGatekeeperAssignmentAndRevisionRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Gatekeeper Mac", "Mac16,1", "14.7")
	drainMacHardwareInventory(t, s, mac, map[string]any{"OSVersion": "14.7"})
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Gatekeeper iPhone", "iPhone16,1", "18.0")
	data, err := BuildProfile("Gatekeeper", "com.example.gatekeeper", "macos-gatekeeper", map[string]any{"EnableAssessment": true, "AllowIdentifiedDevelopers": true, "DisableOverride": true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("Gatekeeper entered a mixed-platform batch", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id=$1`, p.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed batch leaked an assignment", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	var observedVersion string
	if err = s.db.QueryRow(`SELECT os_version FROM mdm_apple_devices WHERE id=$1`, mac.ID).Scan(&observedVersion); err != nil || observedVersion != "14.7" {
		t.Fatal("inventory changed the older-Mac fixture", observedVersion, err)
	}
	data, err = BuildProfile("Gatekeeper", "com.example.gatekeeper", "macos-gatekeeper", map[string]any{"EnableAssessment": true, "EnableXProtectMalwareUpload": false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, data, "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("macOS 15 revision was assigned to an older Mac", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed revision survived rollback")
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.Revision != 1 || !bytes.Equal(stored.Payload, p.Payload) {
		t.Fatal("failed revision changed the catalog", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='15.0' WHERE id=$1`, mac.ID)
	current, err := s.SaveProfile(t.Context(), 1, p.ID, 1, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}})
	if err = s.AssignProfile(t.Context(), scope, current.ID, []string{mac.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{})
	assignments, err := s.Assignments(t.Context(), scope, mac.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Desired != "removed" || assignments[0].Status != "verified" {
		t.Fatal("Gatekeeper removal was not verified", err)
	}
}
