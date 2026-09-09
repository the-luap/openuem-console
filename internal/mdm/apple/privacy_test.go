package apple

import (
	"errors"
	"testing"
)

func privacyProfileData(t *testing.T, identifier, service, policy string) []byte {
	t.Helper()
	data, err := BuildProfile("Privacy policy", identifier, "macos-privacy", privacySettings(service, policy))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPrivacyAssignmentAndRevisionRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Privacy older Mac", "Mac16,1", "13.6")
	drainMacHardwareInventory(t, s, d, map[string]any{"OSVersion": "13.6"})
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Privacy phone", "iPhone16,1", "18.0")
	p, err := s.SaveProfile(t.Context(), 1, "", 0, privacyProfileData(t, "com.example.privacy", "SystemPolicyAllFiles", "allow"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID, phone.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("mixed privacy batch accepted", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id=$1`, p.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed privacy batch leaked assignment", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET security_at=now()-interval '25 hours' WHERE id=$1`, d.ID)
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("stale privacy approval accepted", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET security_at=clock_timestamp() WHERE id=$1`, d.ID)
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, privacyProfileData(t, p.Identifier, "SystemPolicyAppData", "allow"), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("macOS 14 privacy service reached older Mac", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed privacy revision leaked snapshot")
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.Revision != 1 || stored.UUID != p.UUID {
		t.Fatal("failed privacy revision changed catalog", err)
	}
	denial, err := s.SaveProfile(t.Context(), 1, "", 0, privacyProfileData(t, "com.example.privacy.denial", "SystemPolicyAllFiles", "deny"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, denial.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal("compatible most-restrictive policy combination rejected", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='14.0' WHERE id=$1`, d.ID)
	current, err := s.SaveProfile(t.Context(), 1, p.ID, 1, privacyProfileData(t, p.Identifier, "SystemPolicyAppData", "allow"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}, {Identifier: denial.Identifier, UUID: denial.UUID}})
	if err = s.AssignProfile(t.Context(), scope, current.ID, []string{d.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: denial.Identifier, UUID: denial.UUID}})
	assignments, err := s.Assignments(t.Context(), scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	removed := false
	for _, a := range assignments {
		if a.ProfileID == current.ID {
			removed = a.Desired == "removed" && a.Status == "verified"
		}
	}
	if !removed {
		t.Fatal("privacy removal not verified")
	}
	if _, err = ParseProfile(userProfileData(t, privacyPayloadType, map[string]any{"Services": map[string]any{}})); err == nil {
		t.Fatal("privacy upload accepted on User channel")
	}
}

func TestPrivacyAccessibilityGrantRemovalAppliesToAssignment(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Privacy macOS 27", "Mac16,1", "27.0")
	drainMacHardwareInventory(t, s, d, map[string]any{"OSVersion": "27.0"})
	grant, err := s.SaveProfile(t.Context(), 1, "", 0, privacyProfileData(t, "com.example.privacy.accessibility", "Accessibility", "allow"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, grant.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("removed Accessibility grant reached macOS 27", err)
	}
	deny, err := s.SaveProfile(t.Context(), 1, "", 0, privacyProfileData(t, "com.example.privacy.accessibility-deny", "Accessibility", "deny"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, deny.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal("Accessibility denial removed with grants", err)
	}
}
