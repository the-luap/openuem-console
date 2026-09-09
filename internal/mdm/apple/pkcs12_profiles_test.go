package apple

import (
	"bytes"
	"encoding/base64"
	"errors"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"strings"
	"testing"
)

func pkcs12TemplateData(t *testing.T, identifier, scope string, archive []byte, exportSetting bool) []byte {
	t.Helper()
	settings := map[string]any{"PayloadScope": scope, "IdentityData": archive, "Password": "synthetic-pkcs12-template-secret"}
	if exportSetting {
		settings["KeyIsExtractable"] = false
	}
	data, err := BuildProfile("Client identity", identifier, "apple-pkcs12", settings)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPKCS12TemplateAssignmentRevisionRollbackAndProtectedIdentity(t *testing.T) {
	archive := pkcs12IdentityFixture(t, pkcs12.Modern2023, "synthetic-pkcs12-template-secret")
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "PKCS12 template Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "PKCS12 template phone", "iPhone16,1", "18.0")
	// Keep the general inventory helper's macOS 15 fixture separate from the
	// persisted version used to exercise this older certificate capability.
	p, err := s.SaveProfile(t.Context(), 1, "", 0, pkcs12TemplateData(t, "com.example.pkcs12", "System", archive, false), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{phone.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, phone, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, pkcs12TemplateData(t, p.Identifier, "System", archive, true), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("Mac-only revision reached phone", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{phone.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, phone, []InstalledProfile{})
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.14.6' WHERE id=$1`, mac.ID)
	var version string
	if err = s.db.QueryRow(`SELECT os_version FROM mdm_apple_devices WHERE id=$1`, mac.ID).Scan(&version); err != nil || version != "10.14.6" {
		t.Fatal("older PKCS12 fixture changed", version, err)
	}
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, pkcs12TemplateData(t, p.Identifier, "System", archive, true), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("new key option reached unsupported Mac", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed PKCS12 revision leaked history")
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.Revision != 1 || stored.UUID != p.UUID {
		t.Fatal("failed PKCS12 revision changed catalog", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.15' WHERE id=$1`, mac.ID)
	current, err := s.SaveProfile(t.Context(), 1, p.ID, 1, pkcs12TemplateData(t, p.Identifier, "System", archive, true), "admin")
	if err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}})
	if err = s.AssignProfile(t.Context(), scope, current.ID, []string{phone.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("Mac option assigned to phone", err)
	}
	var encrypted []byte
	if err = s.db.QueryRow(`SELECT payload FROM mdm_apple_profiles WHERE id=$1`, p.ID).Scan(&encrypted); err != nil || (bytes.Contains(encrypted, []byte("synthetic-pkcs12-template-secret")) || bytes.Contains(encrypted, []byte(base64.StdEncoding.EncodeToString(archive)))) {
		t.Fatal("PKCS12 password or identity stored in plaintext", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE details::text LIKE '%synthetic-pkcs12-template-secret%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("PKCS12 password or identity leaked to audit", err)
	}
	if err = s.AssignProfile(t.Context(), scope, current.ID, []string{mac.ID, phone.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{})
	drainCommands(t, s, phone, []InstalledProfile{})
	for _, d := range []*Device{mac, phone} {
		assignments, err := s.Assignments(t.Context(), scope, d.ID)
		if err != nil || len(assignments) != 1 || assignments[0].Desired != "removed" || assignments[0].Status != "verified" {
			t.Fatal("PKCS12 profile removal not verified", err)
		}
	}
}

func TestPKCS12TemplateUserRevisionChecksMacOptions(t *testing.T) {
	archive := pkcs12IdentityFixture(t, pkcs12.Modern2023, "synthetic-pkcs12-template-secret")
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "PKCS12 user template", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	u := testUserEnroll(t, s, d, "alice")
	p, err := s.SaveProfile(t.Context(), 1, "", 0, pkcs12TemplateData(t, "com.example.pkcs12.user", "User", archive, false), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.14.6' WHERE id=$1`, d.ID)
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, pkcs12TemplateData(t, p.Identifier, "User", archive, true), "admin"); err == nil || !strings.Contains(err.Error(), "10.15") {
		t.Fatal("User PKCS12 revision bypassed Mac option boundary", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed User PKCS12 revision leaked snapshot")
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("User PKCS12 reached device channel", err)
	}
}
