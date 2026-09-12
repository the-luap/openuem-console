package apple

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func scepTemplateData(t *testing.T, identifier, scope, address string, exportSetting bool) []byte {
	t.Helper()
	settings := scepProfileSettings()
	settings["URL"] = address
	settings["PayloadScope"] = scope
	settings["Challenge"] = "synthetic-scep-template-secret"
	if exportSetting {
		settings["KeyIsExtractable"] = false
	}
	data, err := BuildProfile("Client identity", identifier, "apple-scep", settings)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSCEPTemplateAssignmentRevisionRollbackAndNoIssuerContact(t *testing.T) {
	var requests atomic.Int32
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer issuer.Close()
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "SCEP template Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "SCEP template phone", "iPhone16,1", "18.0")
	// Keep the general inventory helper's macOS 15 fixture separate from the
	// persisted version used to exercise this older certificate capability.
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.13.3' WHERE id=$1`, mac.ID)
	p, err := s.SaveProfile(t.Context(), 1, "", 0, scepTemplateData(t, "com.example.scep", "System", issuer.URL, false), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	drainCommands(t, s, phone, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	var version string
	if err = s.db.QueryRow(`SELECT os_version FROM mdm_apple_devices WHERE id=$1`, mac.ID).Scan(&version); err != nil || version != "10.13.3" {
		t.Fatal("older SCEP fixture changed", version, err)
	}
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, scepTemplateData(t, p.Identifier, "System", issuer.URL, true), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("new key option reached unsupported Mac", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed SCEP revision leaked history")
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.Revision != 1 || stored.UUID != p.UUID {
		t.Fatal("failed SCEP revision changed catalog", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.13.4' WHERE id=$1`, mac.ID)
	current, err := s.SaveProfile(t.Context(), 1, p.ID, 1, scepTemplateData(t, p.Identifier, "System", issuer.URL, true), "admin")
	if err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}})
	drainCommands(t, s, phone, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}})
	var encrypted []byte
	if err = s.db.QueryRow(`SELECT payload FROM mdm_apple_profiles WHERE id=$1`, p.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-scep-template-secret")) {
		t.Fatal("SCEP challenge stored in plaintext", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE details::text LIKE '%synthetic-scep-template-secret%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("SCEP challenge leaked to audit", err)
	}
	if err = s.AssignProfile(t.Context(), scope, current.ID, []string{mac.ID, phone.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{})
	drainCommands(t, s, phone, []InstalledProfile{})
	for _, d := range []*Device{mac, phone} {
		assignments, err := s.Assignments(t.Context(), scope, d.ID)
		if err != nil || len(assignments) != 1 || assignments[0].Desired != "removed" || assignments[0].Status != "verified" {
			t.Fatal("SCEP profile removal not verified", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("profile management contacted the issuer from the server")
	}
}

func TestSCEPTemplateUserRevisionChecksMacOptions(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "SCEP user template", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	u := testUserEnroll(t, s, d, "alice")
	p, err := s.SaveProfile(t.Context(), 1, "", 0, scepTemplateData(t, "com.example.scep.user", "User", "https://ca.example.test/scep", false), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.13.3' WHERE id=$1`, d.ID)
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, scepTemplateData(t, p.Identifier, "User", "https://ca.example.test/scep", true), "admin"); err == nil || !strings.Contains(err.Error(), "10.13.4") {
		t.Fatal("User SCEP revision bypassed Mac option boundary", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed User SCEP revision leaked snapshot")
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("User SCEP reached device channel", err)
	}
}
