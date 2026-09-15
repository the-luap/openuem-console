package apple

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func publicCertificateProfileData(t *testing.T, identifier, scope string, der []byte) []byte {
	t.Helper()
	data, err := BuildProfile("Public certificates", identifier, "apple-certificates", map[string]any{"PayloadScope": scope, "CertificateData": der})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPublicCertificateAssignmentExpiryAndRevisionRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	now := time.Now()
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Certificate Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Certificate phone", "iPhone16,1", "18.0")
	der := publicCertificateFixture(t, 1, true, now.Add(-time.Hour), now.Add(time.Hour))
	p, err := s.SaveProfile(t.Context(), 1, "", 0, publicCertificateProfileData(t, "com.example.certificates", "System", der), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "installed", "admin"); err != nil {
		t.Fatal("public certificates rejected a supported mixed platform batch", err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	drainCommands(t, s, phone, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	expired := publicCertificateFixture(t, 2, true, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, publicCertificateProfileData(t, p.Identifier, "System", expired), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("expired certificate revision was assigned", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("expired revision leaked a snapshot")
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.Revision != 1 || stored.UUID != p.UUID {
		t.Fatal("expired revision changed catalog", err)
	}
	future := publicCertificateFixture(t, 3, false, now.Add(time.Hour), now.Add(2*time.Hour))
	pending, err := s.SaveProfile(t.Context(), 1, "", 0, publicCertificateProfileData(t, "com.example.certificates.future", "System", future), "admin")
	if err != nil {
		t.Fatal("future certificate cannot be staged", err)
	}
	if err = s.AssignProfile(t.Context(), scope, pending.ID, []string{mac.ID, phone.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("future certificate assigned before validity", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id=$1`, pending.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid certificate batch leaked assignments", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{})
	drainCommands(t, s, phone, []InstalledProfile{})
	for _, d := range []*Device{mac, phone} {
		assignments, err := s.Assignments(t.Context(), scope, d.ID)
		if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" || assignments[0].Desired != "removed" {
			t.Fatal("certificate removal not verified", err)
		}
	}
}

func TestPublicCertificatesOnManagedMacUserChannel(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	now := time.Now()
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "User certificate Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	u := testUserEnroll(t, s, d, "alice")
	der := publicCertificateFixture(t, 1, false, now.Add(-time.Hour), now.Add(time.Hour))
	p, err := s.SaveProfile(t.Context(), 1, "", 0, publicCertificateProfileData(t, "com.example.user-certificate", "User", der), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "installed", "admin"); err != nil {
		t.Fatal("public user certificate rejected", err)
	}
	expired := publicCertificateFixture(t, 2, false, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, publicCertificateProfileData(t, p.Identifier, "User", expired), "admin"); err == nil || !strings.Contains(err.Error(), "not currently valid") {
		t.Fatal("user revision bypassed certificate validity", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed user certificate revision leaked snapshot")
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("user certificate reached device channel", err)
	}
}
