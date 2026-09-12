package apple

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func acmeTemplateData(t *testing.T, identifier, scope, client string) []byte {
	t.Helper()
	settings := acmeProfileSettings()
	settings["PayloadScope"] = scope
	settings["ClientIdentifier"] = client
	data, err := BuildProfile("Client certificate", identifier, "apple-acme", settings)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func saveACMETemplate(t *testing.T, s *Store, identifier, scope, client string) *Profile {
	t.Helper()
	p, err := s.SaveProfile(t.Context(), 1, "", 0, acmeTemplateData(t, identifier, scope, client), "admin")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestACMEConcurrentClientOwnershipSurvivesRemovalAndCatalogDeletion(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d1, _, _ := testEnrollPlatformWithKey(t, s, scope, "ACME first phone", "iPhone16,1", "18.0")
	d2, _, _ := testEnrollPlatformWithKey(t, s, scope, "ACME second phone", "iPhone16,1", "18.0")
	devices := []*Device{d1, d2}
	profiles := []*Profile{saveACMETemplate(t, s, "com.example.acme.first", "System", "synthetic-acme-shared-secret"), saveACMETemplate(t, s, "com.example.acme.second", "System", "synthetic-acme-shared-secret")}
	replica, err := NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	stores := []*Store{s, replica}
	start := make(chan struct{})
	type result struct {
		index int
		err   error
	}
	results := make(chan result, 2)
	for i := range 2 {
		go func() {
			<-start
			results <- result{i, stores[i].AssignProfile(t.Context(), scope, profiles[i].ID, []string{devices[i].ID}, "installed", "admin")}
		}()
	}
	close(start)
	winner := -1
	for range 2 {
		r := <-results
		if r.err == nil {
			if winner != -1 {
				t.Fatal("two devices acquired the same ACME client")
			}
			winner = r.index
		} else if !errors.Is(r.err, ErrProfilePrerequisite) {
			t.Fatal("unexpected concurrent ACME failure", r.err)
		}
	}
	if winner < 0 {
		t.Fatal("neither device acquired the available client")
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id IN ($1,$2)`, profiles[0].ID, profiles[1].ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("losing assignment leaked state", count, err)
	}
	var encrypted, key []byte
	if err = s.db.QueryRow(`SELECT encrypted_client FROM mdm_apple_acme_clients WHERE tenant_id=1`).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-acme-shared-secret")) {
		t.Fatal("ACME client stored in plaintext", err)
	}
	if err = s.db.QueryRow(`SELECT encrypted_key FROM mdm_apple_acme_registry_keys WHERE tenant_id=1`).Scan(&key); err != nil || len(key) != 60 {
		t.Fatal("ACME registry key is not protected", err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE details::text LIKE '%synthetic-acme-shared-secret%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("ACME client leaked to audit", err)
	}
	p, d := profiles[winner], devices[winner]
	drainCommands(t, s, d, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{})
	if err = s.DeleteProfile(t.Context(), 1, p.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, profiles[1-winner].ID, []string{devices[1-winner].ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("removal/deletion released an issuer client identifier", err)
	}
	if err = s.AssignProfile(t.Context(), scope, profiles[1-winner].ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal("same enrollment could not retain its client ownership", err)
	}
}

func TestACMESharedProfileRevisionRollbackAndUserNamespace(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "ACME user Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "ACME shared phone", "iPhone16,1", "18.0")
	data, err := BuildProfile("Shared Wi-Fi", "com.example.acme.shared", "wifi", map[string]any{"SSID_STR": "Synthetic Wi-Fi", "EncryptionType": "WPA", "Password": "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*Device{mac, phone} {
		drainCommands(t, s, d, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID}})
	}
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, acmeTemplateData(t, p.Identifier, "System", "synthetic-acme-batch-client"), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("one ACME client reached a device batch", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_acme_clients`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed batch revision retained a new client claim", count, err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed ACME revision leaked history")
	}
	current, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || current.Revision != 1 || current.UUID != p.UUID {
		t.Fatal("failed ACME revision changed the catalog", err)
	}
	system := saveACMETemplate(t, s, "com.example.acme.system", "System", "synthetic-acme-user-client")
	if err = s.AssignProfile(t.Context(), scope, system.ID, []string{mac.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	u := testUserEnroll(t, s, mac, "alice")
	user := saveACMETemplate(t, s, "com.example.acme.user", "User", "synthetic-acme-user-client")
	if err = s.AssignUserProfile(t.Context(), scope, mac.ID, u.ID, user.ID, "installed", "admin"); err != nil {
		t.Fatal("System/User profiles on one enrollment did not share client ownership", err)
	}
	if err = s.AssignProfile(t.Context(), scope, system.ID, []string{phone.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("ACME User ownership was ignored", err)
	}
}

func TestACMELegacyMigrationAndReviewedArchive(t *testing.T) {
	s := testStoreBeforeMigration(t, "migrations/035_acme_client_registry.sql")
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d1, _, _ := testEnrollPlatformWithKey(t, s, scope, "Legacy ACME first", "iPhone16,1", "18.0")
	d2, _, _ := testEnrollPlatformWithKey(t, s, scope, "Legacy ACME second", "iPhone16,1", "18.0")
	first := saveACMETemplate(t, s, "com.example.acme.legacy", "System", "synthetic-legacy-reused-client")
	if _, err := s.SaveProfile(t.Context(), 1, first.ID, 1, acmeTemplateData(t, first.Identifier, "System", "synthetic-legacy-current-client"), "admin"); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `INSERT INTO mdm_apple_profile_assignments(tenant_id,device_id,profile_id,revision,desired,status) VALUES(1,$1,$2,2,'removed','verified')`, d1.ID, first.ID)
	for _, item := range []struct {
		device   string
		revision int
	}{{d1.ID, 1}, {d1.ID, 99}, {d2.ID, 1}} {
		adeExec(t, s, `INSERT INTO mdm_apple_commands(id,tenant_id,device_id,request_type,status,payload,profile_id,profile_revision,attempts) VALUES($1,1,$2,'InstallProfile','cancelled','\x',$3,$4,1)`, uuid.NewString(), item.device, first.ID, item.revision)
	}
	for range 2 {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal("ACME migration/idempotence", err)
		}
	}
	var total, conflicts int
	if err := s.db.QueryRow(`SELECT count(*),count(*) FILTER(WHERE conflicted) FROM mdm_apple_acme_clients WHERE tenant_id=1`).Scan(&total, &conflicts); err != nil || total != 2 || conflicts != 1 {
		t.Fatal("legacy client references or conflicting ownership changed", total, conflicts, err)
	}
	items, next, err := s.ACMELegacyProfiles(t.Context(), 1, "", "unresolved")
	if err != nil || len(items) != 1 || next != "" || items[0].Revision != 99 {
		t.Fatal("missing archive was hidden or invented", err)
	}
	item := items[0]
	fresh := saveACMETemplate(t, s, "com.example.acme.fresh", "System", "synthetic-fresh-client")
	if err = s.AssignProfile(t.Context(), scope, fresh.ID, []string{d2.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("unresolved historical clients were assumed free", err)
	}
	archive, err := BuildProfile("Archived Wi-Fi", first.Identifier, "wifi", map[string]any{"SSID_STR": "Archived Wi-Fi", "EncryptionType": "WPA", "Password": "synthetic-archive-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ReviewACMELegacyProfile(t.Context(), 1, item.ID, 99, archive, "Reviewed original revision 99.", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("legacy review accepted missing authority", err)
	}
	if err = s.reviewACMELegacyProfile(t.Context(), 2, item.ID, 99, archive, "Reviewed original revision 99.", "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy review crossed organizations", err)
	}
	if err = s.reviewACMELegacyProfile(t.Context(), 1, item.ID, 98, archive, "Reviewed original revision 99.", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("stale archive review accepted", err)
	}
	if err = s.reviewACMELegacyProfile(t.Context(), 1, item.ID, 99, archive, "", "admin", nil); !errors.Is(err, ErrACMEHistory) {
		t.Fatal("unexplained archive review accepted", err)
	}
	if err = s.reviewACMELegacyProfile(t.Context(), 1, item.ID, 99, archive, "Reviewed original revision 99; contains Wi-Fi only.", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.reviewACMELegacyProfile(t.Context(), 1, item.ID, 99, archive, "Repeated review.", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("review evidence was overwritten", err)
	}
	items, _, err = s.ACMELegacyProfiles(t.Context(), 1, "", "reviewed")
	if err != nil || len(items) != 1 || items[0].ReviewedBy != "admin" || items[0].ReviewedAt == nil {
		t.Fatal("review receipt missing", err)
	}
	var encrypted []byte
	if err = s.db.QueryRow(`SELECT reviewed_payload FROM mdm_apple_acme_legacy_profiles WHERE id=$1`, item.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, archive) || bytes.Contains(encrypted, []byte("synthetic-archive-password")) {
		t.Fatal("review archive leaked", err)
	}
	if err = s.AssignProfile(t.Context(), scope, fresh.ID, []string{d2.ID}, "installed", "admin"); err != nil {
		t.Fatal("reviewed history did not unblock a fresh identifier", err)
	}
	for i, client := range []string{"synthetic-legacy-reused-client", "synthetic-legacy-current-client"} {
		p := saveACMETemplate(t, s, fmt.Sprintf("com.example.acme.retained.%d", i), "System", client)
		if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d2.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
			t.Fatal("historical identifier was reused", err)
		}
	}
}
