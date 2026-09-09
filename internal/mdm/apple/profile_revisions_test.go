package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

func revisionWiFi(t *testing.T, name, password string) []byte {
	t.Helper()
	data, err := BuildProfile(name, "com.example.versioned.wifi", "wifi", map[string]any{"SSID_STR": "Synthetic network", "EncryptionType": "WPA", "Password": password})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func revisionHistory(t *testing.T, s *Store, profile string) []ProfileRevision {
	t.Helper()
	items, next, err := s.ProfileRevisions(t.Context(), 1, profile, "")
	if err != nil || next != "" {
		t.Fatal("missing revision history", err)
	}
	return items
}

func TestProfileRevisionsRemainEncryptedImmutableAndAvailableAfterDeletion(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	p, err := s.SaveProfile(t.Context(), 1, "", 0, revisionWiFi(t, "Version <one>", "synthetic-first-secret"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	first := revisionHistory(t, s, p.ID)[0]
	p2, err := s.SaveProfile(t.Context(), 1, p.ID, 1, revisionWiFi(t, "Version two", "synthetic-second-secret"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	history := revisionHistory(t, s, p.ID)
	if len(history) != 2 || history[0].Revision != 2 || history[1].UUID != p.UUID || history[1].CurrentRevision != 2 {
		t.Fatal("saved profile overwrote its earlier revision")
	}
	metadata, _ := json.Marshal(history)
	if bytes.Contains(metadata, []byte("synthetic-first-secret")) || bytes.Contains(metadata, []byte("synthetic-second-secret")) {
		t.Fatal("revision metadata exposed credentials")
	}
	var encrypted []byte
	if err = s.db.QueryRow(`SELECT encrypted_payload FROM mdm_apple_profile_revisions WHERE id=$1`, first.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-first-secret")) {
		t.Fatal("snapshot was not encrypted", err)
	}
	if _, err = s.secrets.open(encrypted, secretPurpose(1, history[0].ID, "profile_revision")); err == nil {
		t.Fatal("snapshot ciphertext could be rebound to another revision")
	}
	stored, err := s.ProfileRevisionPayload(t.Context(), 1, first.ID)
	if err != nil || !bytes.Equal(stored.Payload, p.Payload) || stored.UUID != p.UUID || stored.Revision != 1 {
		t.Fatal("historical payload changed", err)
	}
	if _, err = s.ProfileRevisionPayload(t.Context(), 2, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("historical payload crossed organization", err)
	}
	if _, err = s.RestoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Revert the synthetic network", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("restore accepted missing transaction authority", err)
	}
	if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, history[0].ID, 2, "Current version", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("current version restored as an earlier version", err)
	}
	if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 1, "Stale edit", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("stale restore accepted", err)
	}
	for _, reason := range []string{"", " ", strings.Repeat("x", 1001)} {
		if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, reason, "admin", nil); !errors.Is(err, ErrProfileRevision) {
			t.Fatal("invalid restoration reason accepted", err)
		}
	}
	p3, err := s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Restore <approved> network settings", "admin", nil)
	if err != nil || p3.Revision != 3 || p3.UUID == p.UUID || p3.UUID == p2.UUID || !bytes.Contains(p3.Payload, []byte("synthetic-first-secret")) || bytes.Contains(p3.Payload, []byte("synthetic-second-secret")) {
		t.Fatal("restore did not create the intended new revision", err)
	}
	history = revisionHistory(t, s, p.ID)
	if len(history) != 3 || history[0].Origin != "restore" || history[0].RestoredFrom != first.ID || history[0].Reason != "Restore <approved> network settings" || history[0].Actor != "admin" {
		t.Fatal("restoration lost provenance")
	}
	for _, query := range []string{`UPDATE mdm_apple_profile_revisions SET reason='Changed' WHERE id=$1`, `DELETE FROM mdm_apple_profile_revisions WHERE id=$1`} {
		if _, err = s.db.Exec(query, first.ID); err == nil {
			t.Fatal("historical snapshot was mutable")
		}
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_profiles SET revision=4 WHERE id=$1`, p.ID); err == nil {
		t.Fatal("current profile accepted a revision without its matching snapshot")
	}
	older, next, err := s.ProfileRevisions(t.Context(), 1, p.ID, history[0].ID)
	if err != nil || next != "" || len(older) != 2 || older[1].ID != first.ID {
		t.Fatal("history cursor repeated or lost a revision", err)
	}
	if err = s.DeleteProfile(t.Context(), 1, p.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Profile(t.Context(), 1, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted catalog profile remained current", err)
	}
	history = revisionHistory(t, s, p.ID)
	if len(history) != 3 || history[0].CurrentRevision != 0 {
		t.Fatal("catalog deletion erased historical revisions")
	}
	if stored, err = s.ProfileRevisionPayload(t.Context(), 1, first.ID); err != nil || !bytes.Equal(stored.Payload, p.Payload) {
		t.Fatal("deleted catalog lost protected download", err)
	}
	if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 3, "Deleted catalog", "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("restore silently recreated a deleted catalog", err)
	}
}

func TestProfileRestoreIsAtomicAcrossAuditAndConcurrentWriters(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	p, err := s.SaveProfile(t.Context(), 1, "", 0, revisionWiFi(t, "One", "synthetic-one"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	first := revisionHistory(t, s, p.ID)[0]
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, revisionWiFi(t, "Two", "synthetic-two"), "admin"); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `CREATE FUNCTION reject_profile_restore_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.restore' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_profile_restore_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_profile_restore_audit()`)
	if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Synthetic audit rollback", "admin", nil); err == nil {
		t.Fatal("audit failure accepted restoration")
	}
	current, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || current.Revision != 2 || len(revisionHistory(t, s, p.ID)) != 2 {
		t.Fatal("audit failure retained part of restoration", err)
	}
	adeExec(t, s, `DROP TRIGGER reject_profile_restore_audit ON mdm_apple_audit`)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, err := s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Concurrent synthetic restore", "admin", nil)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	accepted, conflicts := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || conflicts != 1 || len(revisionHistory(t, s, p.ID)) != 3 {
		t.Fatal("concurrent restoration was not serialized")
	}
}

func TestProfileRestoreRequiresFreshUUIDObservationAndRollsBackIncompatibleSSO(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Revision Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	draft := platformSSOProfile(t, platformSSOSettings())
	p, err := s.SaveProfile(t.Context(), 1, "", 0, draft.Payload, "admin")
	if err != nil {
		t.Fatal(err)
	}
	first := revisionHistory(t, s, p.ID)[0]
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Managed: true}})
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, draft.Payload, "admin"); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='13.0',security_at=NULL WHERE id=$1`, mac.ID)
	var before int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Incompatible current Mac", "admin", nil); err == nil {
		t.Fatal("restore bypassed current SSO prerequisites")
	}
	var after int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&after); err != nil || after != before || len(revisionHistory(t, s, p.ID)) != 2 {
		t.Fatal("incompatible restoration leaked commands or snapshot", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='15.0',security_at=clock_timestamp() WHERE id=$1`, mac.ID)
	restored, err := s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Restore verified SSO configuration", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Managed: true}})
	assignments, err := s.Assignments(t.Context(), scope, mac.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Revision != 3 || assignments[0].Status == "verified" {
		t.Fatal("old UUID verified a restored revision", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, mac, []InstalledProfile{{Identifier: restored.Identifier, UUID: restored.UUID, Managed: true}})
	assignments, err = s.Assignments(t.Context(), scope, mac.ID)
	if err != nil || assignments[0].Status != "verified" {
		t.Fatal("fresh restored UUID did not verify", err)
	}
}

func TestProfileRevisionMigrationRetainsOnlyKnownLegacyPayload(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	// Reconstruct the pre-029 schema only inside this isolated test database.
	adeExec(t, s, `ALTER TABLE mdm_apple_profiles DROP CONSTRAINT mdm_apple_profile_current_revision; ALTER TABLE mdm_apple_profiles DROP COLUMN revision_id; DROP TABLE mdm_apple_profile_revisions; DROP FUNCTION mdm_apple_profile_revision_immutable(); DELETE FROM mdm_apple_migrations WHERE name='migrations/029_profile_revisions.sql'`)
	p, err := ParseProfile(revisionWiFi(t, "Legacy configuration", "synthetic-legacy-secret"))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
		t.Fatal(err)
	}
	delete(root, "PayloadScope") // Historical omitted scope means System.
	p.Payload, err = plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.secrets.seal(p.Payload, secretPurpose(1, p.ID, "profile"))
	if err != nil {
		t.Fatal(err)
	}
	types, _ := json.Marshal(p.PayloadTypes)
	adeExec(t, s, `INSERT INTO mdm_apple_profiles(id,tenant_id,name,identifier,payload_uuid,revision,payload_types,payload,payload_scope) VALUES($1,1,$2,$3,$4,7,$5,$6,'System')`, p.ID, p.Name, p.Identifier, p.UUID, types, sealed)
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("migration was not repeatable", err)
	}
	history := revisionHistory(t, s, p.ID)
	if len(history) != 1 || history[0].Revision != 7 || history[0].Origin != "migration" || history[0].Actor != "" {
		t.Fatal("migration invented earlier history or authors")
	}
	stored, err := s.ProfileRevisionPayload(t.Context(), 1, history[0].ID)
	if err != nil || !bytes.Equal(stored.Payload, p.Payload) {
		t.Fatal("legacy encryption or omitted System scope was lost", err)
	}
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 7, revisionWiFi(t, "New configuration", "synthetic-new-secret"), "admin"); err != nil {
		t.Fatal(err)
	}
	if restored, err := s.restoreProfileRevision(t.Context(), 1, p.ID, history[0].ID, 8, "Restore migrated revision", "admin", nil); err != nil || restored.Revision != 9 || !bytes.Contains(restored.Payload, []byte("synthetic-legacy-secret")) {
		t.Fatal("migrated revision could not be restored", err)
	}
}

func TestProfileRevisionHistoryBoundaries(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	p, err := s.SaveProfile(t.Context(), 1, "", 0, revisionWiFi(t, "First", "synthetic-secret"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	first := revisionHistory(t, s, p.ID)[0]
	for revision := 1; revision < 102; revision++ {
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, revision, revisionWiFi(t, "Next", "synthetic-secret"), "admin"); err != nil {
			t.Fatal(err)
		}
	}
	items, next, err := s.ProfileRevisions(t.Context(), 1, p.ID, "")
	if err != nil || len(items) != 100 || next != items[99].ID {
		t.Fatal("history was not bounded", err)
	}
	older, after, err := s.ProfileRevisions(t.Context(), 1, p.ID, next)
	if err != nil || len(older) != 2 || after != "" || older[1].ID != first.ID || older[0].Revision != 2 {
		t.Fatal("history pagination skipped or repeated revisions", err)
	}
	for _, query := range []struct {
		tenant          int
		profile, before string
	}{{2, p.ID, ""}, {1, uuid.NewString(), first.ID}, {1, p.ID, uuid.NewString()}} {
		if _, _, err = s.ProfileRevisions(t.Context(), query.tenant, query.profile, query.before); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign history family or cursor accepted", err)
		}
	}
	if _, _, err = s.ProfileRevisions(t.Context(), 1, p.ID, "invalid"); !errors.Is(err, ErrProfileRevision) {
		t.Fatal("malformed history cursor accepted", err)
	}
}

func TestProfileRestoreUpdatesActiveUsersAndPreservesPausedHistory(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "User revision Mac", "Mac16,1", "15.0")
	alice := testUserEnroll(t, s, d, "alice")
	bob := testUserEnroll(t, s, d, "bob")
	data := userProfileData(t, "com.apple.ManagedClient.preferences", map[string]any{"PayloadContent": map[string]any{"com.example.client": map[string]any{"Forced": []any{map[string]any{"mcx_preference_settings": map[string]any{"Value": "synthetic-original"}}}}}})
	p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	first := revisionHistory(t, s, p.ID)[0]
	for _, u := range []*UserChannel{alice, bob} {
		if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "installed", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, userProfileData(t, "com.apple.ManagedClient.preferences", nil), "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.PauseUserManagement(t.Context(), scope, d.ID, bob.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Restore original user settings", "admin", nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user     *UserChannel
		revision int
	}{{alice, 3}, {bob, 2}} {
		items, err := s.UserAssignments(t.Context(), scope, d.ID, tc.user.ID)
		if err != nil || len(items) != 1 || items[0].Revision != tc.revision {
			t.Fatal("restoration ignored user lifecycle", err)
		}
	}
	if err = s.ResumeUserManagement(t.Context(), scope, d.ID, bob.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	items, err := s.UserAssignments(t.Context(), scope, d.ID, bob.ID)
	if err != nil || items[0].Revision != 3 {
		t.Fatal("resumed user did not receive restored current revision", err)
	}
	source, err := s.ProfileRevisionPayload(t.Context(), 1, first.ID)
	if err != nil || !bytes.Contains(source.Payload, []byte("synthetic-original")) {
		t.Fatal("cancelled user commands erased protected source history", err)
	}
}
