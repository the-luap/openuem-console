package apple

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func systemExtensionData(t *testing.T, identifier, mode string, protected bool) []byte {
	t.Helper()
	settings := systemExtensionTestSettings(mode)
	if protected {
		settings["ProtectedBundleIdentifiers"] = "com.example.agent.extension"
	}
	data, err := BuildProfile(identifier, identifier, "macos-system-extensions", settings)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func saveSystemExtensionProfile(t *testing.T, s *Store, identifier, mode string, protected bool) *Profile {
	t.Helper()
	p, err := s.SaveProfile(t.Context(), 1, "", 0, systemExtensionData(t, identifier, mode, protected), "admin")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertSystemExtensionClaims(t *testing.T, s *Store, d *Device, profile string, want int) {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_system_extension_reservations WHERE tenant_id=$1 AND device_id=$2 AND profile_id=$3`, d.TenantID, d.ID, profile).Scan(&count); err != nil || count != want {
		t.Fatalf("extension claims=%d want=%d: %v", count, want, err)
	}
}

func TestSystemExtensionAssignmentsAndRevisionRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Extensions older Mac", "Mac16,1", "14.7")
	drainMacHardwareInventory(t, s, d, map[string]any{"OSVersion": "14.7"})
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Extensions phone", "iPhone16,1", "18.0")
	p := saveSystemExtensionProfile(t, s, "com.example.extensions", "listed", false)
	if err := s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID, phone.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("mixed batch accepted", err)
	}
	assertSystemExtensionClaims(t, s, d, p.ID, 0)
	adeExec(t, s, `UPDATE mdm_apple_devices SET security_at=now()-interval '25 hours' WHERE id=$1`, d.ID)
	if err := s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("stale approval accepted", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET security_at=clock_timestamp() WHERE id=$1`, d.ID)
	if err := s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveProfile(t.Context(), 1, p.ID, 1, systemExtensionData(t, p.Identifier, "listed", true), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("macOS 15 revision reached older Mac", err)
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("failed revision leaked snapshot")
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.Revision != 1 || stored.UUID != p.UUID {
		t.Fatal("failed revision changed catalog", err)
	}
	assertSystemExtensionClaims(t, s, d, p.ID, 1)
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='15.0' WHERE id=$1`, d.ID)
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, systemExtensionData(t, p.Identifier, "listed", true), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = ParseProfile(userProfileData(t, systemExtensionPayloadType, map[string]any{"AllowUserOverrides": false})); err == nil {
		t.Fatal("user upload accepted")
	}
}

func TestSystemExtensionReservationsRetainSentRevisionAndRemoval(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Extension revision lifecycle", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	first := saveSystemExtensionProfile(t, s, "com.example.extensions.first", "team", false)
	other := saveSystemExtensionProfile(t, s, "com.example.extensions.other", "listed", false)
	settings := systemExtensionTestSettings("listed")
	settings["RemovableBundleIdentifiers"] = "com.example.agent.extension"
	data, err := BuildProfile("Removable extension", "com.example.extensions.removable", "macos-system-extensions", settings)
	if err != nil {
		t.Fatal(err)
	}
	removable, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	assign := func(p *Profile, desired string) error {
		return s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, desired, "admin")
	}
	if err = assign(first, "installed"); err != nil {
		t.Fatal(err)
	}
	sent := profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "InstallProfile")
	current, err := s.SaveProfile(t.Context(), 1, first.ID, 1, systemExtensionData(t, first.Identifier, "listed", true), "admin")
	if err != nil {
		t.Fatal(err)
	}
	assertSystemExtensionClaims(t, s, d, first.ID, 2)
	if err = assign(other, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("catalog change released possibly installed team approval", err)
	}
	adeConnect(t, s, d, "Acknowledged", sent, nil)
	drainCommands(t, s, d, []InstalledProfile{{Identifier: first.Identifier, UUID: first.UUID}})
	if err = assign(other, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("old UUID released team approval", err)
	}
	if err = assign(current, "installed"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}})
	assertSystemExtensionClaims(t, s, d, current.ID, 1)
	if err = assign(other, "installed"); err != nil {
		t.Fatal("verified replacement retained old team approval", err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}, {Identifier: other.Identifier, UUID: other.UUID}})
	if err = assign(current, "removed"); err != nil {
		t.Fatal(err)
	}
	remove := profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "RemoveProfile")
	query := profileObservationCommand(t, adeConnect(t, s, d, "Acknowledged", remove, nil), "ProfileList")
	if err = assign(removable, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("removal acknowledgement released protected extension", err)
	}
	adeConnect(t, s, d, "Acknowledged", query, map[string]any{"ProfileList": []any{map[string]any{"PayloadIdentifier": other.Identifier, "PayloadUUID": other.UUID}}})
	assertSystemExtensionClaims(t, s, d, current.ID, 0)
	if err = assign(removable, "installed"); err != nil {
		t.Fatal("verified removal kept extension protected", err)
	}
}

func TestSystemExtensionReservationConcurrencyAndAuditRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Concurrent extension policies", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	a := saveSystemExtensionProfile(t, s, "com.example.extensions.team", "team", false)
	b := saveSystemExtensionProfile(t, s, "com.example.extensions.list", "listed", false)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, p := range []*Profile{a, b} {
		go func() {
			<-start
			results <- s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin")
		}()
	}
	close(start)
	accepted, denied := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrProfilePrerequisite) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || denied != 1 {
		t.Fatal("conflicting assignments were not serialized")
	}
	independent := saveSystemExtensionProfile(t, s, "com.example.extensions.block", "block", false)
	adeExec(t, s, `CREATE FUNCTION reject_extension_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.installed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_extension_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_extension_audit()`)
	if err := s.AssignProfile(t.Context(), scope, independent.ID, []string{d.ID}, "installed", "admin"); err == nil {
		t.Fatal("assignment committed without audit")
	}
	assertSystemExtensionClaims(t, s, d, independent.ID, 0)
	for _, foreign := range []Scope{{TenantID: 2, SiteID: 2}, {TenantID: 1, SiteID: 2}} {
		if err := s.AssignProfile(t.Context(), foreign, independent.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrNotFound) {
			t.Fatal("extension assignment crossed scope", err)
		}
	}
}

func TestSystemExtensionReservationMigrationPreservesUnknownHistory(t *testing.T) {
	s := testStoreBeforeMigration(t, "migrations/034_system_extension_reservations.sql")
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Legacy extension profiles", "Mac16,1", "15.0")
	seedLegacyMacProfileInventory(t, s, d)
	first := saveSystemExtensionProfile(t, s, "com.example.extensions.legacy", "team", false)
	current, err := s.SaveProfile(t.Context(), 1, first.ID, 1, systemExtensionData(t, first.Identifier, "listed", false), "admin")
	if err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `INSERT INTO mdm_apple_profile_assignments(tenant_id,device_id,profile_id,revision,desired,status) VALUES(1,$1,$2,2,'installed','verifying')`, d.ID, first.ID)
	for _, revision := range []int{1, 99} {
		adeExec(t, s, `INSERT INTO mdm_apple_commands(id,tenant_id,device_id,request_type,status,payload,profile_id,profile_revision,attempts) VALUES($1,1,$2,'InstallProfile','cancelled','\x',$3,$4,1)`, uuid.NewString(), d.ID, first.ID, revision)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("migration not idempotent", err)
	}
	assertSystemExtensionClaims(t, s, d, first.ID, 3)
	var missing int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_system_extension_reservations WHERE device_id=$1 AND profile_revision_id IS NULL`, d.ID).Scan(&missing); err != nil || missing != 1 {
		t.Fatal("missing snapshot invented", err)
	}
	other := saveSystemExtensionProfile(t, s, "com.example.extensions.migrated-other", "listed", false)
	if err = s.AssignProfile(t.Context(), scope, other.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("unknown legacy policy assumed compatible", err)
	}
	block := saveSystemExtensionProfile(t, s, "com.example.extensions.migrated-block", "block", false)
	if err = s.AssignProfile(t.Context(), scope, block.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal("block-only policy cannot conflict with old approval lists", err)
	}
	if err = s.AssignProfile(t.Context(), scope, current.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}, {Identifier: block.Identifier, UUID: block.UUID}})
	assertSystemExtensionClaims(t, s, d, current.ID, 1)
	if err = s.AssignProfile(t.Context(), scope, other.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal("fresh replacement did not resolve unknown policy", err)
	}
}
