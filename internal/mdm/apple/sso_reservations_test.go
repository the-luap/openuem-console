package apple

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func ssoReservationData(t *testing.T, identifier, route, scope, extension string) []byte {
	t.Helper()
	settings := platformSSOSettings()
	settings["URLs"] = []any{route}
	settings["ExtensionIdentifier"] = extension
	data, err := BuildProfile(identifier, identifier, "macos-platform-sso", settings)
	if err != nil {
		t.Fatal(err)
	}
	if scope == "User" {
		var root map[string]any
		if _, err = plist.Unmarshal(data, &root); err != nil {
			t.Fatal(err)
		}
		root["PayloadScope"] = "User"
		data, err = plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
	}
	return data
}

func saveSSOReservationProfile(t *testing.T, s *Store, identifier, route, scope, extension string) *Profile {
	t.Helper()
	p, err := s.SaveProfile(t.Context(), 1, "", 0, ssoReservationData(t, identifier, route, scope, extension), "admin")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertSSOClaimCount(t *testing.T, s *Store, d *Device, profile string, want int) {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_sso_reservations WHERE tenant_id=$1 AND device_id=$2 AND profile_id=$3`, d.TenantID, d.ID, profile).Scan(&count); err != nil || count != want {
		t.Fatalf("reservation count=%d want=%d: %v", count, want, err)
	}
}

func TestSSORouteReservationsRetainSentRevisionsUntilFreshReplacementAndRemoval(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "SSO reservation lifecycle", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	first := saveSSOReservationProfile(t, s, "com.example.sso.first", "https://old.example.test/", "System", "com.example.Provider.extension")
	oldRoute := saveSSOReservationProfile(t, s, "com.example.sso.old", "https://OLD.example.test/", "System", "com.example.Other.extension")
	newRoute := saveSSOReservationProfile(t, s, "com.example.sso.new", "https://new.example.test/", "System", "com.example.Other.extension")
	assign := func(p *Profile, desired string) error {
		return s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, desired, "admin")
	}
	if err := assign(first, "installed"); err != nil {
		t.Fatal(err)
	}
	sent := profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "InstallProfile")
	current, err := s.SaveProfile(t.Context(), 1, first.ID, first.Revision, ssoReservationData(t, first.Identifier, "https://new.example.test/", "System", "com.example.Provider.extension"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	assertSSOClaimCount(t, s, d, first.ID, 2)
	if err = assign(oldRoute, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("sent historical route was freed by catalog update", err)
	}
	adeConnect(t, s, d, "Acknowledged", sent, nil)
	drainCommands(t, s, d, []InstalledProfile{{Identifier: first.Identifier, UUID: first.UUID}})
	if err = assign(oldRoute, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("old UUID released historical routes", err)
	}
	if err = assign(current, "installed"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}})
	assertSSOClaimCount(t, s, d, current.ID, 1)
	if err = assign(oldRoute, "installed"); err != nil {
		t.Fatal("fresh replacement did not release its old route", err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}, {Identifier: oldRoute.Identifier, UUID: oldRoute.UUID}})
	if err = assign(current, "removed"); err != nil {
		t.Fatal(err)
	}
	remove := profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "RemoveProfile")
	query := profileObservationCommand(t, adeConnect(t, s, d, "Acknowledged", remove, nil), "ProfileList")
	if err = assign(newRoute, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("removal acceptance released an unverified route", err)
	}
	adeConnect(t, s, d, "Acknowledged", query, map[string]any{"ProfileList": []any{map[string]any{"PayloadIdentifier": oldRoute.Identifier, "PayloadUUID": oldRoute.UUID}}})
	assertSSOClaimCount(t, s, d, current.ID, 0)
	if err = assign(newRoute, "installed"); err != nil {
		t.Fatal("verified removal kept the route reserved", err)
	}
}

func TestSSORouteReservationConcurrencyAndAtomicProfileChanges(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "SSO reservation concurrency", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	a := saveSSOReservationProfile(t, s, "com.example.sso.a", "https://shared.example.test/", "System", "com.example.One.extension")
	b := saveSSOReservationProfile(t, s, "com.example.sso.b", "https://shared.example.test/", "System", "com.example.Two.extension")
	results := make(chan error, 2)
	start := make(chan struct{})
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
		t.Fatal("concurrent routing reservations were not serialized")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_sso_reservations WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected assignment left a reservation", err)
	}
	independent := saveSSOReservationProfile(t, s, "com.example.sso.independent", "https://independent.example.test/", "System", "com.example.Three.extension")
	if err := s.AssignProfile(t.Context(), scope, independent.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveProfile(t.Context(), 1, independent.ID, 1, ssoReservationData(t, independent.Identifier, "https://shared.example.test/", "System", "com.example.Three.extension"), "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("catalog update bypassed routing conflict", err)
	}
	if history := revisionHistory(t, s, independent.ID); len(history) != 1 {
		t.Fatal("failed catalog update left a retained revision")
	}
	assertSSOClaimCount(t, s, d, independent.ID, 1)
	third := saveSSOReservationProfile(t, s, "com.example.sso.audit", "https://audit.example.test/", "System", "com.example.Four.extension")
	adeExec(t, s, `CREATE FUNCTION reject_sso_assignment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.installed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_sso_assignment_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_sso_assignment_audit()`)
	if err := s.AssignProfile(t.Context(), scope, third.ID, []string{d.ID}, "installed", "admin"); err == nil {
		t.Fatal("assignment committed without audit")
	}
	assertSSOClaimCount(t, s, d, third.ID, 0)
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND profile_id=$2`, d.ID, third.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("audit failure leaked a profile command", err)
	}
	for _, foreign := range []Scope{{TenantID: 2, SiteID: 2}, {TenantID: 1, SiteID: 2}} {
		if err := s.AssignProfile(t.Context(), foreign, third.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrNotFound) {
			t.Fatal("routing assignment crossed scope", err)
		}
	}
}

func TestSSORouteReservationsRespectUserIsolationAndPlatformSSOMerging(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "SSO user routing", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	alice, bob := testUserEnroll(t, s, d, "alice"), testUserEnroll(t, s, d, "bob")
	system := saveSSOReservationProfile(t, s, "com.example.sso.system", "https://shared.example.test/", "System", "com.example.Provider.extension")
	merged := saveSSOReservationProfile(t, s, "com.example.sso.merged", "https://shared.example.test/", "User", "com.example.Provider.extension")
	other := saveSSOReservationProfile(t, s, "com.example.sso.conflicting", "https://shared.example.test/", "User", "com.example.Other.extension")
	if err := s.AssignProfile(t.Context(), scope, system.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignUserProfile(t.Context(), scope, d.ID, alice.ID, merged.ID, "installed", "admin"); err != nil {
		t.Fatal("same-provider device/user merge was blocked", err)
	}
	if err := s.AssignUserProfile(t.Context(), scope, d.ID, bob.ID, other.ID, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("different provider overlapped the System route", err)
	}
	first := saveSSOReservationProfile(t, s, "com.example.sso.alice", "https://user.example.test/", "User", "com.example.Alice.extension")
	second := saveSSOReservationProfile(t, s, "com.example.sso.bob", "https://user.example.test/", "User", "com.example.Bob.extension")
	if err := s.AssignUserProfile(t.Context(), scope, d.ID, alice.ID, first.ID, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignUserProfile(t.Context(), scope, d.ID, bob.ID, second.ID, "installed", "admin"); err != nil {
		t.Fatal("independent users shared a routing namespace", err)
	}
	if err := s.AssignUserProfile(t.Context(), scope, d.ID, alice.ID, second.ID, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("same-user duplicate route accepted", err)
	}
	systemConflict := saveSSOReservationProfile(t, s, "com.example.sso.systemconflict", "https://user.example.test/", "System", "com.example.Other.extension")
	if err := s.AssignProfile(t.Context(), scope, systemConflict.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("System routing ignored existing user profiles", err)
	}
}

func TestSSORouteReservationMigrationRetainsDispatchedAndMissingHistory(t *testing.T) {
	s := testStoreBeforeMigration(t, "migrations/033_sso_route_reservations.sql")
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Legacy SSO reservations", "Mac16,1", "15.0")
	seedLegacyMacProfileInventory(t, s, d)
	first := saveSSOReservationProfile(t, s, "com.example.sso.migrated", "https://old.example.test/", "System", "com.example.Provider.extension")
	current, err := s.SaveProfile(t.Context(), 1, first.ID, 1, ssoReservationData(t, first.Identifier, "https://current.example.test/", "System", "com.example.Provider.extension"), "admin")
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
		t.Fatal("reservation migration was not idempotent", err)
	}
	assertSSOClaimCount(t, s, d, first.ID, 3)
	var missing int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_sso_reservations WHERE device_id=$1 AND profile_revision_id IS NULL`, d.ID).Scan(&missing); err != nil || missing != 1 {
		t.Fatal("migration invented a missing snapshot", err)
	}
	other := saveSSOReservationProfile(t, s, "com.example.sso.migrationother", "https://other.example.test/", "System", "com.example.Other.extension")
	if err = s.AssignProfile(t.Context(), scope, other.ID, []string{d.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("unknown legacy routing was assumed free", err)
	}
	if err = s.AssignProfile(t.Context(), scope, current.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: current.Identifier, UUID: current.UUID}})
	assertSSOClaimCount(t, s, d, first.ID, 1)
	if err = s.AssignProfile(t.Context(), scope, other.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal("fresh replacement did not resolve missing legacy routing", err)
	}
}

func TestSSOUserRouteReservationsRequireFreshProfileEvidence(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "SSO user observations", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	u := testUserEnroll(t, s, d, "alice")
	oldList, kind := userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "ProfileList" {
		t.Fatal(kind)
	}
	p := saveSSOReservationProfile(t, s, "com.example.sso.userobserved", "https://old.example.test/", "User", "com.example.Provider.extension")
	oldRoute := saveSSOReservationProfile(t, s, "com.example.sso.userold", "https://old.example.test/", "User", "com.example.Other.extension")
	newRoute := saveSSOReservationProfile(t, s, "com.example.sso.usernew", "https://new.example.test/", "User", "com.example.Other.extension")
	assign := func(p *Profile, desired string) error {
		return s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, desired, "admin")
	}
	if err := assign(p, "installed"); err != nil {
		t.Fatal(err)
	}
	sent, kind := userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "InstallProfile" {
		t.Fatal(kind)
	}
	current, err := s.SaveProfile(t.Context(), 1, p.ID, 1, ssoReservationData(t, p.Identifier, "https://new.example.test/", "User", "com.example.Provider.extension"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	assertSSOClaimCount(t, s, d, p.ID, 2)
	if err = assign(oldRoute, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("user catalog update freed the old route", err)
	}
	install, kind := userCommand(t, s, d, u, userReply(d, u, "Acknowledged", sent))
	if kind != "InstallProfile" {
		t.Fatal(kind)
	}
	list, kind := userCommand(t, s, d, u, userReply(d, u, "Acknowledged", install))
	if kind != "ProfileList" {
		t.Fatal(kind)
	}
	old := userReply(d, u, "Acknowledged", list)
	old["ProfileList"] = []any{map[string]any{"PayloadIdentifier": p.Identifier, "PayloadUUID": p.UUID}}
	userCommand(t, s, d, u, old)
	if err = assign(oldRoute, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("old user UUID released a reservation", err)
	}
	if err = assign(current, "installed"); err != nil {
		t.Fatal(err)
	}
	install, kind = userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "InstallProfile" {
		t.Fatal(kind)
	}
	list, kind = userCommand(t, s, d, u, userReply(d, u, "Acknowledged", install))
	if kind != "ProfileList" {
		t.Fatal(kind)
	}
	fresh := userReply(d, u, "Acknowledged", list)
	fresh["ProfileList"] = []any{map[string]any{"PayloadIdentifier": current.Identifier, "PayloadUUID": current.UUID}}
	userCommand(t, s, d, u, fresh)
	assertSSOClaimCount(t, s, d, p.ID, 1)
	if err = assign(current, "removed"); err != nil {
		t.Fatal(err)
	}
	remove, kind := userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "RemoveProfile" {
		t.Fatal(kind)
	}
	list, kind = userCommand(t, s, d, u, userReply(d, u, "Acknowledged", remove))
	if kind != "ProfileList" {
		t.Fatal(kind)
	}
	stale := userReply(d, u, "Acknowledged", oldList)
	stale["ProfileList"] = []any{}
	userCommand(t, s, d, u, stale)
	if err = assign(newRoute, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("acceptance or stale user inventory released the route", err)
	}
	fresh = userReply(d, u, "Acknowledged", list)
	fresh["ProfileList"] = []any{}
	userCommand(t, s, d, u, fresh)
	assertSSOClaimCount(t, s, d, p.ID, 0)
	if err = assign(newRoute, "installed"); err != nil {
		t.Fatal("verified user removal did not free the route", err)
	}
}
