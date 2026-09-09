package apple

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func macAppFixture(t *testing.T) (*Store, *Device, *SoftwareVersion) {
	t.Helper()
	s := testStore(t)
	testSettings(t, s, 1)
	d, _, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "App delivery", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	v, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, testMacAppPackage(), "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, d, v
}

func macAppState(t *testing.T, s *Store, d *Device) MacAppAssignment {
	t.Helper()
	items, next, err := s.MacApps(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "")
	if err != nil || len(items) != 1 || next != "" {
		t.Fatal("missing application assignment", err)
	}
	return items[0]
}

func macAppObserve(t *testing.T, s *Store, d *Device, wire map[string]any, managed, version string) {
	t.Helper()
	if wire == nil {
		wire = adeConnect(t, s, d, "Idle", "", nil)
	}
	for range 8 {
		if wire == nil {
			return
		}
		command := wire["Command"].(map[string]any)
		if ids, ok := command["Identifiers"].([]any); !ok || len(ids) != 1 || ids[0] != "com.example.Editor" {
			t.Fatal("application query was not restricted to the assigned app")
		}
		fields := map[string]any{}
		switch command["RequestType"] {
		case "ManagedApplicationList":
			items := map[string]any{}
			if managed != "" {
				items["com.example.Editor"] = map[string]any{"Status": managed}
			}
			fields["ManagedApplicationList"] = items
		case "InstalledApplicationList":
			items := []any{}
			if version != "" {
				items = append(items, map[string]any{"Identifier": "com.example.Editor", "Version": version, "Installing": false})
			}
			fields["InstalledApplicationList"] = items
		default:
			t.Fatal("unexpected app mutation while observing", command["RequestType"])
		}
		wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), fields)
	}
	t.Fatal("application observation did not settle")
}

func TestMacAppInstallVersionVerificationAndRemoval(t *testing.T) {
	s, d, v := macAppFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	if err := s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{RemoveOnUnenroll: true}, nil); err != nil {
		t.Fatal(err)
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	id := wire["CommandUUID"].(string)
	if wire["Command"].(map[string]any)["RequestType"] != "InstallEnterpriseApplication" || macAppState(t, s, d).Status != "sent" {
		t.Fatal("native installation was not delivered")
	}
	var sealed []byte
	if err := s.db.QueryRow(`SELECT payload FROM mdm_apple_commands WHERE id=$1`, id).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("not-for-pages")) {
		t.Fatal("command leaked package source", err)
	}
	if wire = adeConnect(t, s, d, "Idle", "", nil); wire != nil {
		t.Fatal("unanswered installation automatically replayed")
	}
	wire = adeConnect(t, s, d, "Acknowledged", id, nil)
	if macAppState(t, s, d).Status != "verifying" {
		t.Fatal("command acknowledgement was confused with installation")
	}
	macAppObserve(t, s, d, wire, "Managed", "41.0")
	a := macAppState(t, s, d)
	if a.Status != "verifying" || a.InstalledVersion != "41.0" {
		t.Fatal("an older installed version satisfied the approved artifact")
	}
	if err := s.changeMacApp(t.Context(), scope, d.ID, a.ID, "refresh", "admin", nil); err != nil {
		t.Fatal(err)
	}
	macAppObserve(t, s, d, nil, "Managed", "42.0")
	if macAppState(t, s, d).Status != "verified" {
		t.Fatal("matching post-acceptance app observations were not applied")
	}
	current, err := s.Device(t.Context(), scope, d.ID)
	if err != nil || len(current.Apps) != 0 {
		t.Fatal("filtered verification overwrote the complete application inventory", err)
	}
	if err = s.RetryCommand(t.Context(), scope, d.ID, id, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("generic retry accepted an app mutation", err)
	}
	if err = s.changeMacApp(t.Context(), scope, d.ID, a.ID, "remove", "admin", nil); err != nil {
		t.Fatal(err)
	}
	wire = adeConnect(t, s, d, "Idle", "", nil)
	if wire["Command"].(map[string]any)["RequestType"] != "RemoveApplication" {
		t.Fatal("managed app removal missing")
	}
	wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	macAppObserve(t, s, d, wire, "", "")
	a = macAppState(t, s, d)
	if a.Status != "verified" || a.Operation != "remove" || a.InstalledState != "absent" {
		t.Fatal("removal was not verified from absence")
	}
	var history, site int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_app_attempts WHERE device_id=$1`, d.ID).Scan(&history); err != nil || history != 2 {
		t.Fatal("installation history was lost", err)
	}
	if err = s.db.QueryRow(`SELECT (details->>'site_id')::int FROM mdm_apple_audit WHERE resource_id=$1 AND action='apple.software.verified'`, a.AttemptID).Scan(&site); err != nil || site != 1 {
		t.Fatal("application audit lost device scope", err)
	}
}

func TestMacAppNotNowExpiryLateResponseAndStaleObservation(t *testing.T) {
	s, d, v := macAppFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	if err := s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	id := wire["CommandUUID"].(string)
	adeConnect(t, s, d, "NotNow", id, nil)
	adeExec(t, s, `UPDATE mdm_apple_commands SET available_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
	wire = adeConnect(t, s, d, "Idle", "", nil)
	if wire["CommandUUID"] != id {
		t.Fatal("deferred installation created a different command")
	}
	adeExec(t, s, `UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
	adeConnect(t, s, d, "Idle", "", nil)
	a := macAppState(t, s, d)
	if a.Status != "uncertain" {
		t.Fatal("expired sent installation treated as safe to repeat")
	}
	if err := s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("unresolved installation allowed a new attempt", err)
	}
	wire = adeConnect(t, s, d, "Acknowledged", id, nil)
	query := wire["CommandUUID"].(string)
	adeExec(t, s, `UPDATE mdm_apple_commands SET created_at=(SELECT accepted_at-interval '1 second' FROM mdm_apple_app_attempts WHERE id=$2) WHERE id=$1`, query, a.AttemptID)
	macAppObserve(t, s, d, wire, "Managed", "42.0")
	if macAppState(t, s, d).Status == "verified" {
		t.Fatal("pre-acceptance query verified the new attempt")
	}
	if err := s.changeMacApp(t.Context(), scope, d.ID, a.ID, "refresh", "admin", nil); err != nil {
		t.Fatal(err)
	}
	macAppObserve(t, s, d, nil, "Managed", "42.0")
	if macAppState(t, s, d).Status != "verified" {
		t.Fatal("late acknowledgement and fresh reports did not resolve installation")
	}
	adeConnect(t, s, d, "Error", id, map[string]any{"ErrorChain": []any{map[string]any{"LocalizedDescription": "not-for-pages"}}})
	if macAppState(t, s, d).Status != "verified" {
		t.Fatal("duplicate terminal response reversed verified state")
	}
}

func TestMacAppConcurrentRequestsWithdrawalAndCheckout(t *testing.T) {
	s, d, v := macAppFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			results <- s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil)
		})
	}
	wg.Wait()
	close(results)
	accepted, conflict := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || conflict != 1 {
		t.Fatal("concurrent installations were not serialized")
	}
	adeExec(t, s, `UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, v.ID)
	if adeConnect(t, s, d, "Idle", "", nil) != nil || macAppState(t, s, d).Status != "cancelled" {
		t.Fatal("withdrawn approval reached the device")
	}
	input := testMacAppPackage()
	input.Version = "43.0"
	v, err := s.publishMacAppPackage(t.Context(), Scope{TenantID: 1}, input, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.installMacApp(t.Context(), Scope{TenantID: 1, SiteID: 2}, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-site installation accepted", err)
	}
	if err = s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	adeConnect(t, s, d, "Idle", "", nil)
	if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID}); err != nil {
		t.Fatal(err)
	}
	if a := macAppState(t, s, d); a.Status != "not_managed" {
		t.Fatal("checkout retained active application management")
	}
	var uncertain int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_app_attempts WHERE device_id=$1 AND status='uncertain'`, d.ID).Scan(&uncertain); err != nil || uncertain != 1 {
		t.Fatal("checkout invented a stopped installer", err)
	}
}
