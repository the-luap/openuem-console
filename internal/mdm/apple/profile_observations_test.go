package apple

import (
	"strings"
	"testing"

	"howett.net/plist"
)

func profileObservationCommand(t *testing.T, wire map[string]any, kind string) string {
	t.Helper()
	if wire == nil || wire["Command"].(map[string]any)["RequestType"] != kind {
		t.Fatalf("expected %s command", kind)
	}
	return wire["CommandUUID"].(string)
}

func TestSystemProfileObservationUsesAssignedRevisionAndPostAcknowledgementQuery(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Profile observations", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	first, err := s.SaveProfile(t.Context(), 1, "", 0, revisionWiFi(t, "Original", "synthetic-original"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.SaveProfile(t.Context(), 1, first.ID, 1, revisionWiFi(t, "Current", "synthetic-current"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	queueList := func() string {
		tx, err := s.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		id, err := s.enqueue(t.Context(), tx, d, "ProfileList", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assignRetained := func(desired string) {
		tx, err := s.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		// The retained payload drives the real assignment and command path. A
		// public ADE pinning workflow is intentionally a separate integration.
		if err = s.assign(t.Context(), tx, d, first, desired); err != nil {
			t.Fatal(err)
		}
		var ordered bool
		if err = tx.QueryRowContext(t.Context(), `SELECT a.updated_at>now() AND c.created_at>=a.updated_at FROM mdm_apple_profile_assignments a JOIN mdm_apple_commands c ON c.device_id=a.device_id AND c.profile_id=a.profile_id AND c.profile_revision=a.revision WHERE a.device_id=$1 AND a.profile_id=$2 AND c.status='queued'`, d.ID, first.ID).Scan(&ordered); err != nil || !ordered {
			t.Fatal("assignment/query ordering used transaction-start time", err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	assertState := func(want string) {
		items, err := s.Assignments(t.Context(), scope, d.ID)
		if err != nil || len(items) != 1 || items[0].Revision != 1 || items[0].Status != want {
			t.Fatalf("expected retained revision 1 to be %s: %+v, %v", want, items, err)
		}
	}
	observed := func(p *Profile) map[string]any {
		// macOS omits IsManaged. UUID spelling may differ in case.
		return map[string]any{"ProfileList": []any{map[string]any{"PayloadIdentifier": p.Identifier, "PayloadUUID": strings.ToUpper(p.UUID)}}}
	}
	old := queueList()
	if id := profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "ProfileList"); id != old {
		t.Fatal("old inventory was not delivered")
	}
	adeConnect(t, s, d, "NotNow", old, nil)
	assignRetained("installed")
	wire := adeConnect(t, s, d, "Idle", "", nil)
	install := profileObservationCommand(t, wire, "InstallProfile")
	var payload map[string]any
	if _, err = plist.Unmarshal(wire["Command"].(map[string]any)["Payload"].([]byte), &payload); err != nil || payload["PayloadUUID"] != first.UUID {
		t.Fatal("historical assignment installed the current catalog payload", err)
	}
	fresh := profileObservationCommand(t, adeConnect(t, s, d, "Acknowledged", install, nil), "ProfileList")
	assertState("verifying")
	adeConnect(t, s, d, "Acknowledged", old, observed(first))
	assertState("verifying")
	adeConnect(t, s, d, "Acknowledged", fresh, observed(current))
	assertState("missing")
	fresh = queueList()
	profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "ProfileList")
	adeConnect(t, s, d, "Acknowledged", fresh, observed(first))
	assertState("verified")

	// A delayed empty observation must not verify a later removal.
	old = queueList()
	profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "ProfileList")
	adeConnect(t, s, d, "NotNow", old, nil)
	assignRetained("removed")
	remove := profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "RemoveProfile")
	fresh = profileObservationCommand(t, adeConnect(t, s, d, "Acknowledged", remove, nil), "ProfileList")
	empty := map[string]any{"ProfileList": []any{}}
	adeConnect(t, s, d, "Acknowledged", old, empty)
	assertState("verifying")
	adeConnect(t, s, d, "Acknowledged", fresh, empty)
	assertState("verified")

	// Pre-history assignments can refer to an unavailable old revision. Never
	// substitute the newest catalog entry when that snapshot is missing.
	adeExec(t, s, `UPDATE mdm_apple_profile_assignments SET revision=99,desired='installed',status='verifying',updated_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	fresh = queueList()
	profileObservationCommand(t, adeConnect(t, s, d, "Idle", "", nil), "ProfileList")
	adeConnect(t, s, d, "Acknowledged", fresh, observed(current))
	items, err := s.Assignments(t.Context(), scope, d.ID)
	if err != nil || len(items) != 1 || items[0].Status != "verifying" {
		t.Fatal("missing retained revision fell back to current catalog", err)
	}
}

func TestMacUserProfileObservationRetainsVersionWithoutIsManaged(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "User observations", "Mac16,1", "15.0")
	u := testUserEnroll(t, s, d, "alice")
	data := userProfileData(t, "com.apple.ManagedClient.preferences", nil)
	first, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.SaveProfile(t.Context(), 1, first.ID, 1, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = s.assignUserProfile(t.Context(), tx, d, u, first, "installed"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	install, kind := userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "InstallProfile" {
		t.Fatal("retained user profile was not queued")
	}
	list, kind := userCommand(t, s, d, u, userReply(d, u, "Acknowledged", install))
	if kind != "ProfileList" {
		t.Fatal("user installation did not request confirmation")
	}
	ack := userReply(d, u, "Acknowledged", list)
	ack["ProfileList"] = []any{map[string]any{"PayloadIdentifier": current.Identifier, "PayloadUUID": current.UUID}}
	userCommand(t, s, d, u, ack)
	items, err := s.UserAssignments(t.Context(), scope, d.ID, u.ID)
	if err != nil || len(items) != 1 || items[0].Status != "drifted" || items[0].Revision != 1 {
		t.Fatal("current catalog UUID verified a retained user version", err)
	}
	if err = s.RefreshUserInventory(t.Context(), scope, d.ID, u.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	list, kind = userCommand(t, s, d, u, userReply(d, u, "Idle", ""))
	if kind != "ProfileList" {
		t.Fatal("user inventory refresh did not queue a query")
	}
	ack = userReply(d, u, "Acknowledged", list)
	ack["ProfileList"] = []any{map[string]any{"PayloadIdentifier": first.Identifier, "PayloadUUID": strings.ToUpper(first.UUID)}}
	userCommand(t, s, d, u, ack)
	items, err = s.UserAssignments(t.Context(), scope, d.ID, u.ID)
	if err != nil || len(items) != 1 || items[0].Status != "verified" || items[0].Revision != 1 {
		t.Fatal("retained Mac user profile required the absent IsManaged field", err)
	}
}
