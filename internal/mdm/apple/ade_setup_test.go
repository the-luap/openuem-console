package apple

import (
	"bytes"
	"errors"
	"testing"

	"howett.net/plist"
)

func adeSetupState(t *testing.T, s *Store, d *Device) *ADEDeviceEnrollment {
	t.Helper()
	state, err := s.ADEDeviceEnrollment(t.Context(), Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil || state == nil {
		t.Fatal("missing ADE setup state", err)
	}
	return state
}

func adeSetupCommand(t *testing.T, s *Store, d *Device) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(`SELECT COALESCE(setup_command_id::text,'') FROM mdm_apple_ade_admissions WHERE device_id=$1`, d.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func adeSetupReady(t *testing.T, s *Store, d *Device) {
	t.Helper()
	// Complete the unrelated inventory queue so tests can control the exact
	// DeviceConfigured response and test observation freshness independently.
	adeExec(t, s, `UPDATE mdm_apple_commands SET status='acknowledged',completed_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	adeExec(t, s, `UPDATE mdm_apple_devices SET inventory_at=clock_timestamp(),profiles_at=clock_timestamp() WHERE id=$1`, d.ID)
	adeExec(t, s, `UPDATE mdm_apple_ade_admissions SET next_setup_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	if err := s.ReconcileADESetups(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func adeConnect(t *testing.T, s *Store, d *Device, status, id string, fields map[string]any) map[string]any {
	t.Helper()
	message := map[string]any{"UDID": d.UDID, "Status": status}
	if id != "" {
		message["CommandUUID"] = id
	}
	for k, v := range fields {
		message[k] = v
	}
	data, err := s.Connect(t.Context(), d, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
	}
	var wire map[string]any
	if _, err = plist.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestADESetupWaitsForInventoryAndActualRelease(t *testing.T) {
	s, server, _, _, selector, info := adeArmedFixture(t)
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := adeAuthenticate(t, s, info, profile, true)
	if err = s.ReconcileADESetups(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state := adeSetupState(t, s, d); state.SetupState != "awaiting" || state.SetupError != "configuration_pending" || adeSetupCommand(t, s, d) != "" {
		t.Fatal("setup released before inventory", state.SetupState, state.SetupError)
	}
	// Exercise the actual inventory/command protocol, including automatic
	// DeviceConfigured and its follow-up DeviceInformation request.
	drainMacHardwareInventory(t, s, d, map[string]any{"SerialNumber": info.Serial, "AwaitingConfiguration": true})
	if state := adeSetupState(t, s, d); state.SetupState != "releasing" || adeSetupCommand(t, s, d) == "" {
		t.Fatal("acknowledgement was confused with release", state.SetupState)
	}
	var commandStatus string
	if err = s.db.QueryRow(`SELECT status FROM mdm_apple_commands WHERE id=$1`, adeSetupCommand(t, s, d)).Scan(&commandStatus); err != nil || commandStatus != "acknowledged" {
		t.Fatal("DeviceConfigured was not delivered and acknowledged", commandStatus, err)
	}
	// Removing future ADE assignment must not invalidate an already bound MDM
	// identity, including TokenUpdate after its initial admission expires.
	if err = s.setADETargets(t.Context(), 1, server, "", []string{info.Serial}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `UPDATE mdm_apple_ade_admissions SET expires_at=clock_timestamp()-interval '1 hour' WHERE device_id=$1`, d.ID)
	token := map[string]any{"MessageType": "TokenUpdate", "Topic": "com.apple.mgmt.test", "UDID": d.UDID, "Token": []byte("synthetic-new-token"), "PushMagic": "synthetic-new-magic", "AwaitingConfiguration": false}
	if err = s.CheckIn(t.Context(), d, token); err != nil {
		t.Fatal(err)
	}
	if state := adeSetupState(t, s, d); state.SetupState != "complete" || state.AwaitingConfiguration == nil || *state.AwaitingConfiguration {
		t.Fatal("actual release was not recorded")
	}
	token["AwaitingConfiguration"] = true
	if err = s.CheckIn(t.Context(), d, token); err != nil || adeSetupState(t, s, d).SetupState != "complete" {
		t.Fatal("late report reopened completed setup", err)
	}
	// The replacement identity must retain ADE's removal policy.
	testIdentityDue(t, s, d)
	if err = s.ScheduleIdentityRenewals(t.Context()); err != nil {
		t.Fatal(err)
	}
	renewal := testIdentityGeneration(t, s, d)
	replacement := testIdentityDelivery(t, s, d, renewal)
	var root map[string]any
	if _, err = plist.Unmarshal(replacement, &root); err != nil || root["PayloadRemovalDisallowed"] != true || bytes.Equal(replacement, profile) {
		t.Fatal("identity renewal lost nonremovable enrollment", err)
	}
}

func TestADESetupNotNowFailureAndExplicitRetry(t *testing.T) {
	s, _, _, _, selector, info := adeArmedFixture(t)
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := adeAuthenticate(t, s, info, profile, true)
	adeSetupReady(t, s, d)
	id := adeSetupCommand(t, s, d)
	wire := adeConnect(t, s, d, "Idle", "", nil)
	if id == "" || wire["CommandUUID"] != id || wire["Command"].(map[string]any)["RequestType"] != "DeviceConfigured" {
		t.Fatal("setup release was not delivered")
	}
	if reply := adeConnect(t, s, d, "NotNow", id, nil); reply != nil || adeSetupState(t, s, d).SetupState != "releasing" {
		t.Fatal("NotNow incorrectly finished setup")
	}
	if reply := adeConnect(t, s, d, "Idle", "", nil); reply != nil {
		t.Fatal("NotNow backoff bypassed")
	}
	adeExec(t, s, `UPDATE mdm_apple_commands SET available_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
	adeConnect(t, s, d, "Idle", "", nil)
	adeConnect(t, s, d, "Error", id, map[string]any{"ErrorChain": []any{map[string]any{"LocalizedDescription": "synthetic secret diagnostic"}}})
	if state := adeSetupState(t, s, d); state.SetupState != "failed" || state.SetupError != "command_failed" {
		t.Fatal("setup command failure was hidden")
	}
	if err = s.RetryCommand(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, id, "admin"); err == nil {
		t.Fatal("generic retry bypassed setup workflow")
	}
	if err = s.RetryADESetup(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "admin", nil); err == nil {
		t.Fatal("missing setup retry authorization accepted")
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.retryADESetupTx(t.Context(), tx, Scope{TenantID: 2}, d.ID, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign setup retry accepted", err)
	}
	tx.Rollback()
	tx, err = s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.retryADESetupTx(t.Context(), tx, Scope{TenantID: 1, SiteID: 1}, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileADESetups(t.Context()); err != nil || adeSetupCommand(t, s, d) != "" {
		t.Fatal("retry reused stale awaiting report", err)
	}
	wire = adeConnect(t, s, d, "Idle", "", nil)
	if wire["Command"].(map[string]any)["RequestType"] != "DeviceInformation" {
		t.Fatal("retry skipped actual state query")
	}
	fresh := adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), map[string]any{"QueryResponses": map[string]any{"SerialNumber": info.Serial, "ProductName": info.Product, "OSVersion": info.OSVersion, "AwaitingConfiguration": true}})
	next := adeSetupCommand(t, s, d)
	if next == "" || next == id || fresh["CommandUUID"] != next {
		t.Fatal("fresh retry did not create a separate command")
	}
	// A late old acknowledgement cannot complete or replace the new attempt.
	adeConnect(t, s, d, "Acknowledged", id, nil)
	if adeSetupCommand(t, s, d) != next || adeSetupState(t, s, d).SetupState != "releasing" {
		t.Fatal("stale acknowledgement changed current attempt")
	}
	if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID}); err != nil || adeSetupState(t, s, d).SetupState != "cancelled" {
		t.Fatal("checkout did not cancel setup", err)
	}
}

func TestADESetupRequiresVerifiedConfigurationAssignments(t *testing.T) {
	s, _, _, _, selector, info := adeArmedFixture(t)
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := adeAuthenticate(t, s, info, profile, true)
	data, err := BuildProfile("ADE Wi-Fi", "eu.example.ade-wifi", "wifi", map[string]any{"SSID_STR": "Synthetic office", "EncryptionType": "WPA2", "Password": "synthetic-only"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), Scope{TenantID: 1, SiteID: 1}, p.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	adeSetupReady(t, s, d)
	if adeSetupCommand(t, s, d) != "" {
		t.Fatal("unverified configuration allowed release")
	}
	var current map[string]any
	for _, status := range []string{"failed", "missing", "verifying"} {
		adeExec(t, s, `UPDATE mdm_apple_profile_assignments SET status=$2 WHERE device_id=$1`, d.ID, status)
		adeExec(t, s, `UPDATE mdm_apple_ade_admissions SET next_setup_at=clock_timestamp() WHERE device_id=$1`, d.ID)
		if err = s.ReconcileADESetups(t.Context()); err != nil || adeSetupCommand(t, s, d) != "" {
			t.Fatal("unverified assignment released setup", status, err)
		}
	}
	if err = s.RefreshInventory(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	current = adeConnect(t, s, d, "Idle", "", nil)
	for n := 0; n < 20 && current != nil; n++ {
		kind := current["Command"].(map[string]any)["RequestType"].(string)
		if kind == "DeviceConfigured" {
			break
		}
		fields := map[string]any{}
		switch kind {
		case "DeviceInformation":
			fields["QueryResponses"] = map[string]any{"SerialNumber": info.Serial, "ProductName": info.Product, "OSVersion": info.OSVersion, "AwaitingConfiguration": true}
		case "ProfileList":
			fields["ProfileList"] = []any{map[string]any{"PayloadIdentifier": p.Identifier, "PayloadUUID": p.UUID, "PayloadDisplayName": p.Name, "IsManaged": true}}
		case "InstalledApplicationList":
			fields["InstalledApplicationList"] = []any{}
		case "AvailableOSUpdates":
			fields["AvailableOSUpdates"] = []any{}
		case "SecurityInfo":
			fields["SecurityInfo"] = map[string]any{}
		}
		current = adeConnect(t, s, d, "Acknowledged", current["CommandUUID"].(string), fields)
	}
	if current == nil || current["Command"].(map[string]any)["RequestType"] != "DeviceConfigured" {
		t.Fatal("verified profile inventory did not allow setup release")
	}
}
