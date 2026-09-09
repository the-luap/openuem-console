package apple

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"sync"
	"testing"
	"time"
)

func macAdminFixture(t *testing.T) (*Store, *Device) {
	t.Helper()
	s, _, _, _, selector, info := adeArmedFixture(t, MacAdminOptions{ShortName: "localadmin", FullName: "Managed Admin", Hidden: true, PrimaryAccount: "standard", RotationDays: 30})
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(profile)
	d, _ := adeAuthenticate(t, s, info, profile, true)
	return s, d
}
func macAdminStateForTest(t *testing.T, s *Store, d *Device) *MacAdminAccount {
	t.Helper()
	a, err := s.MacAdmin(t.Context(), Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil || a == nil {
		t.Fatal("missing administrator metadata", err)
	}
	return a
}
func macAdminDrive(t *testing.T, s *Store, d *Device, wire map[string]any, until string, awaiting bool, accounts []any) map[string]any {
	t.Helper()
	if wire == nil {
		wire = adeConnect(t, s, d, "Idle", "", nil)
	}
	for range 30 {
		if wire == nil {
			if until != "" {
				t.Fatal("expected administrator workflow command", until)
			}
			return nil
		}
		kind := wire["Command"].(map[string]any)["RequestType"].(string)
		if kind == until {
			return wire
		}
		if kind == "AccountConfiguration" || kind == "SetAutoAdminPassword" {
			t.Fatal("unexpected password mutation", kind)
		}
		fields := map[string]any{}
		switch kind {
		case "DeviceInformation":
			fields["QueryResponses"] = map[string]any{"SerialNumber": d.SerialNumber, "ProductName": "Mac14,7", "OSVersion": "15.6", "IsSupervised": true, "IsAppleSilicon": true, "AwaitingConfiguration": awaiting, "AutoSetupAdminAccounts": accounts}
		case "ProfileList":
			fields["ProfileList"] = []any{}
		case "InstalledApplicationList":
			fields["InstalledApplicationList"] = []any{}
		case "SecurityInfo":
			fields["SecurityInfo"] = map[string]any{"ManagementStatus": map[string]any{"IsUserEnrollment": false, "UserApprovedEnrollment": true}}
		case "AvailableOSUpdates":
			fields["AvailableOSUpdates"] = []any{}
		}
		wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), fields)
	}
	t.Fatal("administrator workflow failed to settle")
	return nil
}
func macAdminEstablished(t *testing.T, s *Store, d *Device) string {
	t.Helper()
	wire := macAdminDrive(t, s, d, nil, "AccountConfiguration", true, []any{})
	if adeSetupCommand(t, s, d) != "" {
		t.Fatal("setup released before account configuration")
	}
	command := wire["Command"].(map[string]any)
	if command["SetPrimarySetupAccountAsRegularUser"] != true || len(command["AutoSetupAdminAccounts"].([]any)) != 1 {
		t.Fatal("wrong account policy")
	}
	wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	a := macAdminStateForTest(t, s, d)
	if a.CreationState != "accepted" || a.GUID != "" {
		t.Fatal("acknowledgement confused with account report")
	}
	guid := uuid.NewString()
	accounts := []any{map[string]any{"shortName": "localadmin", "GUID": guid}}
	wire = macAdminDrive(t, s, d, wire, "DeviceConfigured", true, accounts)
	wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	macAdminDrive(t, s, d, wire, "", false, accounts)
	a = macAdminStateForTest(t, s, d)
	if a.GUID != guid || a.InventoryState != "present" || a.NextRotationAt == nil || adeSetupState(t, s, d).SetupState != "complete" {
		t.Fatal("missing post-setup account observation")
	}
	return guid
}
func TestMacAdminProvisionRotationUnknownAndLateResponse(t *testing.T) {
	s, d := macAdminFixture(t)
	guid := macAdminEstablished(t, s, d)
	scope := Scope{TenantID: 1, SiteID: 1}
	old := macAdminStateForTest(t, s, d).CurrentKeyID
	password, err := s.revealMacAdminPassword(t.Context(), scope, d.ID, old, "admin", nil)
	if err != nil || !validMacAdminPassword(password) {
		t.Fatal("missing retained password", err)
	}
	defer clear(password)
	var sealed []byte
	if err = s.db.QueryRow(`SELECT password FROM mdm_apple_mac_admin_keys WHERE id=$1`, old).Scan(&sealed); err != nil || bytes.Contains(sealed, password) {
		t.Fatal("password stored in plaintext", err)
	}
	if err = s.requestMacAdmin(t.Context(), scope, d.ID, "pause_rotation", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.requestMacAdmin(t.Context(), scope, d.ID, "rotate", "admin", nil); err != nil {
		t.Fatal(err)
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	command := wire["Command"].(map[string]any)
	id := wire["CommandUUID"].(string)
	if command["RequestType"] != "SetAutoAdminPassword" || command["GUID"] != guid {
		t.Fatal("rotation targeted wrong account")
	}
	if wire = adeConnect(t, s, d, "Idle", "", nil); wire != nil {
		t.Fatal("sent mutation was automatically redelivered")
	}
	adeExec(t, s, `UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
	adeConnect(t, s, d, "Idle", "", nil)
	a := macAdminStateForTest(t, s, d)
	if a.LatestStatus != "uncertain" || a.CurrentKeyID != old {
		t.Fatal("lost response advanced password")
	}
	if err = s.requestMacAdmin(t.Context(), scope, d.ID, "rotate", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("unresolved mutation allowed another candidate", err)
	}
	if err = s.RetryCommand(t.Context(), scope, d.ID, id, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("generic retry accepted", err)
	}
	wire = adeConnect(t, s, d, "Acknowledged", id, nil)
	a = macAdminStateForTest(t, s, d)
	if a.LatestStatus != "acknowledged" || a.CurrentKeyID == old || !a.RotationPaused || a.NextRotationAt != nil {
		t.Fatal("late exact acknowledgement lost")
	}
	macAdminDrive(t, s, d, wire, "", false, []any{map[string]any{"shortName": "localadmin", "GUID": guid}})
	current := a.CurrentKeyID
	// An older terminal response cannot restore the previous password or schedule.
	var oldCommand string
	if err = s.db.QueryRow(`SELECT command_id FROM mdm_apple_mac_admin_keys WHERE id=$1`, old).Scan(&oldCommand); err != nil {
		t.Fatal(err)
	}
	adeConnect(t, s, d, "Acknowledged", oldCommand, nil)
	if macAdminStateForTest(t, s, d).CurrentKeyID != current {
		t.Fatal("duplicate response rolled password back")
	}
	keys, err := s.MacAdminKeys(t.Context(), scope, d.ID)
	if err != nil || len(keys) != 2 {
		t.Fatal("history lost", err)
	}
}
func TestMacAdminNotNowFailureSchedulingAndIdentityConflict(t *testing.T) {
	s, d := macAdminFixture(t)
	guid := macAdminEstablished(t, s, d)
	scope := Scope{TenantID: 1, SiteID: 1}

	if err := s.requestMacAdmin(t.Context(), scope, d.ID, "pause_rotation", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if a := macAdminStateForTest(t, s, d); !a.RotationPaused || a.NextRotationAt != nil {
		t.Fatal("rotation schedule did not pause")
	}
	adeExec(t, s, `UPDATE mdm_apple_mac_admin_accounts SET next_rotation_at=clock_timestamp()-interval '1 second',next_check_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	if err := s.ReconcileMacAdmins(t.Context()); err != nil {
		t.Fatal(err)
	}
	if a := macAdminStateForTest(t, s, d); a.LatestStatus != "acknowledged" {
		t.Fatal("paused schedule created a candidate")
	}
	if err := s.requestMacAdmin(t.Context(), scope, d.ID, "resume_rotation", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if a := macAdminStateForTest(t, s, d); a.RotationPaused || a.NextRotationAt == nil || !a.NextRotationAt.After(time.Now().Add(29*24*time.Hour)) {
		t.Fatal("resume failed to start a new interval")
	}
	adeExec(t, s, `UPDATE mdm_apple_mac_admin_accounts SET next_rotation_at=clock_timestamp()-interval '1 second',next_check_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	if err := s.ReconcileMacAdmins(t.Context()); err != nil {
		t.Fatal(err)
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	id := wire["CommandUUID"].(string)
	adeConnect(t, s, d, "NotNow", id, nil)
	if wire = adeConnect(t, s, d, "Idle", "", nil); wire != nil {
		t.Fatal("NotNow backoff ignored")
	}
	adeExec(t, s, `UPDATE mdm_apple_commands SET available_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
	wire = adeConnect(t, s, d, "Idle", "", nil)
	if wire["CommandUUID"] != id {
		t.Fatal("NotNow generated another candidate")
	}
	adeConnect(t, s, d, "Error", id, map[string]any{"ErrorChain": []any{map[string]any{"LocalizedDescription": "SENSITIVE-ERROR-CONTENT"}}})
	a := macAdminStateForTest(t, s, d)
	if a.LatestStatus != "failed" || a.NextRotationAt != nil {
		t.Fatal("failed operation continued scheduling")
	}
	var message string
	if err := s.db.QueryRow(`SELECT error FROM mdm_apple_commands WHERE id=$1`, id).Scan(&message); err != nil || message != "command_failed" {
		t.Fatal("raw command error retained", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_mac_admin_accounts SET next_check_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	if err := s.ReconcileMacAdmins(t.Context()); err != nil {
		t.Fatal(err)
	}
	if macAdminStateForTest(t, s, d).LatestStatus != "failed" {
		t.Fatal("failed password operation retried automatically")
	}
	if err := s.RefreshInventory(t.Context(), scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	macAdminDrive(t, s, d, nil, "", false, []any{map[string]any{"shortName": "localadmin", "GUID": uuid.NewString()}})
	a = macAdminStateForTest(t, s, d)
	if a.GUID != guid || a.InventoryState != "conflict" {
		t.Fatal("account identity rebound")
	}
	if err := s.requestMacAdmin(t.Context(), scope, d.ID, "rotate", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting account allowed rotation", err)
	}
}
func TestMacAdminAuthorizationAuditAndLifecycle(t *testing.T) {
	s, d := macAdminFixture(t)
	macAdminEstablished(t, s, d)
	scope := Scope{TenantID: 1, SiteID: 1}
	key := macAdminStateForTest(t, s, d).CurrentKeyID
	if err := s.RequestMacAdmin(t.Context(), scope, d.ID, "rotate", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing authorization accepted", err)
	}
	if p, err := s.RevealMacAdminPassword(t.Context(), scope, d.ID, key, "admin", nil); len(p) != 0 || !errors.Is(err, access.ErrDenied) {
		t.Fatal("unauthorized reveal", err)
	}
	for _, scope := range []Scope{{TenantID: 2, SiteID: 2}, {TenantID: 1, SiteID: 2}} {
		if p, err := s.revealMacAdminPassword(t.Context(), scope, d.ID, key, "admin", nil); len(p) != 0 || !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-scope reveal", err)
		}
		if err := s.requestMacAdmin(t.Context(), scope, d.ID, "rotate", "admin", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-scope mutation", err)
		}
	}
	adeExec(t, s, `ALTER TABLE mdm_apple_audit ADD CONSTRAINT mac_admin_audit_test CHECK(action NOT IN ('apple.mac_admin.rotate','apple.mac_admin.password.reveal'))`)
	if err := s.requestMacAdmin(t.Context(), scope, d.ID, "rotate", "admin", nil); err == nil {
		t.Fatal("mutation committed without audit")
	}
	keys, _ := s.MacAdminKeys(t.Context(), scope, d.ID)
	if len(keys) != 1 {
		t.Fatal("failed audit retained a candidate")
	}
	if p, err := s.revealMacAdminPassword(t.Context(), scope, d.ID, key, "admin", nil); len(p) > 0 || err == nil {
		t.Fatal("reveal escaped failed audit")
	}
	adeExec(t, s, `ALTER TABLE mdm_apple_audit DROP CONSTRAINT mac_admin_audit_test`)
	if err := s.requestMacAdmin(t.Context(), scope, d.ID, "rotate", "admin", nil); err != nil {
		t.Fatal(err)
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	if wire == nil {
		t.Fatal("rotation was not delivered")
	}
	if err := s.CheckIn(t.Context(), d, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID}); err != nil {
		t.Fatal(err)
	}
	a := macAdminStateForTest(t, s, d)
	if a.LatestStatus != "uncertain" || a.NextRotationAt != nil {
		t.Fatal("checkout discarded an unresolved operation")
	}
	if p, err := s.revealMacAdminPassword(t.Context(), scope, d.ID, key, "admin", nil); err != nil || len(p) != 43 {
		t.Fatal("checkout destroyed retained recovery credential", err)
	} else {
		clear(p)
	}
}
func TestMacAdminCreationExpiryAndFreshInventory(t *testing.T) {
	s, d := macAdminFixture(t)
	wire := macAdminDrive(t, s, d, nil, "AccountConfiguration", true, []any{})
	id := wire["CommandUUID"].(string)
	adeConnect(t, s, d, "Error", id, nil)
	if adeSetupCommand(t, s, d) != "" {
		t.Fatal("failed account setup released hold")
	}
	if err := s.requestMacAdmin(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "retry_creation", "admin", nil); err != nil {
		t.Fatal(err)
	}
	wire = adeConnect(t, s, d, "Idle", "", nil)
	id = wire["CommandUUID"].(string)
	adeExec(t, s, `UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
	adeConnect(t, s, d, "Idle", "", nil)
	if a := macAdminStateForTest(t, s, d); a.CreationState != "uncertain" {
		t.Fatal("sent creation expiry was treated as safe to retry")
	}
	if err := s.requestMacAdmin(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "retry_creation", "admin", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("uncertain creation retried", err)
	}
	wire = adeConnect(t, s, d, "Acknowledged", id, nil)
	// The post-acceptance inventory is artificially aged to model a delayed reply.
	if wire != nil && wire["Command"].(map[string]any)["RequestType"] == "DeviceInformation" {
		adeExec(t, s, `UPDATE mdm_apple_commands SET created_at=clock_timestamp()-interval '2 days' WHERE id=$1`, wire["CommandUUID"])
	}
	macAdminDrive(t, s, d, wire, "", true, []any{map[string]any{"shortName": "localadmin", "GUID": uuid.NewString()}})
	a := macAdminStateForTest(t, s, d)
	if a.ObservedAt != nil && a.ObservedAt.After(time.Now()) {
		t.Fatal("future account evidence")
	}
}

func TestMacAdminInventoryIgnoresOldAndFutureRequests(t *testing.T) {
	s, d := macAdminFixture(t)
	guid := macAdminEstablished(t, s, d)
	scope := Scope{TenantID: 1, SiteID: 1}
	before := macAdminStateForTest(t, s, d)
	for _, age := range []string{"old", "future"} {
		if err := s.RefreshInventory(t.Context(), scope, d.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		wire := macAdminDrive(t, s, d, nil, "DeviceInformation", false, []any{map[string]any{"shortName": "localadmin", "GUID": guid}})
		if wire["Command"].(map[string]any)["RequestType"] != "DeviceInformation" {
			t.Fatal("missing fresh inventory request")
		}
		id := wire["CommandUUID"].(string)
		if age == "old" {
			adeExec(t, s, `UPDATE mdm_apple_commands SET created_at=clock_timestamp()-interval '2 days' WHERE id=$1`, id)
		} else {
			adeExec(t, s, `UPDATE mdm_apple_commands SET created_at=clock_timestamp()+interval '2 days' WHERE id=$1`, id)
		}
		wire = adeConnect(t, s, d, "Acknowledged", id, map[string]any{"QueryResponses": map[string]any{"AutoSetupAdminAccounts": []any{map[string]any{"shortName": "localadmin", "GUID": uuid.NewString()}}}})
		after := macAdminStateForTest(t, s, d)
		if after.GUID != guid || after.InventoryState != "present" || !after.ObservedAt.Equal(*before.ObservedAt) {
			t.Fatal("out-of-order report changed account evidence", age)
		}
		macAdminDrive(t, s, d, wire, "", false, []any{map[string]any{"shortName": "localadmin", "GUID": guid}})
	}
}

func TestMacAdminPolicyIsImmutableAndRequiresMacSetupHold(t *testing.T) {
	s, server, _ := adeEnrollmentStore(t)
	base := adeEnrollmentOptions()
	base.AllowDeviceLock = false
	base.MacAdmin = &MacAdminOptions{ShortName: "localadmin", PrimaryAccount: "standard"}
	for _, change := range []func(*ADEProfileOptions){func(o *ADEProfileOptions) { o.Platform = PlatformIOS }, func(o *ADEProfileOptions) { o.AwaitConfiguration = false }} {
		o := base
		change(&o)
		if _, err := s.createADEProfile(t.Context(), 1, server, o, "admin", nil); !errors.Is(err, ErrADEProfile) {
			t.Fatal("invalid administrator enrollment allowed", err)
		}
	}
	id, err := s.createADEProfile(t.Context(), 1, server, base, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_ade_profiles SET admin_options=NULL WHERE id=$1`, id); err == nil {
		t.Fatal("administrator policy mutable")
	}
	if err = s.publishADEProfile(t.Context(), 1, server, id); err != nil {
		t.Fatal(err)
	}
	p := adeProfileState(t, s, server, id)
	if p.MacAdmin == nil || p.MacAdmin.ShortName != "localadmin" || p.DeviceLockAllowed {
		t.Fatal("account policy depends on device lock rights")
	}
}

func TestRecoveryLockAcceptsAuthenticatedADEMac(t *testing.T) {
	s, _, _, _, selector, info := adeArmedFixture(t)
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	d, cert := adeAuthenticate(t, s, info, profile, false)
	drainMacHardwareInventory(t, s, d, map[string]any{"SerialNumber": info.Serial, "AwaitingConfiguration": false})
	d, err = s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.requestRecoveryLock(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "set", "", nil, "admin", nil); err != nil {
		t.Fatal("eligible ADE Mac rejected Recovery Lock", err)
	}
}

func TestMacAdminConcurrentRotationKeepsOneCandidate(t *testing.T) {
	s, d := macAdminFixture(t)
	macAdminEstablished(t, s, d)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			results <- s.requestMacAdmin(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "rotate", "admin", nil)
		})
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent password requests were not serialized", successes, conflicts)
	}
	keys, err := s.MacAdminKeys(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID)
	if err != nil || len(keys) != 2 {
		t.Fatal("duplicate password candidates persisted", err)
	}
}

// Inactive accounts must not consume the maintenance batch ahead of a due
// rotation. These ended setups are legitimate retained history without keys.
func TestMacAdminMaintenanceDoesNotStarveDueRotation(t *testing.T) {
	s, d := macAdminFixture(t)
	macAdminEstablished(t, s, d)
	var server, profile string
	if err := s.db.QueryRow(`SELECT server_id,profile_id FROM mdm_apple_ade_admissions WHERE device_id=$1`, d.ID).Scan(&server, &profile); err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		id, serial := uuid.NewString(), fmt.Sprintf("IDLEADMIN%d", i)
		adeExec(t, s, `INSERT INTO mdm_apple_ade_targets(tenant_id,server_id,serial,profile_id) VALUES(1,$1,$2,$3)`, server, serial, profile)
		adeExec(t, s, `INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,model,os_version,enrollment_method,enrollment_platform,invite_expires_at,certificate_expires_at) VALUES($1,1,1,'Ended account setup','enrolled','Mac14,7','15.6','automated_device','macos',clock_timestamp(),clock_timestamp()+interval '1 year')`, id)
		adeExec(t, s, `INSERT INTO mdm_apple_ade_admissions(device_id,tenant_id,server_id,serial,generation,profile_id,expected_udid,signer_fingerprint,expires_at,awaiting_configuration,setup_state) VALUES($1,1,$2,$3,1,$4,$1::text,repeat('d',64),clock_timestamp(),false,'complete')`, id, server, serial, profile)
		adeExec(t, s, `INSERT INTO mdm_apple_mac_admin_accounts(device_id,tenant_id,options,creation_state,next_check_at) SELECT $1,1,options,'cancelled',clock_timestamp()-interval '1 day' FROM mdm_apple_mac_admin_accounts WHERE device_id=$2`, id, d.ID)
	}
	adeExec(t, s, `UPDATE mdm_apple_mac_admin_accounts SET next_rotation_at=clock_timestamp()-interval '1 second',next_check_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	if err := s.ReconcileMacAdmins(t.Context()); err != nil {
		t.Fatal(err)
	}
	if a := macAdminStateForTest(t, s, d); a.LatestStatus != "queued" || a.LatestOperation != "rotate" {
		t.Fatal("idle accounts starved the due rotation")
	}
}
