package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"howett.net/plist"
)

func TestPlatformDetectionAndVersionCapabilities(t *testing.T) {
	for model, want := range map[string]Platform{"iPhone16,1": PlatformIOS, "iPad16,6": PlatformIPadOS, "Mac16,1": PlatformMacOS, "MacBookPro18,3": PlatformMacOS, "iMac20,2": PlatformMacOS, "Macmini8,1": PlatformMacOS, "Mac Studio": PlatformMacOS, "": PlatformUnknown, "AppleTV14,1": PlatformUnknown, "MacAttack": PlatformUnknown, "iphone16,1": PlatformUnknown} {
		if got := DetectPlatform(model); got != want {
			t.Fatal(model, got, want)
		}
	}
	for _, entry := range []struct {
		model, version string
		ddm, update    bool
	}{{"iPhone16,1", "14.8", false, false}, {"iPad16,6", "16.0", true, false}, {"iPad16,6", "17.0", true, true}, {"Mac16,1", "12.7", false, false}, {"Mac16,1", "13.0", true, false}, {"Mac16,1", "14.0", true, true}, {"Mac16,1", "26.0", true, true}, {"", "26.0", false, false}, {"Mac16,1", "unknown", false, false}} {
		d := Device{Model: entry.model, OSVersion: entry.version, Supervised: true, SupervisedReported: true}
		c := d.Capabilities()
		if c.DeclarativeManagement != entry.ddm || c.SpecificOSUpdate != entry.update || c.UserChannel {
			t.Fatal(entry, c)
		}
	}
	mac := Device{Model: "Mac16,1", OSVersion: "15.0"}
	queries := inventoryQueriesFor(mac)
	for _, key := range []string{"SoftwareUpdateDeviceID", "IsAppleSilicon", "ProvisioningUDID", "IsSupervised"} {
		if !slices.Contains(queries, key) {
			t.Fatal("Mac query missing", key)
		}
	}
	for _, key := range []string{"IsDeviceLocatorServiceEnabled", "DeviceCapacity", "IsActivationLockEnabled"} {
		if slices.Contains(queries, key) {
			t.Fatal("iOS-only query sent to Mac", key)
		}
	}
	if _, err := reportedModel(map[string]any{"ProductName": "Mac16,1"}, "iPad16,6"); err == nil {
		t.Fatal("platform changed within enrollment")
	}
}

func TestMacEnrollmentInventoryBootstrapAndUpdatePolicy(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	testSettings(t, s, 2)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, cert, _ := testEnrollPlatformWithKey(t, s, scope, "Mac", "Mac16,1", "15.0")
	if d.Family() != PlatformMacOS || d.Platform() != "macOS" || d.EnrollmentMethod != "manual_device" || d.EnrollmentPlatform != PlatformMacOS {
		t.Fatal("Mac platform not persisted", d)
	}
	if _, err := s.Device(t.Context(), Scope{TenantID: 2}, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("Mac scope leak", err)
	}
	layout, err := func() (*enrollmentLayout, error) {
		tx, e := s.db.BeginTx(t.Context(), nil)
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		return loadEnrollmentLayout(t.Context(), tx, d.ID)
	}()
	if err != nil || !layout.bootstrapToken {
		t.Fatal("Mac profile did not advertise bootstrap support", layout, err)
	}
	drainMacInventory(t, s, d)
	d, err = s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !d.SupervisedReported || d.AppleSilicon == nil || !*d.AppleSilicon || d.SoftwareUpdateDeviceID != "J313AP" {
		t.Fatal("Mac capability inventory missing", d)
	}
	data, _ := json.Marshal(d)
	if bytes.Contains(data, []byte("never-put-recovery")) {
		t.Fatal("secret copied into public inventory")
	}
	policy := UpdatePolicy{TargetVersion: "15.1", TargetBuild: "24B1", Deadline: "2026-10-01T18:00:00"}
	if err = ValidateUpdatePolicy(*d, policy); err == nil {
		t.Fatal("Apple silicon update accepted without escrow")
	}
	bootstrap := []byte("opaque-bootstrap-authorization-for-this-mac")
	protocol := s.ProtocolHandler(nil)
	request := func(certificate *x509.Certificate, message map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := plist.Marshal(message, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("PUT", "https://mdm.example.test/mdm/apple/"+d.ID+"/checkin", bytes.NewReader(body))
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate}}
		rec := httptest.NewRecorder()
		protocol.ServeHTTP(rec, req)
		return rec
	}
	if rec := request(cert, map[string]any{"MessageType": "SetBootstrapToken", "BootstrapToken": bootstrap}); rec.Code != 200 {
		t.Fatal("bootstrap escrow failed", rec.Code, rec.Body.String())
	}
	var encrypted []byte
	if err = s.db.QueryRow(`SELECT encrypted_token FROM mdm_apple_bootstrap_tokens WHERE device_id=$1`, d.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, bootstrap) {
		t.Fatal("bootstrap stored in plaintext", err)
	}
	rec := request(cert, map[string]any{"MessageType": "GetBootstrapToken"})
	var response map[string]any
	if rec.Code != 200 {
		t.Fatal("bootstrap retrieval failed", rec.Code, rec.Body.String())
	}
	if _, err = plist.Unmarshal(rec.Body.Bytes(), &response); err != nil || !bytes.Equal(response["BootstrapToken"].([]byte), bootstrap) {
		t.Fatal("bootstrap response changed", err)
	}
	for _, key := range []string{"UserID", "EnrollmentID", "EnrollmentUserID", "UserShortName"} {
		if rec := request(cert, map[string]any{"MessageType": "GetBootstrapToken", key: ""}); rec.Code != 401 {
			t.Fatal("user channel retrieved device token", key, rec.Code)
		}
	}
	_, foreignCert, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 2, SiteID: 2}, "Foreign Mac", "Mac16,1", "15.0")
	if rec := request(foreignCert, map[string]any{"MessageType": "GetBootstrapToken"}); rec.Code != 401 {
		t.Fatal("foreign identity retrieved token", rec.Code)
	}
	d, err = s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !d.BootstrapTokenEscrowed || ValidateUpdatePolicy(*d, policy) != nil {
		t.Fatal("ready Mac could not set update", d.Capabilities())
	}
	catalog := SoftwareCatalog{PublicAssetSets: map[string][]OSRelease{"macOS": {{Version: "15.1", Build: "24B1", PostingDate: time.Now().Add(-time.Hour * 24).Format("2006-01-02"), ExpirationDate: time.Now().AddDate(1, 0, 0).Format("2006-01-02"), SupportedDevices: []string{"J313AP"}}}, "iOS": {{Version: "15.1", Build: "wrong", PostingDate: "2020-01-01", ExpirationDate: "2099-01-01", SupportedDevices: []string{"J313AP"}}}}}
	if releases := catalog.DeviceReleases(*d, time.Now()); len(releases) != 1 || releases[0].Build != "24B1" {
		t.Fatal("wrong platform catalog", releases)
	}
	data, _ = json.Marshal(catalog)
	if _, err = s.db.Exec(`UPDATE mdm_apple_software_catalog SET document=$1,fetched_at=now()`, data); err != nil {
		t.Fatal(err)
	}
	if err = s.SetUpdatePolicy(t.Context(), scope, []string{d.ID}, &policy, "test-admin"); err != nil {
		t.Fatal(err)
	}
	if declarations := Declarations(*d, &policy); len(declarations) != 3 {
		t.Fatal("Mac update declaration missing", declarations)
	}
	if rec := request(cert, map[string]any{"MessageType": "SetBootstrapToken"}); rec.Code != 200 {
		t.Fatal("bootstrap clear failed", rec.Code)
	}
	if err = s.ReconcileUpdateAvailability(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored, err := s.UpdatePolicy(t.Context(), scope, d.ID)
	if err != nil || stored.Status != "unavailable" {
		t.Fatal("lost authorization did not withdraw update", stored, err)
	}
	if rec := request(cert, map[string]any{"MessageType": "SetBootstrapToken", "BootstrapToken": bootstrap}); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if err = s.RevokeEnrollment(context.Background(), scope, d.ID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	if rec := request(cert, map[string]any{"MessageType": "GetBootstrapToken"}); rec.Code != 401 {
		t.Fatal("revoked token remained accessible", rec.Code)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_bootstrap_tokens WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("revocation kept bootstrap escrow", err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE details::text LIKE '%opaque-bootstrap%' OR details::text LIKE '%never-put-recovery%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("secrets in audit", err)
	}
}

func drainMacInventory(t *testing.T, s *Store, d *Device) {
	drainMacHardwareInventory(t, s, d, nil)
}

func drainMacHardwareInventory(t *testing.T, s *Store, d *Device, hardware map[string]any) {
	t.Helper()
	message := map[string]any{"UDID": d.UDID, "Status": "Idle"}
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		payload, err := s.Connect(t.Context(), d, message)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) == 0 {
			break
		}
		var wire map[string]any
		if _, err = plist.Unmarshal(payload, &wire); err != nil {
			t.Fatal(err)
		}
		command := wire["Command"].(map[string]any)
		kind := command["RequestType"].(string)
		seen[kind] = true
		message = map[string]any{"UDID": d.UDID, "Status": "Acknowledged", "CommandUUID": wire["CommandUUID"]}
		switch kind {
		case "DeviceInformation":
			message["QueryResponses"] = map[string]any{"ProductName": "Mac16,1", "OSVersion": "15.0", "IsSupervised": true, "IsAppleSilicon": true, "SoftwareUpdateDeviceID": "J313AP"}
			for key, value := range hardware {
				message["QueryResponses"].(map[string]any)[key] = value
			}
		case "SecurityInfo":
			message["SecurityInfo"] = map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true, "IsUserEnrollment": false}, "BootstrapTokenAllowedForAuthentication": "allowed", "BootstrapTokenRequiredForSoftwareUpdate": true, "FDE_PersonalRecoveryKey": "never-put-recovery-keys-in-generic-inventory"}
		case "ProfileList":
			message["ProfileList"] = []any{}
		case "InstalledApplicationList":
			if _, exists := command["ManagedAppsOnly"]; exists {
				t.Fatal("unexpected application filter sent to Mac")
			}
			message["InstalledApplicationList"] = []any{}
		case "AvailableOSUpdates":
			message["AvailableOSUpdates"] = []any{}
		}
	}
	for _, kind := range []string{"DeviceInformation", "SecurityInfo", "DeclarativeManagement", "ProfileList", "InstalledApplicationList"} {
		if !seen[kind] {
			t.Fatal("missing Mac command", kind)
		}
	}
}

func TestMacUpdateAuthorizationBoundaries(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	silicon, intel := true, false
	base := func() Device {
		return Device{ID: "mac", Model: "Mac16,1", OSVersion: "15.0", Status: "enrolled", Supervised: true, SupervisedReported: true, AppleSilicon: &silicon, BootstrapTokenEscrowed: true, SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true, "IsUserEnrollment": false}, "BootstrapTokenAllowedForAuthentication": "allowed", "BootstrapTokenRequiredForSoftwareUpdate": true}}
	}
	p := UpdatePolicy{TargetVersion: "15.1", Deadline: "2026-10-01T18:00:00"}
	for _, tc := range []struct {
		name    string
		change  func(*Device)
		allowed bool
	}{
		{"ready Apple silicon", func(*Device) {}, true},
		{"Intel without escrow", func(d *Device) { d.AppleSilicon = &intel; d.BootstrapTokenEscrowed = false }, true},
		{"unknown architecture", func(d *Device) { d.AppleSilicon = nil }, false},
		{"unreported supervision", func(d *Device) { d.SupervisedReported = false }, false},
		{"unsupervised", func(d *Device) { d.Supervised = false }, false},
		{"old OS", func(d *Device) { d.OSVersion = "13.6" }, false},
		{"missing security", func(d *Device) { d.SecurityAt = nil }, false},
		{"stale security", func(d *Device) { old := now.Add(-24 * time.Hour); d.SecurityAt = &old }, false},
		{"missing approval", func(d *Device) { d.SecurityInventory["ManagementStatus"] = map[string]any{} }, false},
		{"user enrollment", func(d *Device) { d.SecurityInventory["ManagementStatus"].(map[string]any)["IsUserEnrollment"] = true }, false},
		{"bootstrap disallowed", func(d *Device) { d.SecurityInventory["BootstrapTokenAllowedForAuthentication"] = "disallowed" }, false},
		{"no update authorization", func(d *Device) { d.SecurityInventory["BootstrapTokenRequiredForSoftwareUpdate"] = false }, false},
		{"token absent", func(d *Device) { d.BootstrapTokenEscrowed = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base()
			tc.change(&d)
			if got := ValidateUpdatePolicy(d, p) == nil; got != tc.allowed {
				t.Fatal("incorrect authorization", d.Capabilities())
			}
			updates := 0
			for _, declaration := range Declarations(d, &p) {
				if declaration.Type == "com.apple.configuration.softwareupdate.enforcement.specific" {
					updates++
				}
			}
			if (updates == 1) != tc.allowed {
				t.Fatal("unsupported update declaration", updates)
			}
		})
	}
}

func TestMacMinimalEnrollmentLearnsVersionAndRejectsOtherChannels(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, cert, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Minimal Mac", "Mac16,1", "")
	if d.Capabilities().DeclarativeManagement {
		t.Fatal("missing version enabled DDM")
	}
	drainMacInventory(t, s, d)
	d, err := s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Capabilities().DeclarativeManagement || d.AppleSilicon == nil || !d.SupervisedReported {
		t.Fatal("new version did not collect capabilities", d)
	}
	for _, key := range []string{"UserID", "EnrollmentID", "EnrollmentUserID", "UserShortName", "UserLongName", "NotOnConsole"} {
		if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID, "Topic": "com.apple.mgmt.test", key: ""}); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("user check-in accepted", key, err)
		}
		if _, err = s.Connect(t.Context(), d, map[string]any{"UDID": d.UDID, "Status": "Idle", key: ""}); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("user command accepted", key, err)
		}
		if _, err = s.DeclarativeManagement(t.Context(), d, map[string]any{"UDID": d.UDID, "Endpoint": "tokens", key: ""}); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("user DDM accepted", key, err)
		}
	}
	if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "Authenticate", "UDID": d.UDID, "Topic": "com.apple.mgmt.test", "ProductName": "iPhone16,1"}); err == nil {
		t.Fatal("platform changed")
	}
	fresh, err := s.Device(t.Context(), Scope{TenantID: 1}, d.ID)
	if err != nil || fresh.Family() != PlatformMacOS || fresh.Status != "enrolled" {
		t.Fatal("rejected channel mutated enrollment", fresh, err)
	}
	b, err := BuildProfile("Mac Wi-Fi", "eu.example.mac-wifi", "wifi", map[string]any{"SSID_STR": "Office", "EncryptionType": "WPA2", "Password": "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s.SaveProfile(t.Context(), 1, "", 0, b, "admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, desired := range []string{"installed", "removed"} {
		if err = s.AssignProfile(t.Context(), Scope{TenantID: 1, SiteID: 1}, profile.ID, []string{d.ID}, desired, "admin"); err != nil {
			t.Fatal(err)
		}
		var installed []InstalledProfile
		if desired == "installed" {
			installed = []InstalledProfile{{Identifier: profile.Identifier, UUID: profile.UUID, Name: profile.Name, Managed: true}}
		}
		drainCommands(t, s, d, installed)
		assignments, err := s.Assignments(t.Context(), Scope{TenantID: 1}, d.ID)
		if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" || assignments[0].Desired != desired {
			t.Fatal("Mac profile state not verified", assignments, err)
		}
	}
	status := []byte(`{"StatusItems":{"softwareupdate":{"device-id":"J515AP"}}}`)
	if _, err = s.DeclarativeManagement(t.Context(), d, map[string]any{"UDID": d.UDID, "Endpoint": "status", "Data": status}); err != nil {
		t.Fatal(err)
	}
	fresh, err = s.Device(t.Context(), Scope{TenantID: 1}, d.ID)
	if err != nil || fresh.SoftwareUpdateDeviceID != "J515AP" {
		t.Fatal("DDM update identifier not persisted", fresh, err)
	}

}

func TestMacBootstrapSurvivesRenewalAndRollsBackFailures(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	testSettings(t, s, 2)
	d, _, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Escrow Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	token := []byte("private-bootstrap-for-renewal")
	get := map[string]any{"MessageType": "GetBootstrapToken"}
	set := map[string]any{"MessageType": "SetBootstrapToken", "BootstrapToken": token}
	if _, err := s.BootstrapToken(t.Context(), d, set); err != nil {
		t.Fatal(err)
	}
	for _, msg := range []map[string]any{
		{"MessageType": "SetBootstrapToken", "BootstrapToken": "not-data"},
		{"MessageType": "SetBootstrapToken", "BootstrapToken": make([]byte, (64<<10)+1)},
		{"MessageType": "GetBootstrapToken", "UDID": false},
		{"MessageType": "GetBootstrapToken", "UDID": ""},
		{"MessageType": "SetBootstrapToken", "BootstrapToken": token, "UDID": "another-mac"},
	} {
		if _, err := s.BootstrapToken(t.Context(), d, msg); err == nil {
			t.Fatal("malformed bootstrap accepted")
		}
	}
	// A failed audit must roll back the secret mutation, including deletion.
	if _, err := s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT test_bootstrap_audit CHECK (action <> 'apple.bootstrap_token.clear')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BootstrapToken(t.Context(), d, map[string]any{"MessageType": "SetBootstrapToken"}); err == nil {
		t.Fatal("clear committed without audit")
	}
	if _, err := s.db.Exec(`ALTER TABLE mdm_apple_audit DROP CONSTRAINT test_bootstrap_audit`); err != nil {
		t.Fatal(err)
	}
	result, err := s.BootstrapToken(t.Context(), d, get)
	if err != nil || !bytes.Equal(result["BootstrapToken"].([]byte), token) {
		t.Fatal("failed clear destroyed token", err)
	}
	testIdentityDue(t, s, d)
	if err = s.ScheduleIdentityRenewals(t.Context()); err != nil {
		t.Fatal(err)
	}
	r := testIdentityGeneration(t, s, d)
	profile := testIdentityDelivery(t, s, d, r)
	var root map[string]any
	if _, err = plist.Unmarshal(profile, &root); err != nil {
		t.Fatal(err)
	}
	advertised := false
	for _, item := range root["PayloadContent"].([]any) {
		p := item.(map[string]any)
		if p["PayloadType"] == "com.apple.mdm" {
			values, _ := p["ServerCapabilities"].([]any)
			for _, v := range values {
				advertised = advertised || v == "com.apple.mdm.bootstraptoken"
			}
		}
	}
	if !advertised {
		t.Fatal("renewal removed bootstrap support")
	}
	a, err := s.scepRenewalAuthority(t.Context(), d.ID, r.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	f, csr := testSCEPDeviceRequest(t, d.ID, testSCEPProfile(t, profile)["Challenge"].(string), a.ca, a.ra)
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := testIdentityIssue(t, s, a, f, request)
	if _, err = s.BootstrapToken(t.Context(), candidate, get); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("candidate read active escrow", err)
	}
	testIdentityToken(t, s, candidate)
	if _, err = s.BootstrapToken(t.Context(), candidate, get); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("staged identity read active escrow", err)
	}
	if _, err = s.Connect(t.Context(), candidate, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BootstrapToken(t.Context(), d, get); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retired identity read active escrow", err)
	}
	result, err = s.BootstrapToken(t.Context(), candidate, get)
	if err != nil || !bytes.Equal(result["BootstrapToken"].([]byte), token) {
		t.Fatal("renewal lost escrow", err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_bootstrap_tokens SET tenant_id=2 WHERE device_id=$1`, d.ID); err == nil {
		t.Fatal("cross-organization escrow relation accepted")
	}
	if err = s.CheckIn(t.Context(), candidate, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID, "Topic": "com.apple.mgmt.test"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_bootstrap_tokens WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("checkout retained secret", err)
	}
}

func TestPlatformMigrationUsesReportedEvidence(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	type fixture struct {
		id, model, inventory string
		family               Platform
		reported, supervised bool
	}
	fixtures := []fixture{
		{model: "Mac16,1", inventory: `{"IsSupervised":false}`, family: PlatformMacOS, reported: true, supervised: false},
		{model: "iPad16,6", inventory: `{"IsSupervised":true}`, family: PlatformIPadOS, reported: true, supervised: true},
		{model: "", inventory: `{"IsSupervised":"true"}`, family: PlatformUnknown, reported: false, supervised: true},
		{model: "AppleTV14,1", inventory: `{}`, family: PlatformUnknown, reported: false, supervised: true},
	}
	for i := range fixtures {
		f := &fixtures[i]
		invite, err := s.Invite(t.Context(), Scope{TenantID: 1, SiteID: 1}, "Legacy inventory", "admin")
		if err != nil {
			t.Fatal(err)
		}
		f.id = invite.DeviceID
		if _, err = s.db.Exec(`UPDATE mdm_apple_devices SET model=$2,inventory=$3,supervised=true WHERE id=$1`, f.id, f.model, []byte(f.inventory)); err != nil {
			t.Fatal(err)
		}
	}
	// Recreate the previous schema only inside this disposable test database.
	if _, err := s.db.Exec(`DROP TABLE mdm_apple_bootstrap_tokens;
	ALTER TABLE mdm_apple_devices DROP COLUMN platform,DROP COLUMN enrollment_method,DROP COLUMN enrollment_platform,DROP COLUMN supervised_reported,DROP COLUMN software_update_device_id,DROP COLUMN apple_silicon,DROP COLUMN security_inventory,DROP COLUMN security_at;
	ALTER TABLE mdm_apple_enrollment_layouts DROP COLUMN bootstrap_token;
	DELETE FROM mdm_apple_migrations WHERE name='migrations/012_platform_capabilities.sql'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal("migration replay", err)
	}
	for _, f := range fixtures {
		d, err := s.Device(t.Context(), Scope{TenantID: 1}, f.id)
		if err != nil || d.Family() != f.family || d.SupervisedReported != f.reported || d.Supervised != f.supervised || d.BootstrapTokenEscrowed {
			t.Fatal("legacy evidence misclassified", f, d, err)
		}
	}
}

func TestMacBootstrapConcurrentRevocation(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Concurrent Mac", "Mac16,1", "15.0")
	start := make(chan struct{})
	results := make(chan error, 13)
	for i := 0; i < 12; i++ {
		go func(i int) {
			<-start
			message := map[string]any{"MessageType": "GetBootstrapToken"}
			if i%2 == 0 {
				message = map[string]any{"MessageType": "SetBootstrapToken", "BootstrapToken": []byte("synthetic-concurrent-token")}
			}
			_, err := s.BootstrapToken(t.Context(), d, message)
			results <- err
		}(i)
	}
	go func() { <-start; results <- s.RevokeEnrollment(t.Context(), scope, d.ID, "admin") }()
	close(start)
	for i := 0; i < 13; i++ {
		if err := <-results; err != nil && !errors.Is(err, ErrUnauthorized) {
			t.Fatal("concurrent escrow failed unexpectedly", err)
		}
	}
	if _, err := s.BootstrapToken(t.Context(), d, map[string]any{"MessageType": "GetBootstrapToken"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revocation did not take effect", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_bootstrap_tokens WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("racing set recreated revoked escrow", err)
	}
}
