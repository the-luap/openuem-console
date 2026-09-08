package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"howett.net/plist"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "apple_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		if err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	s, err := NewStore(db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	s.pushTrust = testPushTrust(t)
	// Most database tests isolate persistence from networking. Dedicated APNs
	// tests use real loopback TLS/HTTP2 peers and test the replacement gate.
	s.checkPushConnection = func(ctx context.Context, _ *Settings) error { return ctx.Err() }
	// Minimal upstream scope tables; the console integration test separately
	// exercises migrations against the real Ent schema.
	if _, err = db.Exec(`CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT NOT NULL REFERENCES tenants(id)); INSERT INTO tenants VALUES(1),(2); INSERT INTO sites VALUES(1,1),(2,2)`); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal("migration is not idempotent", err)
	}
	catalog, _ := json.Marshal(SoftwareCatalog{PublicAssetSets: map[string][]OSRelease{"iOS": {{Version: "18.7.1", Build: "22H100", PostingDate: time.Now().AddDate(0, -1, 0).Format("2006-01-02"), ExpirationDate: time.Now().AddDate(1, 0, 0).Format("2006-01-02"), SupportedDevices: []string{"iPhone16,1"}}}}})
	if _, err = s.db.Exec(`UPDATE mdm_apple_software_catalog SET document=$1,fetched_at=now(),attempted_at=now()`, catalog); err != nil {
		t.Fatal(err)
	}
	return s
}

func testSettings(t *testing.T, s *Store, tenant int) *Settings {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := certificateSerial()
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Test APNs", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "com.apple.mgmt.test"}}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: testProductionPushExtensions()}
	issuer, issuerKey := testPushCA(t)
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c := Settings{TenantID: tenant, PublicURL: "https://mdm.example.test", Organization: "Test organization", PushCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PushKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
	if err = s.Configure(context.Background(), c, "test-admin"); err != nil {
		t.Fatal(err)
	}
	result, err := s.Settings(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testEnroll(t *testing.T, s *Store, scope Scope, name string, existingUDID ...string) (*Device, *x509.Certificate) {
	t.Helper()
	ctx := context.Background()
	invite, err := s.Invite(ctx, scope, name, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	profile, err := s.EnrollmentProfile(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnrollmentProfile(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatal("invitation reused", err)
	}
	_, cert := testSCEPEnrollProfile(t, s, invite.DeviceID, profile)
	d, err := s.AuthenticateCertificate(ctx, invite.DeviceID, cert)
	if err != nil {
		t.Fatal(err)
	}
	udid := uuid.NewString()
	if len(existingUDID) > 0 {
		udid = existingUDID[0]
	}
	if err = s.CheckIn(ctx, d, map[string]any{"MessageType": "Authenticate", "UDID": udid, "Topic": "com.apple.mgmt.test", "ProductName": "iPhone16,1", "OSVersion": "18.6", "SerialNumber": "TEST-" + name}); err != nil {
		t.Fatal(err)
	}
	d, err = s.AuthenticateCertificate(ctx, invite.DeviceID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckIn(ctx, d, map[string]any{"MessageType": "TokenUpdate", "UDID": udid, "Topic": "com.apple.mgmt.test", "Token": []byte("test-apns-token"), "PushMagic": "magic"}); err != nil {
		t.Fatal(err)
	}
	d, err = s.Device(ctx, scope, invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	return d, cert
}

func TestNativeEnrollmentInventoryProfilesAndDDM(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	testSettings(t, s, 1)
	testSettings(t, s, 2)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, cert := testEnroll(t, s, scope, "Phone")
	foreign, foreignCert := testEnroll(t, s, Scope{TenantID: 2, SiteID: 2}, "Other")
	if _, err := s.AuthenticateCertificate(ctx, d.ID, foreignCert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign device certificate accepted", err)
	}
	if _, err := s.Device(ctx, Scope{TenantID: 2}, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant device disclosure", err)
	}
	if _, err := s.Device(ctx, Scope{TenantID: 1, SiteID: 2}, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-site device disclosure", err)
	}
	if err := s.CheckIn(ctx, d, map[string]any{"MessageType": "TokenUpdate", "UDID": foreign.UDID, "Topic": "com.apple.mgmt.test", "Token": []byte("stolen"), "PushMagic": "bad"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("device identity rebound", err)
	}

	drainCommands(t, s, d, nil)
	d, err := s.Device(ctx, scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.OSVersion != "18.6.2" || d.BuildVersion != "22G100" || !d.Supervised || len(d.Apps) != 1 || d.Apps[0].Identifier != "com.example.test" {
		t.Fatalf("incorrect inventory: %+v", d)
	}
	b, err := BuildProfile("Passcode", "test.passcode", "passcode", map[string]any{"minLength": 6})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(ctx, 1, "", 0, b, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(ctx, scope, p.ID, []string{d.ID, foreign.ID}, "installed", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant profile assignment accepted", err)
	}
	assignments, err := s.Assignments(ctx, scope, d.ID)
	if err != nil || len(assignments) != 0 {
		t.Fatal("failed bulk assignment was not atomic", err)
	}
	if err = s.AssignProfile(ctx, scope, p.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Name: p.Name, Managed: true}})
	assignments, err = s.Assignments(ctx, scope, d.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" {
		t.Fatal("profile not verified", assignments, err)
	}
	p2, err := s.SaveProfile(ctx, 1, p.ID, 1, b, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveProfile(ctx, 1, p.ID, 1, b, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale profile edit accepted", err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: p.Identifier, UUID: p.UUID, Managed: true}})
	assignments, err = s.Assignments(ctx, scope, d.ID)
	if err != nil || assignments[0].Status != "missing" {
		t.Fatal("old profile UUID verified as new revision", assignments, err)
	}
	if err = s.AssignProfile(ctx, scope, p.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{{Identifier: p2.Identifier, UUID: p2.UUID, Managed: true}})
	if err = s.DeleteProfile(ctx, 1, p.ID, "admin"); err == nil {
		t.Fatal("installed profile deleted without removal")
	}
	if err = s.AssignProfile(ctx, scope, p.ID, []string{d.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, []InstalledProfile{})
	if err = s.DeleteProfile(ctx, 1, p.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	d, err = s.Device(ctx, scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	policy := &UpdatePolicy{TargetVersion: "18.7.1", Deadline: "2026-10-01T18:00:00"}
	if err = s.SetUpdatePolicy(ctx, scope, []string{d.ID}, policy, "admin"); err != nil {
		t.Fatal(err)
	}
	response, err := s.DeclarativeManagement(ctx, d, map[string]any{"UDID": d.UDID, "Endpoint": "declaration-items"})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.(DeclarationManifest).Declarations.Configurations) != 2 {
		t.Fatal("missing DDM configuration")
	}
	if err = s.CheckIn(ctx, d, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthenticateCertificate(ctx, d.ID, cert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unenrolled certificate remains authorized", err)
	}
	reenrolled, _ := testEnroll(t, s, scope, "Reenrolled", d.UDID)
	if reenrolled.ID == d.ID || reenrolled.UDID != d.UDID {
		t.Fatal("re-enrollment did not issue a new identity")
	}
}

func TestDeferredCommandsAndObsoleteProfileRetries(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	ctx := context.Background()
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _ := testEnroll(t, s, scope, "Deferred")
	payload, err := s.Connect(ctx, d, map[string]any{"UDID": d.UDID, "Status": "Idle"})
	if err != nil {
		t.Fatal(err)
	}
	var command map[string]any
	if _, err = plist.Unmarshal(payload, &command); err != nil {
		t.Fatal(err)
	}
	id := command["CommandUUID"].(string)
	response, err := s.Connect(ctx, d, map[string]any{"UDID": d.UDID, "Status": "NotNow", "CommandUUID": id})
	if err != nil || len(response) != 0 {
		t.Fatal("NotNow must finish the current exchange", err)
	}
	var status string
	if err = s.db.QueryRow(`SELECT status FROM mdm_apple_commands WHERE id=$1`, id).Scan(&status); err != nil || status != "not_now" {
		t.Fatal("deferred command lost", status, err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_commands SET available_at=now()-interval '1 minute' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, s, d, nil)
	b, err := BuildProfile("Passcode", "test.obsolete", "passcode", map[string]any{"minLength": 6})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(ctx, 1, "", 0, b, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(ctx, scope, p.ID, []string{d.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`UPDATE mdm_apple_commands SET status='failed' WHERE profile_id=$1 AND device_id=$2 RETURNING id`, p.ID, d.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(ctx, scope, p.ID, []string{d.ID}, "removed", "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.RetryCommand(ctx, scope, d.ID, id, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("obsolete installation could undo a newer removal", err)
	}
	drainCommands(t, s, d, nil)
	if err = s.DeleteProfile(ctx, scope.TenantID, p.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.RetryCommand(ctx, scope, d.ID, id, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("deleted profile could be redeployed from command history", err)
	}
}

func TestMaintenanceAndEnrollmentRevocation(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	ctx := context.Background()
	scope := Scope{TenantID: 1, SiteID: 1}
	d, cert := testEnroll(t, s, scope, "Maintenance")
	if _, err := s.Invite(ctx, Scope{TenantID: 1, SiteID: 2}, "Wrong organization", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("invitation accepted a site from another organization", err)
	}
	drainCommands(t, s, d, nil)
	if err := s.ScheduleInventory(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND status='queued'`, d.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("enrollment inventory was immediately duplicated", count, err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_devices SET next_inventory_at=now()-interval '1 minute' WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND status='queued'`, d.ID).Scan(&count); err != nil || count != 4 {
		t.Fatal("scheduled inventory missing or duplicated", count, err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_commands SET expires_at=now()-interval '1 minute' WHERE device_id=$1 AND status='queued'`, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.expireCommands(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND status='expired'`, d.ID).Scan(&count); err != nil || count != 4 {
		t.Fatal("expired commands remained queued", count, err)
	}
	if err := s.ScheduleInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND status='queued'`, d.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("inventory cursor did not prevent repeated scheduling", count, err)
	}
	if err := s.RevokeEnrollment(ctx, Scope{TenantID: 2}, d.ID, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant revocation accepted", err)
	}
	if err := s.RevokeEnrollment(ctx, scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateCertificate(ctx, d.ID, cert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked identity accepted", err)
	}
	if _, err := s.Connect(ctx, d, map[string]any{"UDID": d.UDID, "Status": "Idle"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("request authenticated before revocation still executed", err)
	}
	testEnroll(t, s, scope, "Reenrolled", d.UDID)
	invite, err := s.Invite(ctx, scope, "Cancelled invitation", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeEnrollment(ctx, scope, invite.DeviceID, "admin"); err != nil {
		t.Fatal(err)
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	if _, err = s.EnrollmentProfile(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked invitation still downloadable", err)
	}
	if inUse, err := s.ScopeInUse(ctx, scope); err != nil || !inUse {
		t.Fatal("site containing devices can be deleted", err)
	}
	if _, err := s.db.Exec(`DELETE FROM sites WHERE id=1`); err == nil {
		t.Fatal("database allowed orphaning native devices")
	}
	if _, err := s.db.Exec(`DELETE FROM tenants WHERE id=1`); err == nil {
		t.Fatal("database allowed orphaning Apple settings")
	}
}

func TestUpdateStatusAndUnavailableReleaseReconciliation(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	ctx := context.Background()
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _ := testEnroll(t, s, scope, "Updates")
	drainCommands(t, s, d, nil)
	d, err := s.Device(ctx, scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	p := &UpdatePolicy{TargetVersion: "18.7.1", Deadline: "2026-10-01T18:00:00"}
	if err = s.SetUpdatePolicy(ctx, scope, []string{d.ID}, p, "admin"); err != nil {
		t.Fatal(err)
	}
	bad := *p
	bad.TargetVersion = "99.0"
	if err = s.SetUpdatePolicy(ctx, scope, []string{d.ID}, &bad, "admin"); err == nil {
		t.Fatal("unknown release accepted")
	}
	if err = s.saveStatus(ctx, d, &StatusReport{StatusItems: map[string]any{"softwareupdate": map[string]any{"failure-reason": map[string]any{"count": float64(0)}}}}); err != nil {
		t.Fatal(err)
	}
	p, err = s.UpdatePolicy(ctx, scope, d.ID)
	if err != nil || p.Status == "failed" {
		t.Fatal("zero failures interpreted as a failed update", p, err)
	}
	var declaration Declaration
	for _, candidate := range Declarations(*d, p) {
		if strings.HasSuffix(candidate.Identifier, ".update") {
			declaration = candidate
		}
	}
	report := &StatusReport{StatusItems: map[string]any{"management": map[string]any{"declarations": map[string]any{"configurations": []any{map[string]any{"identifier": declaration.Identifier, "server-token": declaration.ServerToken, "active": true, "valid": "valid"}}}}}}
	if err = s.saveStatus(ctx, d, report); err != nil {
		t.Fatal(err)
	}
	p, err = s.UpdatePolicy(ctx, scope, d.ID)
	if err != nil || p.Status != "enforced" {
		t.Fatal("active declaration not recorded", p, err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_software_catalog SET document='{"PublicAssetSets":{"iOS":[]}}'::jsonb`); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileUpdateAvailability(ctx); err != nil {
		t.Fatal(err)
	}
	p, err = s.UpdatePolicy(ctx, scope, d.ID)
	if err != nil || p.Status != "unavailable" {
		t.Fatal("withdrawn Apple release remained active", p, err)
	}
	if len(Declarations(*d, p)) != 2 {
		t.Fatal("unavailable update declaration still served")
	}
}

func drainCommands(t *testing.T, s *Store, d *Device, profiles []InstalledProfile) {
	t.Helper()
	message := map[string]any{"UDID": d.UDID, "Status": "Idle"}
	for i := 0; i < 25; i++ {
		payload, err := s.Connect(context.Background(), d, message)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) == 0 {
			return
		}
		var command map[string]any
		if _, err = plist.Unmarshal(payload, &command); err != nil {
			t.Fatal(err)
		}
		kind := command["Command"].(map[string]any)["RequestType"].(string)
		message = map[string]any{"UDID": d.UDID, "Status": "Acknowledged", "CommandUUID": command["CommandUUID"]}
		switch kind {
		case "DeviceInformation":
			message["QueryResponses"] = map[string]any{"DeviceName": "Test Phone", "OSVersion": "18.6.2", "BuildVersion": "22G100", "ProductName": "iPhone16,1", "IsSupervised": true}
		case "InstalledApplicationList":
			message["InstalledApplicationList"] = []map[string]any{{"Identifier": "com.example.test", "Name": "Test app", "Version": "42", "ShortVersion": "1.2"}}
		case "ProfileList":
			if profiles == nil {
				profiles = []InstalledProfile{}
			}
			var values any
			b, err := plist.Marshal(profiles, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = plist.Unmarshal(b, &values); err != nil {
				t.Fatal(err)
			}
			message["ProfileList"] = values
		case "AvailableOSUpdates":
			message["AvailableOSUpdates"] = []any{}
		}
	}
	t.Fatal("command queue failed to drain")
}
