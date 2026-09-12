package apple

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

func testFileVaultMac(t *testing.T) (*Store, *Device, Scope) {
	t.Helper()
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "FileVault test", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	return s, d, scope
}

func testFileVaultStep(t *testing.T, s *Store, d *Device, phase, status string, profiles []InstalledProfile) []byte {
	t.Helper()
	var id, actual string
	if err := s.db.QueryRow(`SELECT phase,command_id FROM mdm_apple_filevault_policies WHERE device_id=$1`, d.ID).Scan(&actual, &id); err != nil || actual != phase {
		t.Fatal("unexpected FileVault phase", actual, phase, err)
	}
	payload, err := s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if _, err = plist.Unmarshal(payload, &wire); err != nil || wire["CommandUUID"] != id {
		t.Fatal("wrong FileVault command delivered", err)
	}
	message := map[string]any{"Status": status, "UDID": d.UDID, "CommandUUID": id}
	if wire["Command"].(map[string]any)["RequestType"] == "ProfileList" {
		if profiles == nil {
			profiles = []InstalledProfile{}
		}
		message["ProfileList"] = profiles
	}
	if status == "Error" {
		message["ErrorChain"] = []any{map[string]any{"LocalizedDescription": "PRIVATE-RECOVERY-MATERIAL"}}
	}
	if _, err = s.Connect(t.Context(), d, message); err != nil {
		t.Fatal(err)
	}
	return payload
}

func testFileVaultProfiles(t *testing.T, s *Store, d *Device) []InstalledProfile {
	t.Helper()
	var escrow, enable string
	if err := s.db.QueryRow(`SELECT id,enable_uuid FROM mdm_apple_filevault_escrow WHERE device_id=$1`, d.ID).Scan(&escrow, &enable); err != nil {
		t.Fatal(err)
	}
	return []InstalledProfile{
		{Identifier: fileVaultDomain + "." + d.ID + ".escrow", UUID: escrow, Managed: true, Payloads: []InstalledPayload{{Type: "com.apple.security.FDERecoveryKeyEscrow"}}},
		{Identifier: fileVaultDomain + "." + d.ID + ".enable", UUID: enable, Managed: true, Payloads: []InstalledPayload{{Type: "com.apple.MCX.FileVault2"}}},
	}
}

func testActivateFileVault(t *testing.T, s *Store, d *Device, scope Scope) {
	t.Helper()
	if err := s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal(err)
	}
	testFileVaultStep(t, s, d, "preflight", "Acknowledged", nil)
	testFileVaultStep(t, s, d, "installing_escrow", "Acknowledged", nil)
	profiles := testFileVaultProfiles(t, s, d)
	testFileVaultStep(t, s, d, "verifying_escrow", "Acknowledged", profiles[:1])
	testFileVaultStep(t, s, d, "installing_enable", "Acknowledged", nil)
	testFileVaultStep(t, s, d, "verifying_enable", "Acknowledged", profiles)
}

func testFileVaultSecurity(t *testing.T, s *Store, d *Device, info map[string]any) {
	t.Helper()
	var id string
	err := s.db.QueryRow(`SELECT id FROM mdm_apple_commands WHERE device_id=$1 AND request_type='SecurityInfo' AND status IN ('queued','sent','not_now') ORDER BY created_at LIMIT 1`, d.ID).Scan(&id)
	if err != nil {
		tx, err := s.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		id, err = s.enqueue(t.Context(), tx, d, "SecurityInfo", nil, nil, nil)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "UDID": d.UDID, "CommandUUID": id, "SecurityInfo": info}); err != nil {
		t.Fatal(err)
	}
}

func TestFileVaultStagesEscrowBeforeEncryption(t *testing.T) {
	s, d, scope := testFileVaultMac(t)
	if err := s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal("idempotent request failed", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_filevault_escrow WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate escrow generation", count, err)
	}
	testFileVaultStep(t, s, d, "preflight", "Acknowledged", nil)
	install := testFileVaultStep(t, s, d, "installing_escrow", "Acknowledged", nil)
	if bytes.Contains(install, []byte("com.apple.MCX.FileVault2")) {
		t.Fatal("escrow installation also enabled encryption")
	}
	profiles := testFileVaultProfiles(t, s, d)
	// A successful install with no matching managed profile must not enable FDE.
	testFileVaultStep(t, s, d, "verifying_escrow", "Acknowledged", nil)
	v, err := s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Phase != "failed" || v.Error != "escrow_profile_missing" {
		t.Fatal("missing escrow profile accepted", v, err)
	}
	if err = s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal(err)
	}
	testFileVaultStep(t, s, d, "preflight", "Acknowledged", profiles[:1])
	testFileVaultStep(t, s, d, "installing_escrow", "Acknowledged", nil)
	testFileVaultStep(t, s, d, "verifying_escrow", "Acknowledged", profiles[:1])
	testFileVaultStep(t, s, d, "installing_enable", "Acknowledged", nil)
	testFileVaultStep(t, s, d, "verifying_enable", "Acknowledged", profiles)
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Phase != "active" || v.EscrowedAt != nil || v.VerifiedAt != nil {
		t.Fatal("profiles were confused with key escrow or verification", v, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE filevault AND status='acknowledged' AND octet_length(payload)>0`).Scan(&count); err != nil || count != 0 {
		t.Fatal("completed workflow payload retained", count, err)
	}
}

func TestFileVaultEscrowPrivacyHistoryAndRetention(t *testing.T) {
	s, d, scope := testFileVaultMac(t)
	testActivateFileVault(t, s, d, scope)
	var der []byte
	if err := s.db.QueryRow(`SELECT certificate FROM mdm_apple_filevault_escrow WHERE device_id=$1`, d.ID).Scan(&der); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.IsCA || cert.KeyUsage != x509.KeyUsageKeyEncipherment {
		t.Fatal("escrow certificate has unexpected authority", err)
	}
	key := []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
	report := func(value []byte, deviceKey string) {
		t.Helper()
		testFileVaultSecurity(t, s, d, map[string]any{
			"FDE_Enabled": true, "FDE_HasPersonalRecoveryKey": true,
			"FDE_PersonalRecoveryKeyCMS": value, "FDE_PersonalRecoveryKeyDeviceKey": deviceKey,
			"FDE_PersonalRecoveryKey": string(key),
		})
	}
	report(testFileVaultEnvelope(t, cert, key, fileVaultTripleDESOID, true), d.ID)
	v, err := s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.KeyID == "" || v.EscrowedAt == nil || v.VerifiedAt != nil || v.RecoveryError != "" {
		t.Fatal("key escrow metadata incorrect", v, err)
	}
	first := v.KeyID
	for i := 0; i < 2; i++ {
		report(testFileVaultEnvelope(t, cert, key, fileVaultAES256OID, false), d.ID)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_filevault_keys WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("repeated CMS created duplicate recovery versions", count, err)
	}
	report([]byte("malformed CMS"), d.ID)
	report(testFileVaultEnvelope(t, cert, key, fileVaultAES128OID, false), uuid.NewString())
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.KeyID != first || v.RecoveryError != "invalid_recovery_envelope" {
		t.Fatal("bad envelope destroyed valid escrow", v, err)
	}
	newKey := []byte("GGGG-HHHH-IIII-JJJJ-KKKK-LLLL")
	report(testFileVaultEnvelope(t, cert, newKey, fileVaultAES128OID, false), d.ID)
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.KeyID == first || v.VerifiedAt != nil {
		t.Fatal("new recovery key was not versioned independently", v, err)
	}
	latest := v.KeyID
	// Simulate an older delivered request returning after the newer key report.
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := s.enqueue(t.Context(), tx, d, "SecurityInfo", nil, nil, nil)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE mdm_apple_commands SET created_at=clock_timestamp()-interval '1 day',status='sent' WHERE id=$1`, stale); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "UDID": d.UDID, "CommandUUID": stale, "SecurityInfo": map[string]any{"FDE_PersonalRecoveryKeyCMS": testFileVaultEnvelope(t, cert, key, fileVaultAES128OID, false), "FDE_PersonalRecoveryKeyDeviceKey": d.ID}}); err != nil {
		t.Fatal(err)
	}
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.KeyID != latest {
		t.Fatal("older SecurityInfo rolled back current key", err)
	}
	var encrypted, inventory, auditData []byte
	if err = s.db.QueryRow(`SELECT recovery_key FROM mdm_apple_filevault_keys WHERE id=$1`, first).Scan(&encrypted); err != nil || bytes.Contains(encrypted, key) {
		t.Fatal("recovery key persisted without encryption", err)
	}
	if err = s.db.QueryRow(`SELECT security_inventory::text FROM mdm_apple_devices WHERE id=$1`, d.ID).Scan(&inventory); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT json_agg(a)::text FROM mdm_apple_audit a`).Scan(&auditData); err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(v)
	for _, data := range [][]byte{inventory, auditData, public} {
		if bytes.Contains(data, key) || bytes.Contains(data, newKey) || bytes.Contains(data, []byte("FDE_PersonalRecoveryKeyCMS")) || bytes.Contains(data, []byte("FDE_PersonalRecoveryKeyDeviceKey")) {
			t.Fatal("recovery material escaped its encrypted store")
		}
	}
	for _, other := range []Scope{{TenantID: 2}, {TenantID: 1, SiteID: 2}} {
		if material, err := s.revealFileVaultKey(t.Context(), other, d.ID, first, "admin", nil); err == nil || material != nil {
			t.Fatal("cross-scope recovery disclosure")
		}
	}
	if err = s.RevokeEnrollment(t.Context(), scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.revealFileVaultKey(t.Context(), scope, d.ID, first, "admin", nil)
	if err != nil || !bytes.Equal(recovered, key) {
		t.Fatal("revocation lost the previous recovery key", err)
	}
	clear(recovered)
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Phase != "not_managed" || v.KeyID == "" {
		t.Fatal("revocation lost recovery history", v, err)
	}
	if _, err = s.db.Exec(`DELETE FROM mdm_apple_devices WHERE id=$1`, d.ID); err == nil {
		t.Fatal("device deletion silently deleted recovery keys")
	}
	if _, err = s.db.Exec(`CREATE FUNCTION reject_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.filevault.key.reveal' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_recovery_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_recovery_audit()`); err != nil {
		t.Fatal(err)
	}
	if recovered, err = s.revealFileVaultKey(t.Context(), scope, d.ID, first, "admin", nil); err == nil || recovered != nil {
		t.Fatal("recovery disclosed despite audit failure")
	}
}

func TestFileVaultRemovalKeepsEscrowUntilActivationProfileIsGone(t *testing.T) {
	s, d, scope := testFileVaultMac(t)
	testActivateFileVault(t, s, d, scope)
	testFileVaultSecurity(t, s, d, map[string]any{"FDE_Enabled": true})
	profiles := testFileVaultProfiles(t, s, d)
	if err := s.setFileVault(t.Context(), scope, d.ID, "removed", "admin", nil); err != nil {
		t.Fatal(err)
	}
	testFileVaultStep(t, s, d, "removing_enable", "Acknowledged", nil)
	testFileVaultStep(t, s, d, "verifying_enable_removal", "Acknowledged", profiles)
	v, err := s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Phase != "failed" || v.Error != "profile_still_present" {
		t.Fatal("escrow removal did not wait for activation profile removal", v, err)
	}
	if err = s.setFileVault(t.Context(), scope, d.ID, "removed", "admin", nil); err != nil {
		t.Fatal(err)
	}
	testFileVaultStep(t, s, d, "removing_enable", "Acknowledged", nil)
	testFileVaultStep(t, s, d, "verifying_enable_removal", "Acknowledged", profiles[:1])
	testFileVaultStep(t, s, d, "removing_escrow", "Acknowledged", nil)
	testFileVaultStep(t, s, d, "verifying_removal", "Acknowledged", nil)
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Phase != "removed" {
		t.Fatal("profile removal was not confirmed", v, err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_filevault_escrow WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("profile removal deleted escrow private key", err)
	}
}

func TestFileVaultRejectsCatalogConflictAndRollsBackAuditFailure(t *testing.T) {
	s, d, scope := testFileVaultMac(t)
	raw, err := plist.Marshal(map[string]any{"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": "example.filevault", "PayloadUUID": uuid.NewString(), "PayloadContent": []any{map[string]any{"PayloadType": "com.apple.MCX.FileVault2", "PayloadVersion": 1, "PayloadUUID": uuid.NewString(), "PayloadIdentifier": "example.filevault.settings", "Enable": "On", "Defer": true}}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(t.Context(), 1, "", 0, raw, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, "installed", "admin"); err == nil {
		t.Fatal("catalog replaced workflow-owned FileVault settings")
	}
	if _, err = s.db.Exec(`CREATE FUNCTION reject_filevault_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'apple.filevault.%' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_filevault_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_filevault_audit()`); err != nil {
		t.Fatal(err)
	}
	if err = s.setFileVault(t.Context(), scope, d.ID, "removed", "admin", nil); err == nil {
		t.Fatal("removal ignored failed audit")
	}
	v, err := s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Desired != "enabled" || v.Phase != "preflight" {
		t.Fatal("audit failure changed desired state", v, err)
	}
}

func TestFileVaultConflictsTimeoutAndReceiptIsolation(t *testing.T) {
	s, d, scope := testFileVaultMac(t)
	if err := s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal(err)
	}
	foreign := []InstalledProfile{{Identifier: "other.vendor.escrow", UUID: uuid.NewString(), Managed: true, Payloads: []InstalledPayload{{Type: "com.apple.security.FDERecoveryKeyEscrow"}}}}
	testFileVaultStep(t, s, d, "preflight", "Acknowledged", foreign)
	v, err := s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Error != "conflicting_profile" {
		t.Fatal("foreign escrow profile accepted", v, err)
	}
	if err = s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal(err)
	}
	var old string
	if err = s.db.QueryRow(`SELECT command_id FROM mdm_apple_filevault_policies WHERE device_id=$1`, d.ID).Scan(&old); err != nil {
		t.Fatal(err)
	}
	testFileVaultStep(t, s, d, "preflight", "Error", nil)
	if err = s.RetryCommand(t.Context(), scope, d.ID, old, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("generic command retry accepted FileVault workflow", err)
	}
	commands, err := s.Commands(t.Context(), scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range commands {
		if strings.Contains(c.Error, "PRIVATE-RECOVERY") {
			t.Fatal("device error leaked recovery material")
		}
	}
	if err = s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "CommandUUID": old, "UDID": d.UDID, "ProfileList": []any{}}); err != nil {
		t.Fatal(err)
	}
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Phase != "preflight" {
		t.Fatal("old receipt advanced current policy", v, err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 second' WHERE id=(SELECT command_id FROM mdm_apple_filevault_policies WHERE device_id=$1)`, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID}); err != nil {
		t.Fatal(err)
	}
	v, err = s.FileVault(t.Context(), scope, d.ID)
	if err != nil || v.Phase != "failed" {
		t.Fatal("expired command did not fail policy", v, err)
	}
	if _, err = s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err = s.setFileVault(t.Context(), scope, d.ID, "enabled", "admin", nil); err == nil {
		t.Fatal("changed site ownership allowed FileVault mutation")
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("changed site ownership allowed FileVault delivery", err)
	}
}

func TestFileVaultProfileEvidenceAndEligibility(t *testing.T) {
	escrow, enable := uuid.NewString(), uuid.NewString()
	for _, tc := range []struct {
		name    string
		profile InstalledProfile
	}{
		{"unmanaged", InstalledProfile{Identifier: "escrow", UUID: escrow}},
		{"wrong revision", InstalledProfile{Identifier: "escrow", UUID: uuid.NewString(), Managed: true}},
		{"foreign payload", InstalledProfile{Identifier: "foreign", Payloads: []InstalledPayload{{Type: "com.apple.MCX.FileVault2"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, conflict := fileVaultProfileEvidence([]InstalledProfile{tc.profile}, "escrow", "enable", escrow, enable)
			if !conflict {
				t.Fatal("unsafe profile evidence accepted")
			}
		})
	}
	now := time.Now()
	d := Device{Status: "enrolled", Model: "Mac16,1", OSVersion: "15.0", CertificateExpiresAt: now.Add(time.Hour), InventoryAt: &now, SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true}}}
	if reason := d.FileVaultReason(now); reason != "" {
		t.Fatal(reason)
	}
	d.SecurityAt = nil
	if d.FileVaultReason(now) == "" {
		t.Fatal("missing security evidence accepted")
	}
}

func TestFileVaultRecoveryRechecksPermissionInsideTransaction(t *testing.T) {
	s, d, scope := testFileVaultMac(t)
	if _, err := s.db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY); INSERT INTO users VALUES('admin'),('recovery-admin')`); err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	if err = permissions.ReplaceGrants(t.Context(), "admin", "recovery-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err = s.SetFileVault(t.Context(), scope, d.ID, "enabled", "recovery-admin", permissions); err != nil {
		t.Fatal(err)
	}
	keyID := uuid.NewString()
	key := []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
	encrypted, err := s.secrets.seal(key, secretPurpose(1, d.ID+"/"+keyID, "filevault_recovery_key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO mdm_apple_filevault_keys(id,tenant_id,device_id,escrow_id,recovery_key) SELECT $1,tenant_id,device_id,escrow_id,$3 FROM mdm_apple_filevault_policies WHERE device_id=$2`, keyID, d.ID, encrypted); err != nil {
		t.Fatal(err)
	}
	if material, err := s.RevealFileVaultKey(t.Context(), scope, d.ID, keyID, "recovery-admin", nil); err == nil || material != nil {
		t.Fatal("missing permission store allowed disclosure")
	}
	material, err := s.RevealFileVaultKey(t.Context(), scope, d.ID, keyID, "recovery-admin", permissions)
	if err != nil || !bytes.Equal(material, key) {
		t.Fatal("authorized recovery failed", err)
	}
	clear(material)
	change, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer change.Rollback()
	if _, err = change.Exec(`SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		material, err := s.RevealFileVaultKey(t.Context(), scope, d.ID, keyID, "recovery-admin", permissions)
		if material != nil {
			clear(material)
			done <- errors.New("revoked permission returned recovery material")
			return
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatal("recovery bypassed permission change lock", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err = change.Exec(`DELETE FROM uem_access_grants WHERE user_id='recovery-admin'`); err != nil {
		t.Fatal(err)
	}
	if err = change.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, access.ErrDenied) {
			t.Fatal("recovery did not observe permission revocation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not finish after permission change")
	}
}
