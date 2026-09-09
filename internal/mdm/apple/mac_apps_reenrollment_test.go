package apple

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// Enrollments and protocol responses are synthetic; no installer is executed.
func macAppRetireDispatched(t *testing.T, s *Store, d *Device, v *SoftwareVersion) string {
	t.Helper()
	if err := s.installMacApp(t.Context(), Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	if wire := adeConnect(t, s, d, "Idle", "", nil); wire == nil || wire["Command"].(map[string]any)["RequestType"] != "InstallEnterpriseApplication" {
		t.Fatal("synthetic installation not dispatched")
	}
	a := macAppState(t, s, d)
	if err := s.CheckIn(t.Context(), d, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID}); err != nil {
		t.Fatal(err)
	}
	return a.AttemptID
}

func TestMacAppReenrollmentRequiresExplicitImmutableStoppingEvidence(t *testing.T) {
	s, old, v := macAppFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	attempt := macAppRetireDispatched(t, s, old, v)
	current, _, _ := testEnrollPlatformWithKey(t, s, scope, "Reenrolled Mac", "Mac16,1", "15.0", old.UDID)
	drainMacInventory(t, s, current)
	// Case-folding also covers legacy rows whose spelling changed.
	adeExec(t, s, `UPDATE mdm_apple_devices SET udid=upper(udid),site_id=2,name='Earlier <Site>' WHERE id=$1`, old.ID)
	if err := s.installMacApp(t.Context(), scope, current.ID, v.ID, "admin", MacAppInstallOptions{}, nil); !errors.Is(err, ErrMacAppPriorEnrollment) {
		t.Fatal("reenrollment replayed an unknown installer", err)
	}
	if items, _, err := s.MacApps(t.Context(), scope, current.ID, ""); err != nil || len(items) != 0 {
		t.Fatal("blocked install retained a partial assignment", err)
	}
	if risk, err := s.MacAppEnrollmentRisk(t.Context(), scope, current.ID); err != nil || !risk.Unresolved || risk.ActiveIdentity {
		t.Fatal("missing earlier enrollment risk", risk, err)
	}
	if _, _, _, _, err := s.MacAppPriorAttempts(t.Context(), scope, current.ID, "", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("unauthorized history disclosed earlier site", err)
	}
	if err := s.RecordMacAppStoppingEvidence(t.Context(), scope, current.ID, attempt, "installer_stopped", "Synthetic stopping evidence", "admin", nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing transaction authority accepted", err)
	}
	for _, foreign := range []Scope{{TenantID: 2}, {TenantID: 1, SiteID: 2}} {
		if err := s.recordMacAppStoppingEvidence(t.Context(), foreign, current.ID, attempt, "installer_stopped", "Synthetic stopping evidence", "admin", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal("evidence crossed current device scope", err)
		}
	}
	for _, evidence := range []string{"", "rebooted", "unenrolled"} {
		if err := s.recordMacAppStoppingEvidence(t.Context(), scope, current.ID, attempt, evidence, "Synthetic evidence", "admin", nil); !errors.Is(err, ErrMacApp) {
			t.Fatal("insufficient evidence accepted", err)
		}
	}
	if err := s.recordMacAppStoppingEvidence(t.Context(), scope, current.ID, attempt, "installer_stopped", strings.Repeat("x", 1001), "admin", nil); !errors.Is(err, ErrMacApp) {
		t.Fatal("oversized evidence accepted", err)
	}
	if err := s.recordMacAppStoppingEvidence(t.Context(), scope, current.ID, uuid.NewString(), "installer_stopped", "Synthetic evidence", "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign attempt accepted", err)
	}
	_, risk, history, next, err := s.macAppPriorAttempts(t.Context(), scope, current.ID, "", nil)
	if err != nil || !risk.Unresolved || next != "" || len(history) != 1 || history[0].ID != attempt || !history[0].CanRecordEvidence() {
		t.Fatal("cross-site history lost unresolved attempt", err)
	}
	if err = s.recordMacAppStoppingEvidence(t.Context(), scope, current.ID, attempt, "installer_stopped", "Synthetic inspection confirmed the earlier process stopped.", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.recordMacAppStoppingEvidence(t.Context(), scope, current.ID, attempt, "device_erased", "Repeated receipt", "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("duplicate receipt accepted", err)
	}
	_, risk, history, _, err = s.macAppPriorAttempts(t.Context(), scope, current.ID, "", nil)
	if err != nil || risk.Blocked() || len(history) != 1 || history[0].Recovery == nil || history[0].Status != "uncertain" || history[0].CanRecordEvidence() {
		t.Fatal("receipt rewrote history or failed to unblock", err)
	}
	for _, query := range []string{`UPDATE mdm_apple_app_recoveries SET reason='Changed' WHERE attempt_id=$1`, `DELETE FROM mdm_apple_app_recoveries WHERE attempt_id=$1`} {
		if _, err = s.db.Exec(query, attempt); err == nil {
			t.Fatal("stopping evidence was mutable")
		}
	}
	var auditSite int
	if err = s.db.QueryRow(`SELECT (details->>'site_id')::int FROM mdm_apple_audit WHERE action='apple.software.reenrollment.resolve' AND resource_id=$1`, history[0].Recovery.ID).Scan(&auditSite); err != nil || auditSite != 1 {
		t.Fatal("receipt audit lost current device site", err)
	}
	if err = s.installMacApp(t.Context(), scope, current.ID, v.ID, "admin", MacAppInstallOptions{}, nil); err != nil {
		t.Fatal("explicit evidence did not allow a fresh request", err)
	}
	if wire := adeConnect(t, s, current, "Idle", "", nil); wire == nil {
		t.Fatal("fresh operation was not delivered")
	}
	if err = s.CheckIn(t.Context(), current, map[string]any{"MessageType": "CheckOut", "UDID": current.UDID}); err != nil {
		t.Fatal(err)
	}
	third, _, _ := testEnrollPlatformWithKey(t, s, scope, "Third enrollment", "Mac16,1", "15.0", current.UDID)
	drainMacInventory(t, s, third)
	if err = s.installMacApp(t.Context(), scope, third.ID, v.ID, "admin", MacAppInstallOptions{}, nil); !errors.Is(err, ErrMacAppPriorEnrollment) {
		t.Fatal("old receipt authorized a later unknown operation", err)
	}
	_, _, history, next, err = s.macAppPriorAttempts(t.Context(), scope, third.ID, "", nil)
	if err != nil || len(history) != 2 || next != "" {
		t.Fatal("reenrollment history lost old receipt", err)
	}
	_, _, older, _, err := s.macAppPriorAttempts(t.Context(), scope, third.ID, history[0].ID, nil)
	if err != nil || len(older) != 1 || older[0].ID != attempt {
		t.Fatal("history cursor repeated or skipped attempt", err)
	}
}

func TestMacAppReenrollmentDeliveryGuardAndAtomicEvidence(t *testing.T) {
	s, d, v := macAppFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	if err := s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	// A legacy case-variant identity appears after this operation was queued.
	other := uuid.NewString()
	adeExec(t, s, `INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,udid,model,os_version,enrollment_method,enrollment_platform,invite_expires_at) VALUES($1,1,2,'Legacy duplicate','enrolled',upper($2),'Mac16,1','15.0','manual_device','macos',clock_timestamp()+interval '1 hour')`, other, d.UDID)
	if wire := adeConnect(t, s, d, "Idle", "", nil); wire != nil {
		t.Fatal("duplicate identity escaped delivery guard")
	}
	if a := macAppState(t, s, d); a.Status != "cancelled" || a.Error != "previous_enrollment_unresolved" {
		t.Fatal("delivery cancellation did not preserve reason")
	}
	if err := s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); !errors.Is(err, ErrMacAppPriorEnrollment) {
		t.Fatal("active duplicate permitted request", err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET status='revoked' WHERE id=$1`, other)
	// Create an unknown historical operation entirely in the synthetic fixture.
	assignment, attempt := uuid.NewString(), uuid.NewString()
	adeExec(t, s, `INSERT INTO mdm_apple_app_assignments(id,tenant_id,device_id,package_id,version_id,desired,status) VALUES($1,1,$2,$3,$4,'present','not_managed')`, assignment, other, v.PackageID, v.ID)
	adeExec(t, s, `INSERT INTO mdm_apple_app_attempts(id,tenant_id,device_id,package_id,assignment_id,version_id,operation,options,status,requested_by,dispatched_at) VALUES($1,1,$2,$3,$4,$5,'install','{}','uncertain','admin',clock_timestamp())`, attempt, other, v.PackageID, assignment, v.ID)
	adeExec(t, s, `CREATE FUNCTION reject_reenrollment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.software.reenrollment.resolve' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_reenrollment_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_reenrollment_audit()`)
	if err := s.recordMacAppStoppingEvidence(t.Context(), scope, d.ID, attempt, "device_erased", "Synthetic erased fixture", "admin", nil); err == nil {
		t.Fatal("audit failure committed evidence")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_app_recoveries`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed audit retained receipt", err)
	}
	adeExec(t, s, `DROP TRIGGER reject_reenrollment_audit ON mdm_apple_audit`)
	deny := func(context.Context, *sql.Tx) error { return access.ErrDenied }
	if err := s.recordMacAppStoppingEvidence(t.Context(), scope, d.ID, attempt, "device_erased", "Synthetic erased fixture", "admin", deny); !errors.Is(err, access.ErrDenied) {
		t.Fatal("transaction permission bypass", err)
	}
	if err := s.recordMacAppStoppingEvidence(t.Context(), scope, d.ID, attempt, "device_erased", "Synthetic erased fixture", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.installMacApp(t.Context(), scope, d.ID, v.ID, "admin", MacAppInstallOptions{}, nil); err != nil {
		t.Fatal("fresh request remained blocked", err)
	}
}

func TestADERequiredApplicationWaitsForPriorEnrollmentStoppingEvidence(t *testing.T) {
	s, d, v, _ := adeAppFixture(t)
	old, assignment, attempt := uuid.NewString(), uuid.NewString(), uuid.NewString()
	adeExec(t, s, `INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,status,udid,model,os_version,enrollment_method,enrollment_platform,invite_expires_at) VALUES($1,1,2,'Prior ADE Mac','unenrolled',upper($2),'Mac16,1','15.0','manual_device','macos',clock_timestamp())`, old, d.UDID)
	adeExec(t, s, `INSERT INTO mdm_apple_app_assignments(id,tenant_id,device_id,package_id,version_id,desired,status) VALUES($1,1,$2,$3,$4,'present','not_managed')`, assignment, old, v.PackageID, v.ID)
	adeExec(t, s, `INSERT INTO mdm_apple_app_attempts(id,tenant_id,device_id,package_id,assignment_id,version_id,operation,options,status,requested_by,dispatched_at) VALUES($1,1,$2,$3,$4,$5,'install','{}','uncertain','admin',clock_timestamp())`, attempt, old, v.PackageID, assignment, v.ID)
	adeSetupReady(t, s, d)
	r := adeRequiredApp(t, s, d)
	if r.Error != "previous_enrollment_unresolved" || r.Assignment != nil || adeSetupCommand(t, s, d) != "" {
		t.Fatal("ADE replayed an earlier unknown operation or retained partial assignment", r.Error)
	}
	if err := s.recordMacAppStoppingEvidence(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, attempt, "installer_stopped", "Synthetic prior operation stopped", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if adeSetupCommand(t, s, d) != "" {
		t.Fatal("receipt itself released Setup Assistant")
	}
	if err := s.ReconcileADESetups(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r = adeRequiredApp(t, s, d); r.Assignment == nil || r.Assignment.Status != "queued" || adeSetupCommand(t, s, d) != "" {
		t.Fatal("ADE prerequisite did not resume safely")
	}
	wire := adeConnect(t, s, d, "Idle", "", nil)
	if wire == nil || wire["Command"].(map[string]any)["RequestType"] != "InstallEnterpriseApplication" {
		t.Fatal("resumed ADE install not delivered")
	}
	wire = adeConnect(t, s, d, "Acknowledged", wire["CommandUUID"].(string), nil)
	if wire = adeAppReports(t, s, d, wire, "42.0"); wire == nil || wire["Command"].(map[string]any)["RequestType"] != "DeviceConfigured" {
		t.Fatal("verified resumed app did not release Setup Assistant")
	}
}
