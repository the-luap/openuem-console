package apple

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

func TestEnrollmentDeviceLockRightsAreExact(t *testing.T) {
	for _, rights := range []int64{0, 1, 4, 8, 7955, 7959, 7963, 8191, -1} {
		l := newEnrollmentLayout(&Settings{PublicURL: "https://mdm.example.test", Topic: "com.apple.mgmt.test"})
		l.accessRights = rights
		if (l.validate() == nil) != (rights == 7955 || rights == 7959) {
			t.Fatal("unexpected enrollment rights", rights)
		}
	}
}

func TestEnrollmentDeviceLockRequiresExplicitMacClaim(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	if _, err := s.InviteWithOptions(t.Context(), scope, "Denied", "admin", EnrollmentOptions{AllowMacDeviceLock: true}, nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing permissions accepted", err)
	}
	invite, err := s.invite(t.Context(), scope, "Mac with lock rights", "admin", EnrollmentOptions{AllowMacDeviceLock: true}, nil)
	if err != nil || !invite.DeviceLockAllowed {
		t.Fatal("invitation option missing", err)
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	for _, platform := range []Platform{"", PlatformIOS, PlatformIPadOS} {
		if _, err = s.issueEnrollmentProfile(t.Context(), token, "", platform); !errors.Is(err, ErrConflict) {
			t.Fatal("non-Mac lock rights accepted", platform, err)
		}
	}
	if _, err = s.EnrollmentProfile(t.Context(), token); !errors.Is(err, ErrConflict) {
		t.Fatal("legacy claim implicitly granted Mac lock rights", err)
	}
	var pending bool
	var count int
	if err = s.db.QueryRow(`SELECT status='pending' AND invite_hash IS NOT NULL FROM mdm_apple_devices WHERE id=$1`, invite.DeviceID).Scan(&pending); err != nil || !pending {
		t.Fatal("rejected claim consumed invitation", err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_scep_enrollments WHERE device_id=$1`, invite.DeviceID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected claim created a SCEP authorization", err)
	}
	profile, err := s.issueEnrollmentProfile(t.Context(), token, "", PlatformMacOS)
	if err != nil {
		t.Fatal(err)
	}
	if got := testEnrollmentMDMPayload(t, profile)["AccessRights"]; numberValue(got) != 7959 {
		t.Fatal("wrong lock rights in initial profile", got)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE resource_id=$1 AND action='apple.enrollment.device_lock.allow'`, invite.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("explicit rights choice was not audited once", count, err)
	}
	for _, statement := range []string{
		`UPDATE mdm_apple_devices SET device_lock_allowed=false WHERE id=$1`,
		`UPDATE mdm_apple_enrollment_layouts SET access_rights=7955 WHERE device_id=$1`,
		`UPDATE mdm_apple_enrollment_layouts SET access_rights=7963 WHERE device_id=$1`,
	} {
		if _, err = s.db.Exec(statement, invite.DeviceID); err == nil {
			t.Fatal("immutable rights changed", statement)
		}
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("migration replay", err)
	}
}

func testEnrollmentMDMPayload(t *testing.T, profile []byte) map[string]any {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(profile, &root); err != nil {
		t.Fatal(err)
	}
	for _, value := range root["PayloadContent"].([]any) {
		payload := value.(map[string]any)
		if payload["PayloadType"] == "com.apple.mdm" {
			return payload
		}
	}
	t.Fatal("missing MDM payload")
	return nil
}

func TestEnrollmentDeviceLockSurvivesRenewalAndLayoutRecovery(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	for _, allowed := range []bool{false, true} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			d, _, _ := testEnrollOptionsWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, fmt.Sprintf("Mac lock rights %t", allowed), "Mac16,1", "15.0", EnrollmentOptions{AllowMacDeviceLock: allowed})
			if d.DeviceLockAllowed != allowed {
				t.Fatal("device metadata lost invitation choice")
			}
			drainMacInventory(t, s, d)
			load := func() *enrollmentLayout {
				t.Helper()
				tx, err := s.db.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				l, err := loadEnrollmentLayout(t.Context(), tx, d.ID)
				if err != nil {
					t.Fatal(err)
				}
				return l
			}
			old := load()
			if old.accessRights != enrollmentRights(allowed) {
				t.Fatal("initial layout rights differ")
			}
			if _, err := s.db.Exec(`UPDATE mdm_apple_devices SET device_lock_allowed=$2 WHERE id=$1`, d.ID, !allowed); err == nil {
				t.Fatal("existing enrollment rights changed")
			}
			testIdentityDue(t, s, d)
			if err := s.ScheduleIdentityRenewals(t.Context()); err != nil {
				t.Fatal(err)
			}
			r := testIdentityGeneration(t, s, d)
			profile := testIdentityDelivery(t, s, d, r)
			mdm := testEnrollmentMDMPayload(t, profile)
			if numberValue(mdm["AccessRights"]) != uint64(old.accessRights) || mdm["PayloadUUID"] != old.mdmUUID {
				t.Fatal("renewal changed installed access rights or MDM identity")
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
			testIdentityToken(t, s, candidate)
			if _, err = s.Connect(t.Context(), candidate, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
				t.Fatal(err)
			}
			current := load()
			if current.accessRights != old.accessRights || current.identityUUID == old.identityUUID {
				t.Fatal("confirmed renewal lost rights or retained old identity")
			}
			// Reconstruct UUID metadata without trusting a stale Device copy or
			// inventing rights from the model reported in inventory.
			if _, err = s.db.Exec(`DELETE FROM mdm_apple_enrollment_layouts WHERE device_id=$1`, d.ID); err != nil {
				t.Fatal(err)
			}
			prefix := "eu.openuem.enrollment." + d.ID
			installed := InstalledProfile{Identifier: prefix, UUID: current.profileUUID, Payloads: []InstalledPayload{
				{Identifier: prefix + ".mdm", UUID: current.mdmUUID, Type: "com.apple.mdm"},
				{Identifier: prefix + ".identity", UUID: current.identityUUID, Type: current.identityType},
				{Identifier: prefix + ".ca", UUID: current.caUUID, Type: "com.apple.security.root"},
			}}
			tx, err := s.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			stale := *d
			stale.DeviceLockAllowed = !allowed
			if err = s.recoverEnrollmentLayout(t.Context(), tx, &stale, []InstalledProfile{installed}); err != nil {
				t.Fatal(err)
			}
			recovered, err := loadEnrollmentLayout(t.Context(), tx, d.ID)
			if err != nil || recovered.accessRights != old.accessRights {
				t.Fatal("recovered rights differed", err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnrollmentDeviceLockInvitationRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	if _, err := s.db.Exec(`CREATE FUNCTION reject_lock_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.enrollment.device_lock.allow' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_lock_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_lock_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.invite(t.Context(), Scope{TenantID: 1, SiteID: 1}, "Rollback lock rights", "admin", EnrollmentOptions{AllowMacDeviceLock: true}, nil); err == nil {
		t.Fatal("audit failure accepted")
	}
	var devices, audits int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_devices),(SELECT count(*) FROM mdm_apple_audit WHERE action='apple.enrollment.invite')`).Scan(&devices, &audits); err != nil || devices != 0 || audits != 0 {
		t.Fatal("partial invitation persisted", devices, audits, err)
	}
	denied := func(context.Context, *sql.Tx) error { return access.ErrDenied }
	if _, err := s.invite(t.Context(), Scope{TenantID: 1, SiteID: 1}, "Denied", "admin", EnrollmentOptions{AllowMacDeviceLock: true}, denied); !errors.Is(err, access.ErrDenied) {
		t.Fatal("authorization ignored", err)
	}
}

func TestEnrollmentDeviceLockPageExplainsRights(t *testing.T) {
	for _, state := range []string{"ready", "claimed"} {
		r := httptest.NewRequest("GET", "/mdm/apple/enroll/example", nil)
		w := httptest.NewRecorder()
		renderEnrollmentPage(w, r, 200, enrollmentPageData{EnrollmentStatus: &EnrollmentStatus{State: state, Platform: PlatformMacOS, Organization: "Example organization", DeviceLockAllowed: true, ExpiresAt: time.Now().Add(time.Hour), DownloadsRemaining: 3}, Path: r.URL.Path, CSRF: "test-csrf-token"})
		if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("device lock and passcode removal rights")) || bytes.Contains(w.Body.Bytes(), []byte(`value="ios"`)) {
			t.Fatal("Mac permission disclosure missing", w.Code)
		}
		if state == "ready" && !bytes.Contains(w.Body.Bytes(), []byte(`name="confirm_device_lock" value="yes" required`)) {
			t.Fatal("separate confirmation missing")
		}
		savePortalArtifact(t, "device-lock-"+state, w.Body.Bytes())
	}
}

func TestEnrollmentDeviceLockRejectsLayoutPermissionMismatch(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, _, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Baseline Mac", "Mac16,1", "15.0")
	if _, err := s.db.Exec(`UPDATE mdm_apple_enrollment_layouts SET access_rights=7959 WHERE device_id=$1`, d.ID); err == nil {
		t.Fatal("layout escalation accepted")
	}
	// Simulate restored inconsistent metadata only in this disposable schema.
	if _, err := s.db.Exec(`ALTER TABLE mdm_apple_enrollment_layouts DISABLE TRIGGER mdm_apple_enrollment_rights_guard; UPDATE mdm_apple_enrollment_layouts SET access_rights=7959; ALTER TABLE mdm_apple_enrollment_layouts ENABLE TRIGGER mdm_apple_enrollment_rights_guard`); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = loadEnrollmentLayout(t.Context(), tx, d.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("restored mismatched rights accepted", err)
	}
	if err = s.recoverEnrollmentLayout(t.Context(), tx, d, []InstalledProfile{{UUID: uuid.NewString()}}); !errors.Is(err, ErrConflict) {
		t.Fatal("inconsistent layout silently replaced", err)
	}
}

func TestEnrollmentDeviceLockMigrationPreservesExistingRights(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, _, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Pre-option Mac", "Mac16,1", "15.0")
	// Recreate the immediate predecessor only within this disposable schema.
	if _, err := s.db.Exec(`DROP TRIGGER mdm_apple_enrollment_rights_guard ON mdm_apple_enrollment_layouts;
	 DROP FUNCTION mdm_apple_enrollment_rights_guard();
	 DROP TRIGGER mdm_apple_immutable_device_lock ON mdm_apple_devices;
	 DROP FUNCTION mdm_apple_immutable_device_lock();
	 ALTER TABLE mdm_apple_devices DROP COLUMN device_lock_allowed;
	 DELETE FROM mdm_apple_migrations WHERE name='migrations/018_enrollment_device_lock.sql'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var allowed bool
	var rights int64
	if err := s.db.QueryRow(`SELECT d.device_lock_allowed,l.access_rights FROM mdm_apple_devices d JOIN mdm_apple_enrollment_layouts l ON l.device_id=d.id WHERE d.id=$1`, d.ID).Scan(&allowed, &rights); err != nil || allowed || rights != 7955 {
		t.Fatal("migration granted existing enrollment new rights", err)
	}
}
