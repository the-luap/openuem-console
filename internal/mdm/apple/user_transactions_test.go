package apple

import (
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func TestMacUserLayoutRecoveryPreservesOriginalChannels(t *testing.T) {
	for _, perUser := range []bool{false, true} {
		name := "device-only"
		if perUser {
			name = "per-user"
		}
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			testSettings(t, s, 1)
			d, _, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, name, "Mac16,1", "15.0")
			drainMacInventory(t, s, d)
			tx, err := s.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			original, err := loadEnrollmentLayout(t.Context(), tx, d.ID)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "eu.openuem.enrollment." + d.ID
			inventory := InstalledProfile{Identifier: prefix, UUID: original.profileUUID, Payloads: []InstalledPayload{{Identifier: prefix + ".mdm", UUID: original.mdmUUID, Type: "com.apple.mdm"}, {Identifier: prefix + ".identity", UUID: original.identityUUID, Type: original.identityType}, {Identifier: prefix + ".ca", UUID: original.caUUID, Type: "com.apple.security.root"}}}
			if _, err = tx.Exec(`DELETE FROM mdm_apple_enrollment_layouts WHERE device_id=$1`, d.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(`UPDATE mdm_apple_devices SET per_user_connections=$2 WHERE id=$1`, d.ID, perUser); err != nil {
				t.Fatal(err)
			}
			d.PerUserConnections = perUser
			if err = s.recoverEnrollmentLayout(t.Context(), tx, d, []InstalledProfile{inventory}); err != nil {
				t.Fatal(err)
			}
			recovered, err := loadEnrollmentLayout(t.Context(), tx, d.ID)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.perUserConnections != perUser || !recovered.bootstrapToken {
				t.Fatal("recovery changed original enrollment capabilities", recovered)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			testIdentityDue(t, s, d)
			if err = s.ScheduleIdentityRenewals(t.Context()); err != nil {
				t.Fatal(err)
			}
			renewal := testIdentityGeneration(t, s, d)
			payload := testIdentityDelivery(t, s, d, renewal)
			var root map[string]any
			if _, err = plist.Unmarshal(payload, &root); err != nil {
				t.Fatal(err)
			}
			actual := false
			for _, item := range root["PayloadContent"].([]any) {
				p := item.(map[string]any)
				if p["PayloadType"] == "com.apple.mdm" {
					caps, _ := p["ServerCapabilities"].([]any)
					for _, c := range caps {
						actual = actual || c == "com.apple.mdm.per-user-connections"
					}
				}
			}
			if actual != perUser {
				t.Fatal("renewal changed recovered per-user capability")
			}
		})
	}
}

func TestMacUserAuditFailureRollsBackDiscoveryAndAssignment(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Audit users", "Mac16,1", "15.0")
	failAudit := func() {
		t.Helper()
		if _, err := s.db.Exec(`CREATE OR REPLACE FUNCTION reject_user_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'apple.user.%' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_user_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_user_audit()`); err != nil {
			t.Fatal(err)
		}
	}
	allowAudit := func() {
		t.Helper()
		if _, err := s.db.Exec(`DROP TRIGGER reject_user_audit ON mdm_apple_audit`); err != nil {
			t.Fatal(err)
		}
	}
	failAudit()
	if _, err := s.UserCheckIn(t.Context(), d, map[string]any{"MessageType": "UserAuthenticate", "UDID": d.UDID, "UserID": uuid.NewString()}); err == nil {
		t.Fatal("discovery ignored audit failure")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_users WHERE device_id=$1`, d.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed discovery left a user", count, err)
	}
	allowAudit()
	u := testUserEnroll(t, s, d, "alice")
	p, err := s.SaveProfile(t.Context(), 1, "", 0, userProfileData(t, "com.apple.ManagedClient.preferences", nil), "admin")
	if err != nil {
		t.Fatal(err)
	}
	failAudit()
	if err = s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, "installed", "admin"); err == nil {
		t.Fatal("assignment ignored audit failure")
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_user_commands WHERE user_channel_id=$1 AND request_type='InstallProfile'`, u.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed assignment retained work", count, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_user_assignments WHERE user_channel_id=$1`, u.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed assignment retained desired state", count, err)
	}
	allowAudit()
	if _, err = s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if push, err := s.leaseUserPush(t.Context()); err != nil || push != nil {
		t.Fatal("user push ignored changed site ownership", push, err)
	}
	if _, err = s.UserCheckIn(t.Context(), d, map[string]any{"MessageType": "UserAuthenticate", "UDID": d.UDID, "UserID": u.UserID}); err == nil {
		t.Fatal("user handshake ignored changed site ownership")
	}
}
