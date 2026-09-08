package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

func testIdentityDue(t *testing.T, s *Store, d *Device) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()+interval '20 days',next_identity_renewal_at=clock_timestamp() WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
}

func testIdentityGeneration(t *testing.T, s *Store, d *Device) IdentityRenewal {
	t.Helper()
	rows, err := s.IdentityRenewals(context.Background(), Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil || len(rows) == 0 {
		t.Fatal("missing identity generation", rows, err)
	}
	return rows[0]
}

func testIdentityDelivery(t *testing.T, s *Store, d *Device, r IdentityRenewal) []byte {
	t.Helper()
	data, err := s.Connect(context.Background(), d, map[string]any{"UDID": d.UDID, "Status": "Idle"})
	if err != nil {
		t.Fatal(err)
	}
	var command map[string]any
	if _, err = plist.Unmarshal(data, &command); err != nil {
		t.Fatal(err)
	}
	if command["CommandUUID"] != r.CommandID || command["Command"].(map[string]any)["RequestType"] != "InstallProfile" {
		t.Fatal("renewal profile was not delivered", command)
	}
	profile := command["Command"].(map[string]any)["Payload"].([]byte)
	content := testSCEPProfile(t, profile)
	if !strings.HasSuffix(content["URL"].(string), "/"+d.ID+"/scep/"+r.ID) {
		t.Fatal("renewal authorization is not generation-bound")
	}
	return profile
}

func testIdentityPending(t *testing.T, s *Store) (*Device, *x509.Certificate, IdentityRenewal, *scepAuthority, *scepFixture, *scepRequest) {
	t.Helper()
	d, cert := testEnroll(t, s, Scope{TenantID: 1, SiteID: 1}, "Renewal test")
	drainCommands(t, s, d, nil)
	testIdentityDue(t, s, d)
	if err := s.ScheduleIdentityRenewals(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := testIdentityGeneration(t, s, d)
	if _, err := s.scepRenewalAuthority(context.Background(), d.ID, r.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("undelivered command exposed SCEP authority", err)
	}
	profile := testIdentityDelivery(t, s, d, r)
	a, err := s.scepRenewalAuthority(context.Background(), d.ID, r.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	f, csr := testSCEPDeviceRequest(t, d.ID, testSCEPProfile(t, profile)["Challenge"].(string), a.ca, a.ra)
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return d, cert, r, a, f, request
}

func testIdentityIssue(t *testing.T, s *Store, a *scepAuthority, f *scepFixture, request *scepRequest) (*Device, *x509.Certificate) {
	t.Helper()
	response, err := s.scepRenew(context.Background(), a, request)
	if err != nil {
		t.Fatal(err)
	}
	cert := testSCEPResult(t, f, response, true)
	d, err := s.AuthenticateCertificate(context.Background(), a.deviceID, cert)
	if err != nil {
		t.Fatal(err)
	}
	return d, cert
}

func testIdentityToken(t *testing.T, s *Store, d *Device) {
	t.Helper()
	if err := s.CheckIn(context.Background(), d, map[string]any{"MessageType": "TokenUpdate", "UDID": d.UDID, "Topic": "com.apple.mgmt.test", "Token": []byte("renewed-push-token"), "PushMagic": "renewed-magic"}); err != nil {
		t.Fatal(err)
	}
}

func testIdentityPin(t *testing.T, s *Store, d *Device, cert *x509.Certificate, token string) {
	t.Helper()
	var fingerprint string
	var encrypted []byte
	if err := s.db.QueryRow(`SELECT certificate_fingerprint,push_token FROM mdm_apple_devices WHERE id=$1`, d.ID).Scan(&fingerprint, &encrypted); err != nil {
		t.Fatal(err)
	}
	plain, err := s.secrets.open(encrypted, secretPurpose(d.TenantID, d.ID, "push_token"))
	if err != nil || fingerprint != digest(cert.Raw) || string(plain) != token {
		t.Fatal("certificate and push data changed outside confirmation", err)
	}
}

func TestIdentityRenewalConfirmsPossessionAndRestrictsRetiredKey(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	ctx := context.Background()
	d, oldCert, r, a, f, request := testIdentityPending(t, s)
	var wg sync.WaitGroup
	responses, failures := make([][]byte, 8), make([]error, 8)
	for i := range responses {
		wg.Go(func() { responses[i], failures[i] = s.scepRenew(ctx, a, request) })
	}
	wg.Wait()
	var cert *x509.Certificate
	for i, response := range responses {
		if failures[i] != nil {
			t.Fatal(failures[i])
		}
		got := testSCEPResult(t, f, response, true)
		if cert != nil && !bytes.Equal(cert.Raw, got.Raw) {
			t.Fatal("concurrent retry issued another identity")
		}
		cert = got
	}
	// Candidate state and authorization must survive recreation of the service.
	restarted, err := NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	s = restarted
	testIdentityPin(t, s, d, oldCert, "test-apns-token")
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE resource_id=$1 AND action='apple.identity.renewal.issue'`, r.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate issuance", count, err)
	}
	candidate, err := s.AuthenticateCertificate(ctx, d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	idle := map[string]any{"UDID": d.UDID, "Status": "Idle"}
	if _, err = s.Connect(ctx, candidate, idle); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("candidate confirmed without push data", err)
	}
	if _, err = s.DeclarativeManagement(ctx, candidate, map[string]any{"UDID": d.UDID, "Endpoint": "tokens"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unconfirmed candidate fetched declarations", err)
	}
	if err = s.CheckIn(ctx, candidate, map[string]any{"UDID": d.UDID, "MessageType": "CheckOut"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unconfirmed candidate checked out device", err)
	}
	testIdentityToken(t, s, candidate)
	testIdentityPin(t, s, d, oldCert, "test-apns-token")
	var staged []byte
	if err = s.db.QueryRow(`SELECT encrypted_token FROM mdm_apple_identity_renewals WHERE id=$1`, r.ID).Scan(&staged); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(staged, []byte("renewed-push-token")) {
		t.Fatal("staged push secret is plaintext")
	}
	if _, err = s.secrets.open(staged, secretPurpose(d.TenantID, d.ID, "push_token")); err == nil {
		t.Fatal("candidate secret is not generation-bound")
	}
	if payload, err := s.Connect(ctx, candidate, idle); err != nil || len(payload) != 0 {
		t.Fatal("candidate was not confirmed or profile was redelivered", err)
	}
	testIdentityPin(t, s, d, cert, "renewed-push-token")
	r = testIdentityGeneration(t, s, d)
	if r.Status != "confirmed" || r.ConfirmedAt == nil || r.TokenUpdatedAt == nil || r.CertificateExpiresAt == nil || !r.CertificateExpiresAt.After(time.Now().AddDate(0, 11, 0)) {
		t.Fatal("confirmation evidence missing", r)
	}
	var status string
	if err = s.db.QueryRow(`SELECT status FROM mdm_apple_commands WHERE id=$1`, r.CommandID).Scan(&status); err != nil || status != "verified" {
		t.Fatal("independent verification invented an ACK", status, err)
	}
	if _, err = s.Connect(ctx, d, idle); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("stale authenticated object fetched commands", err)
	}
	if err = s.CheckIn(ctx, d, map[string]any{"UDID": d.UDID, "MessageType": "CheckOut"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retired key checked out device", err)
	}
	if _, err = s.DeclarativeManagement(ctx, d, map[string]any{"UDID": d.UDID, "Endpoint": "tokens"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retired key fetched declarations", err)
	}
	ack := map[string]any{"UDID": d.UDID, "Status": "Acknowledged", "CommandUUID": uuid.NewString()}
	if _, err = s.Connect(ctx, d, ack); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retired key acknowledged another command", err)
	}
	ack["CommandUUID"] = r.CommandID
	if payload, err := s.Connect(ctx, d, ack); err != nil || len(payload) != 0 {
		t.Fatal("exact retired ACK failed or received another command", err)
	}
	if err = s.db.QueryRow(`SELECT status FROM mdm_apple_commands WHERE id=$1`, r.CommandID).Scan(&status); err != nil || status != "acknowledged" {
		t.Fatal("late ACK missing", status, err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_identity_renewals SET grace_until=clock_timestamp()-interval '1 second' WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthenticateCertificate(ctx, d.ID, oldCert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retired identity outlived its grace", err)
	}
	if _, err = s.Connect(ctx, d, ack); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("stale authenticated object bypassed expired grace", err)
	}
	if _, err = s.Connect(ctx, candidate, idle); err != nil {
		t.Fatal("new active identity stopped working", err)
	}
	for _, scope := range []Scope{{TenantID: 2}, {TenantID: 1, SiteID: 2}} {
		if _, err = s.IdentityRenewals(ctx, scope, d.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("renewal history crossed scope", err)
		}
	}
}

func TestIdentityRenewalIssuanceAndConfirmationRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, oldCert, r, a, f, request := testIdentityPending(t, s)
	ctx := context.Background()
	if _, err := s.db.Exec(`CREATE FUNCTION reject_identity_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('apple.identity.renewal.issue','apple.identity.renewal.confirm') THEN RAISE EXCEPTION 'test failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_identity_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_identity_audit()`); err != nil {
		t.Fatal(err)
	}
	if response, err := s.scepRenew(ctx, a, request); err == nil || len(response) != 0 {
		t.Fatal("issuance committed without audit")
	}
	if got := testIdentityGeneration(t, s, d); got.Status != "queued" || got.Fingerprint != "" {
		t.Fatal("failed issuance consumed authorization", got)
	}
	if _, err := s.db.Exec(`ALTER TABLE mdm_apple_audit DISABLE TRIGGER reject_identity_audit`); err != nil {
		t.Fatal(err)
	}
	candidate, cert := testIdentityIssue(t, s, a, f, request)
	testIdentityToken(t, s, candidate)
	if _, err := s.db.Exec(`ALTER TABLE mdm_apple_audit ENABLE TRIGGER reject_identity_audit`); err != nil {
		t.Fatal(err)
	}
	idle := map[string]any{"UDID": d.UDID, "Status": "Idle"}
	if _, err := s.Connect(ctx, candidate, idle); err == nil {
		t.Fatal("confirmation committed without audit")
	}
	testIdentityPin(t, s, d, oldCert, "test-apns-token")
	if got := testIdentityGeneration(t, s, d); got.Status != "issued" || got.ConfirmedAt != nil {
		t.Fatal("failed confirmation changed generation", got)
	}
	var state string
	if err := s.db.QueryRow(`SELECT status FROM mdm_apple_commands WHERE id=$1`, r.CommandID).Scan(&state); err != nil || state != "sent" {
		t.Fatal("failed confirmation completed command", state, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_identity_audit ON mdm_apple_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Connect(ctx, candidate, idle); err != nil {
		t.Fatal(err)
	}
	testIdentityPin(t, s, d, cert, "renewed-push-token")
}

func TestIdentityRenewalOldAcknowledgementAndNewDeferralDoNotActivate(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, oldCert, r, a, f, request := testIdentityPending(t, s)
	ctx := context.Background()
	ack := map[string]any{"UDID": d.UDID, "Status": "Acknowledged", "CommandUUID": r.CommandID}
	if _, err := s.Connect(ctx, d, ack); err != nil {
		t.Fatal(err)
	}
	if got := testIdentityGeneration(t, s, d); got.Status != "queued" {
		t.Fatal("old ACK completed renewal", got)
	}
	candidate, cert := testIdentityIssue(t, s, a, f, request)
	testIdentityToken(t, s, candidate)
	ack["Status"] = "NotNow"
	if payload, err := s.Connect(ctx, candidate, ack); err != nil || len(payload) != 0 {
		t.Fatal("deferring candidate received commands", err)
	}
	testIdentityPin(t, s, d, oldCert, "test-apns-token")
	if got := testIdentityGeneration(t, s, d); got.Status != "issued" {
		t.Fatal("candidate deferral completed renewal", got)
	}
	ack["Status"], ack["CommandUUID"] = "Acknowledged", uuid.NewString()
	if _, err := s.Connect(ctx, candidate, ack); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("candidate acknowledged unrelated work", err)
	}
	for _, channel := range []string{"UserID", "EnrollmentID"} {
		if _, err := s.DeclarativeManagement(ctx, d, map[string]any{"UDID": d.UDID, "Endpoint": "tokens", channel: "unexpected"}); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("device identity used for another DDM channel", err)
		}
	}
	if _, err := s.Connect(ctx, candidate, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
		t.Fatal(err)
	}
	testIdentityPin(t, s, d, cert, "renewed-push-token")
}

func TestPushOutcomeCannotOverwriteNewIdentityOrToken(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, _, _, a, f, request := testIdentityPending(t, s)
	ctx := context.Background()
	var token, magic []byte
	if err := s.db.QueryRow(`SELECT push_token,push_magic FROM mdm_apple_devices WHERE id=$1`, d.ID).Scan(&token, &magic); err != nil {
		t.Fatal(err)
	}
	if err := s.recordPushOutcome(ctx, d.ID, token, magic, "accepted", ""); err != nil {
		t.Fatal(err)
	}
	assertStatus := func(expected string) {
		t.Helper()
		var status string
		var next time.Time
		if err := s.db.QueryRow(`SELECT push_status,next_push_at FROM mdm_apple_devices WHERE id=$1`, d.ID).Scan(&status, &next); err != nil || status != expected || next.After(time.Now().Add(time.Hour)) {
			t.Fatal("stale push response changed current delivery", status, next, err)
		}
	}
	assertStatus("accepted")
	candidate, _ := testIdentityIssue(t, s, a, f, request)
	testIdentityToken(t, s, candidate)
	if _, err := s.Connect(ctx, candidate, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordPushOutcome(ctx, d.ID, token, magic, "invalid_token", "stale token"); err != nil {
		t.Fatal(err)
	}
	assertStatus("pending")
}

func TestIdentityRenewalOfflineCandidateSurvivesAuthorizationDeadline(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, oldCert, r, a, f, request := testIdentityPending(t, s)
	candidate, cert := testIdentityIssue(t, s, a, f, request)
	ctx := context.Background()
	if _, err := s.db.Exec(`UPDATE mdm_apple_identity_renewals SET expires_at=clock_timestamp()-interval '1 hour',base_expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_commands SET expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1`, r.CommandID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.expireCommands(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileIdentityRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testIdentityGeneration(t, s, d); got.Status != "issued" {
		t.Fatal("offline candidate was lost with expired command", got)
	}
	if _, err := s.scepRenewalAuthority(ctx, d.ID, r.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired issuance authorization remained usable", err)
	}
	if _, err := s.AuthenticateCertificate(ctx, d.ID, oldCert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired active pin still authorized", err)
	}
	if _, err := s.AuthenticateCertificate(ctx, d.ID, cert); err != nil {
		t.Fatal("offline candidate cannot reconnect", err)
	}
	testIdentityToken(t, s, candidate)
	if _, err := s.Connect(ctx, candidate, map[string]any{"UDID": d.UDID, "Status": "Acknowledged", "CommandUUID": r.CommandID}); err != nil {
		t.Fatal(err)
	}
	testIdentityPin(t, s, d, cert, "renewed-push-token")
}

func TestIdentityRenewalFailuresKeepActivePinAndRejectStaleCandidate(t *testing.T) {
	for _, failure := range []string{"authorization_expired", "old_error", "candidate_error", "late_old_error", "candidate_expired", "revoked", "checkout"} {
		t.Run(failure, func(t *testing.T) {
			s := testStore(t)
			testSettings(t, s, 1)
			d, oldCert, r, a, f, request := testIdentityPending(t, s)
			ctx := context.Background()
			var candidate *Device
			var cert *x509.Certificate
			if failure != "authorization_expired" {
				candidate, cert = testIdentityIssue(t, s, a, f, request)
			}
			var err error
			switch failure {
			case "authorization_expired":
				_, err = s.db.Exec(`UPDATE mdm_apple_identity_renewals SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, r.ID)
			case "candidate_expired":
				_, err = s.db.Exec(`UPDATE mdm_apple_identity_renewals SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, r.ID)
			case "revoked":
				err = s.RevokeEnrollment(ctx, Scope{TenantID: 1, SiteID: 1}, d.ID, "admin")
			case "checkout":
				err = s.CheckIn(ctx, d, map[string]any{"UDID": d.UDID, "MessageType": "CheckOut"})
			default:
				if failure == "late_old_error" {
					if _, err = s.db.Exec(`UPDATE mdm_apple_commands SET status='expired',completed_at=clock_timestamp() WHERE id=$1`, r.CommandID); err != nil {
						t.Fatal(err)
					}
				}
				peer := d
				if failure == "candidate_error" {
					peer = candidate
				}
				_, err = s.Connect(ctx, peer, map[string]any{"UDID": d.UDID, "Status": "Error", "CommandUUID": r.CommandID})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.ReconcileIdentityRenewals(ctx); err != nil {
				t.Fatal(err)
			}
			got := testIdentityGeneration(t, s, d)
			if got.Status == "queued" || got.Status == "issued" || got.Status == "confirmed" || got.Error == "" {
				t.Fatal("failed generation remains active", got)
			}
			var challenge sql.NullString
			var staged []byte
			if err = s.db.QueryRow(`SELECT challenge_hash,encrypted_token FROM mdm_apple_identity_renewals WHERE id=$1`, r.ID).Scan(&challenge, &staged); err != nil || challenge.Valid || len(staged) != 0 {
				t.Fatal("terminal generation retained authorization or staged secret", err)
			}
			if _, err = s.scepRenewalAuthority(ctx, d.ID, r.ID, false); !errors.Is(err, ErrNotFound) {
				t.Fatal("failed generation remained discoverable", err)
			}
			response, err := s.scepRenew(ctx, a, request)
			if err != nil {
				t.Fatal(err)
			}
			testSCEPResult(t, f, response, false)
			if candidate != nil {
				if _, err = s.AuthenticateCertificate(ctx, d.ID, cert); !errors.Is(err, ErrUnauthorized) {
					t.Fatal("failed candidate authenticated", err)
				}
				if _, err = s.Connect(ctx, candidate, map[string]any{"UDID": d.UDID, "Status": "Idle"}); !errors.Is(err, ErrUnauthorized) {
					t.Fatal("stale candidate object bypassed failure", err)
				}
			}
			if failure != "revoked" && failure != "checkout" {
				if err = s.RetryCommand(ctx, Scope{TenantID: 1, SiteID: 1}, d.ID, r.CommandID, "admin"); !errors.Is(err, ErrConflict) {
					t.Fatal("manual command retry revived obsolete renewal authorization", err)
				}
				testIdentityPin(t, s, d, oldCert, "test-apns-token")
				if _, err = s.Connect(ctx, d, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
					t.Fatal("renewal failure broke active identity", err)
				}
			}
		})
	}
}
