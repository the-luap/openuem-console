package windows

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestWindowsCertificateHealthAuthenticatesIssuerAfterExpiry(t *testing.T) {
	s := authorityTestStore(t)
	a, err := s.InitializeAuthority(t.Context(), "admin", 1, authorityTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	encrypted := certificateHealthTestBackdateIssuer(t, s, a, time.Now().Add(-6*365*24*time.Hour))
	r, err := s.CertificateHealth(t.Context(), "admin", access.Scope{TenantID: 1}, certificateHealthTestOptions())
	if err != nil || r.Authority == nil || r.Authority.State != "expired" || len(r.Devices) != 0 {
		t.Fatal("expired issuer could not be assessed", err)
	}
	if signer, err := s.decryptAuthority(*a, encrypted, r.AssessedAt); !errors.Is(err, ErrAuthorityUnavailable) || signer != nil {
		t.Fatal("health read enabled expired issuance", err)
	}
}

func certificateHealthTestBackdateIssuer(t *testing.T, s *Store, a *EnrollmentAuthority, created time.Time) []byte {
	t.Helper()
	// Replace only this unused synthetic issuer with a fully authenticated old
	// issuer. Health must remain readable when issuance itself is unavailable.
	a.CreatedAt = created.UTC().Truncate(time.Microsecond)
	der, private, err := generateAuthorityCertificate(*a, a.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	a.Certificate, a.ExpiresAt = der, certificate.NotAfter
	hash := sha256.Sum256(der)
	a.FingerprintSHA256 = hex.EncodeToString(hash[:])
	encrypted, err := s.secrets.seal(private, authoritySecretPurpose(*a))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE mdm_windows_authorities DISABLE TRIGGER mdm_windows_authority_identity`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_authorities SET certificate=$1,encrypted_key=$2,created_at=$3,expires_at=$4`, der, encrypted, a.CreatedAt, a.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE mdm_windows_authorities ENABLE TRIGGER mdm_windows_authority_identity`); err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func TestWindowsCertificateHealthRejectsTamperingAndAuditFailure(t *testing.T) {
	f := renewalTestStore(t)
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"issuer policy":   `ALTER TABLE mdm_windows_authorities DISABLE TRIGGER mdm_windows_authority_identity; UPDATE mdm_windows_authorities SET renewal_seconds=renewal_seconds-1`,
		"issuer key":      `ALTER TABLE mdm_windows_authorities DISABLE TRIGGER mdm_windows_authority_identity; UPDATE mdm_windows_authorities SET encrypted_key=set_byte(encrypted_key,20,get_byte(encrypted_key,20)#1)`,
		"certificate DER": `ALTER TABLE mdm_windows_device_certificates DISABLE TRIGGER mdm_windows_device_certificate; UPDATE mdm_windows_device_certificates SET certificate=set_byte(certificate,20,get_byte(certificate,20)#1)`,
		"sealed renewal":  `ALTER TABLE mdm_windows_certificate_renewals DISABLE TRIGGER mdm_windows_certificate_renewal_identity; UPDATE mdm_windows_certificate_renewals SET encrypted_record=set_byte(encrypted_record,20,get_byte(encrypted_record,20)#1)`,
	} {
		t.Run(name, func(t *testing.T) {
			// Corrupt only this transaction in the random test schema; rollback
			// restores both the fields and their protective triggers.
			tx, err := f.store.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.Exec(statement); err != nil {
				t.Fatal(err)
			}
			// Verify through the same authenticated reader before rollback. The
			// public method is tested below for final-audit failure and scope.
			a, err := scanAuthority(tx.QueryRow(`SELECT ` + authorityColumns + ` FROM mdm_windows_authorities WHERE tenant_id=1`))
			if err == nil {
				var encrypted []byte
				if err = tx.QueryRow(`SELECT encrypted_key FROM mdm_windows_authorities WHERE tenant_id=1`).Scan(&encrypted); err != nil {
					t.Fatal(err)
				}
				if _, err = f.store.authenticateAuthority(*a, encrypted); err == nil {
					_, err = f.store.deviceCertificateHealth(t.Context(), tx, f.identity.Scope, f.identity.DeviceID, f.identity.CertificateID, *a, time.Now(), 30, "admin")
				}
			}
			if !errors.Is(err, ErrAuthoritySecret) && !errors.Is(err, ErrManagementIdentity) {
				t.Fatal("tampered health accepted", err)
			}
		})
	}
	var before int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_renewal_audit`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_certificate_health_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic health audit failure'; END; $$; CREATE TRIGGER reject_certificate_health_audit BEFORE INSERT ON mdm_windows_console_audit FOR EACH ROW EXECUTE FUNCTION reject_certificate_health_audit()`); err != nil {
		t.Fatal(err)
	}
	if r, err := f.store.CertificateHealth(t.Context(), "admin", f.identity.Scope, certificateHealthTestOptions()); err == nil || r != nil {
		t.Fatal("health returned without final audit")
	}
	var after int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_renewal_audit`).Scan(&after); err != nil || before != after {
		t.Fatal("failed health read retained nested audit", err)
	}
}

func TestWindowsCertificateHealthAuthorizationRefreshesAfterLockWait(t *testing.T) {
	f := syncMLTestStore(t)
	s := f.store
	if err := s.permissions.ReplaceGrants(t.Context(), "admin", "second", 1, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	hold, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	var pid int
	if err := hold.QueryRow(`SELECT pg_backend_pid(),pg_advisory_xact_lock(684627902)`).Scan(&pid, new(any)); err != nil {
		t.Fatal(err)
	}
	// The permission writer lock serializes the whole read's grant check.
	if _, err := hold.Exec(`DELETE FROM uem_access_grants WHERE user_id='second'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		r, err := s.CertificateHealth(ctx, "second", f.identity.Scope, certificateHealthTestOptions())
		if r != nil {
			done <- errors.New("health returned with revoked permission")
			return
		}
		done <- err
	}()
	waitForCredentialLock(t, s.db, pid, 1)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, access.ErrDenied) {
		t.Fatal("stale certificate grant survived lock wait", err)
	}
}

func TestWindowsCertificateHealthMigrationPreservesExistingAudit(t *testing.T) {
	f := syncMLTestStore(t)
	if _, err := f.store.Devices(t.Context(), "viewer", f.identity.Scope, "", 0, 25); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := f.store.db.QueryRow(`SELECT json_agg(a ORDER BY id)::text FROM mdm_windows_console_audit a`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	certificateReminderTestRemoveMigration(t, f.store)
	if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_console_audit DROP CONSTRAINT mdm_windows_console_audit_action_check; ALTER TABLE mdm_windows_console_audit ADD CONSTRAINT mdm_windows_console_audit_action_check CHECK(action IN ('invitations.list','devices.list','device.read','device.revoked','authority.status')); DELETE FROM mdm_windows_migrations WHERE name='migrations/014_certificate_health.sql'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.store.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var after string
	if err := f.store.db.QueryRow(`SELECT json_agg(a ORDER BY id)::text FROM mdm_windows_console_audit a`).Scan(&after); err != nil || before != after {
		t.Fatal("health migration changed existing audit", err)
	}
	if _, err := f.store.CertificateHealth(t.Context(), "admin", f.identity.Scope, certificateHealthTestOptions()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCertificateHealthWaitsForConfirmationWithoutReportingOldTip(t *testing.T) {
	f := renewalTestStore(t)
	request, _ := cspTestStart(t, f.syncMLStoreFixture)
	_, session := f.state(t)
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	candidate := f.candidate(t, r.RenewedCertificateID, f.key)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	hold, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	device, err := f.store.authorizeManagementDeviceExclusive(ctx, hold, candidate.certificate, f.options)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		health, err := f.store.CertificateHealth(ctx, "admin", f.identity.Scope, certificateHealthTestOptions())
		if err == nil && (len(health.Devices) != 1 || health.Devices[0].Current.ID != r.RenewedCertificateID || health.Devices[0].ConfirmedRenewalID != r.ID) {
			err = errors.New("health reported the superseded certificate")
		}
		done <- err
	}()
	waitForCredentialLock(t, f.store.db, pid, 1)
	// Complete a valid handoff against the already stored authenticated packet
	// while the health selection is waiting on the device lock.
	digest := sha256.Sum256(request)
	if err := f.store.confirmCertificateRenewal(ctx, hold, device, session, 2, digest[:]); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil && !errors.Is(err, ErrCSPConflict) {
		t.Fatal("health failed across confirmation", err)
	}
	health, err := f.store.CertificateHealth(ctx, "admin", f.identity.Scope, certificateHealthTestOptions())
	if err != nil || len(health.Devices) != 1 || health.Devices[0].Current.ID != r.RenewedCertificateID {
		t.Fatal("fresh health did not use confirmed identity", err)
	}
}
