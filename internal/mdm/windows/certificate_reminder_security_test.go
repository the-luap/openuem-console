package windows

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func certificateReminderTestRemoveMigration(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`DROP TABLE mdm_windows_certificate_reminder_audit,mdm_windows_certificate_deliveries,mdm_windows_certificate_reminders; DROP FUNCTION mdm_windows_keep_certificate_delivery(); DELETE FROM mdm_windows_migrations WHERE name='migrations/015_certificate_reminders.sql'`); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCertificateReminderIssuerDeadlinesAreDistinct(t *testing.T) {
	s := authorityTestStore(t)
	if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN email TEXT,ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT true,ADD COLUMN register TEXT NOT NULL DEFAULT 'users.completed'; UPDATE users SET email=uid||'@example.test'`); err != nil {
		t.Fatal(err)
	}
	a, err := s.InitializeAuthority(t.Context(), "admin", 1, authorityTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	certificateHealthTestBackdateIssuer(t, s, a, time.Now().Add(-5*365*24*time.Hour+20*24*time.Hour))
	cursor := certificateReminderCursor{}
	seen := map[string]CertificateExpiryMessage{}
	if err := s.certificateReminderCycle(t.Context(), func(_ context.Context, _ *sql.Tx, m CertificateExpiryMessage) error { seen[m.Kind] = m; return nil }, &cursor); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen["issuer_expiry"].Stage != 30 || seen["issuer_issuance"].Stage != 0 || seen["issuer_expiry"].Scope.SiteID != 0 || !seen["issuer_issuance"].Deadline.Equal(a.ExpiresAt.Add(-90*24*time.Hour-5*time.Minute)) {
		t.Fatal("CA expiry and earlier issuance deadline were conflated")
	}
	for _, scope := range []access.Scope{{TenantID: 1}, {TenantID: 1, SiteID: 11}} {
		r, err := s.CertificateReminders(t.Context(), "admin", scope, 0, 25)
		if err != nil || len(r) != 2 || r[0].Accepted != 1 || r[1].Accepted != 1 {
			t.Fatal("issuer history absent from scoped view", err)
		}
	}
	if err := s.certificateReminderCycle(t.Context(), func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
		t.Error("accepted issuer stage repeated")
		return nil
	}, &cursor); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCertificateReminderStageRefreshesAfterRecipientLock(t *testing.T) {
	f := renewalTestShortAnchor(t, certificateReminderTestStore(t))
	s := f.store
	certificateReminderTestReconcile(t, f)
	d := certificateReminderTestDelivery(t, s, "second")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	hold, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	var pid int
	if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(`UPDATE users SET email='still-valid@example.test' WHERE uid='second'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- s.deliverCertificateReminder(ctx, d.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
			t.Error("stale reminder stage crossed deadline while waiting on recipient")
			return nil
		})
	}()
	waitForCredentialLock(t, s.db, pid, 1)
	if err := waitUntilDatabaseExpiry(ctx, hold, f.certificate.NotAfter); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if certificateReminderTestDelivery(t, s, "second").reason != "superseded" {
		t.Fatal("late stage was not superseded")
	}
	certificateReminderTestReconcile(t, f)
	d = certificateReminderTestDelivery(t, s, "second")
	if err := s.deliverCertificateReminder(ctx, d.id, func(_ context.Context, _ *sql.Tx, m CertificateExpiryMessage) error {
		if m.Stage != 0 || m.Recipient != "still-valid@example.test" {
			t.Fatal("expired stage lost live recipient or timing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCertificateReminderRevokedGrantAndMovedSitePreventSend(t *testing.T) {
	f := certificateReminderTestStore(t)
	s := f.store
	certificateReminderTestReconcile(t, f)
	d := certificateReminderTestDelivery(t, s, "second")
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
	if _, err := hold.Exec(`DELETE FROM uem_access_grants WHERE user_id='second'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- s.deliverCertificateReminder(ctx, d.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
			t.Error("revoked grant sent mail")
			return nil
		})
	}()
	waitForCredentialLock(t, s.db, pid, 1)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if certificateReminderTestDelivery(t, s, "second").reason != "recipient_unavailable" {
		t.Fatal("revoked recipient stayed pending")
	}
	if _, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	admin := certificateReminderTestDelivery(t, s, "admin")
	if err := s.deliverCertificateReminder(ctx, admin.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
		t.Error("moved site sent mail under old scope")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []access.Scope{{TenantID: 1}, {TenantID: 2}} {
		r, err := s.CertificateReminders(ctx, "admin", scope, 0, 25)
		if err != nil || len(r) != 0 {
			t.Fatal("site move transferred or retained protected device history", err)
		}
	}
}

func TestWindowsCertificateReminderCorruptionFailsBeforeSMTP(t *testing.T) {
	for name, statement := range map[string]string{
		"reminder metadata":   `ALTER TABLE mdm_windows_certificate_reminders DISABLE TRIGGER mdm_windows_certificate_reminder_history; UPDATE mdm_windows_certificate_reminders SET fingerprint=repeat('0',64)`,
		"delivery recipient":  `ALTER TABLE mdm_windows_certificate_deliveries DISABLE TRIGGER mdm_windows_certificate_delivery_identity; UPDATE mdm_windows_certificate_deliveries SET user_id='viewer' WHERE user_id='second'`,
		"delivery retry":      `ALTER TABLE mdm_windows_certificate_deliveries DISABLE TRIGGER mdm_windows_certificate_delivery_identity; UPDATE mdm_windows_certificate_deliveries SET next_attempt_at=next_attempt_at-INTERVAL '1 second'`,
		"delivery ciphertext": `ALTER TABLE mdm_windows_certificate_deliveries DISABLE TRIGGER mdm_windows_certificate_delivery_identity; UPDATE mdm_windows_certificate_deliveries SET encrypted_state=set_byte(encrypted_state,20,get_byte(encrypted_state,20)#1)`,
	} {
		t.Run(name, func(t *testing.T) {
			f := certificateReminderTestStore(t)
			certificateReminderTestReconcile(t, f)
			d := certificateReminderTestDelivery(t, f.store, "second")
			if _, err := f.store.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if err := f.store.deliverCertificateReminder(t.Context(), d.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
				t.Error("tampered outbox reached SMTP")
				return nil
			}); !errors.Is(err, ErrAuthoritySecret) {
				t.Fatal("tampered reminder accepted", err)
			}
			if r, err := f.store.CertificateReminders(t.Context(), "admin", f.identity.Scope, 0, 25); !errors.Is(err, ErrAuthoritySecret) || r != nil {
				t.Fatal("tampered delivery history exposed", err)
			}
		})
	}
}

func TestWindowsCertificateReminderMigrationAndAuditRollback(t *testing.T) {
	f := certificateReminderTestStore(t)
	s := f.store
	var before string
	if err := s.db.QueryRow(`SELECT row_to_json(e)::text FROM mdm_windows_enrollments e`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	certificateReminderTestRemoveMigration(t, s)
	for range 2 {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var after string
	if err := s.db.QueryRow(`SELECT row_to_json(e)::text FROM mdm_windows_enrollments e`).Scan(&after); err != nil || before != after {
		t.Fatal("reminder migration rewrote enrollment", err)
	}
	certificateReminderTestReconcile(t, f)
	if _, err := s.db.Exec(`CREATE FUNCTION fail_windows_reminder_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic read audit failure'; END $$; CREATE TRIGGER fail_windows_reminder_history BEFORE INSERT ON mdm_windows_console_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_reminder_history()`); err != nil {
		t.Fatal(err)
	}
	if r, err := s.CertificateReminders(t.Context(), "admin", f.identity.Scope, 0, 25); err == nil || r != nil {
		t.Fatal("history returned without final audit")
	}
	var reads int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_certificate_reminder_audit WHERE action='reminder.read'`).Scan(&reads); err != nil || reads != 0 {
		t.Fatal("failed history left nested audits", err)
	}
	for _, stmt := range []string{`DELETE FROM mdm_windows_certificate_reminders`, `DELETE FROM mdm_windows_certificate_deliveries`, `UPDATE mdm_windows_certificate_reminder_audit SET actor='other'`} {
		if _, err := s.db.Exec(stmt); err == nil {
			t.Fatal("reminder history mutable")
		}
	}
}
