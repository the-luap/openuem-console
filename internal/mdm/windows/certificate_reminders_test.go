package windows

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func certificateReminderTestStore(t *testing.T) renewalStoreFixture {
	t.Helper()
	f := renewalTestStore(t)
	if _, err := f.store.db.Exec(`ALTER TABLE users ADD COLUMN email TEXT,ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT true,ADD COLUMN register TEXT NOT NULL DEFAULT 'users.completed'; UPDATE users SET email=uid||'@example.test'`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.permissions.ReplaceGrants(t.Context(), "admin", "second", 1, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	return f
}
func certificateReminderTestReconcile(t *testing.T, f renewalStoreFixture) {
	t.Helper()
	if err := f.store.reconcileCertificateReminder(t.Context(), "device_expiry", f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
}
func certificateReminderTestDelivery(t *testing.T, s *Store, user string) *certificateDelivery {
	t.Helper()
	d, err := scanCertificateDelivery(s.db.QueryRow(`SELECT `+certificateDeliveryColumns+` FROM mdm_windows_certificate_deliveries WHERE user_id=$1 ORDER BY created_at DESC,id LIMIT 1`, user))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.verifyCertificateDelivery(d); err != nil {
		t.Fatal(err)
	}
	return d
}
func certificateReminderTestDue(t *testing.T, s *Store, id string) {
	t.Helper()
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	d, err := scanCertificateDelivery(tx.QueryRow(`SELECT `+certificateDeliveryColumns+` FROM mdm_windows_certificate_deliveries WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		t.Fatal(err)
	}
	d.next = time.Now().Add(-time.Second).UTC().Truncate(time.Microsecond)
	if err := s.saveCertificateDelivery(t.Context(), tx, d, "delivery.retry"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCertificateReminderThresholdsAndBackoff(t *testing.T) {
	expires := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		before time.Duration
		want   int
	}{{31 * 24 * time.Hour, -1}, {30*24*time.Hour + time.Nanosecond, -1}, {30 * 24 * time.Hour, 30}, {14 * 24 * time.Hour, 14}, {7 * 24 * time.Hour, 7}, {24 * time.Hour, 1}, {time.Nanosecond, 1}, {0, 0}, {-time.Hour, 0}} {
		if got := certificateReminderStage(expires, expires.Add(-test.before)); got != test.want {
			t.Fatal("wrong inclusive reminder stage", test.before, got)
		}
	}
	if certificateReminderRetry(1) != 5*time.Minute || certificateReminderRetry(2) != 10*time.Minute || certificateReminderRetry(30) != 24*time.Hour {
		t.Fatal("reminder backoff changed")
	}
}

func TestWindowsCertificateReminderDurabilityRecipientsAndHistory(t *testing.T) {
	f := certificateReminderTestStore(t)
	s := f.store
	ctx := t.Context()
	for range 2 {
		certificateReminderTestReconcile(t, f)
	}
	r, err := s.CertificateReminders(ctx, "admin", f.identity.Scope, 0, 25)
	if err != nil || len(r) != 1 || r[0].Pending != 2 || r[0].Stage != 1 || r[0].ResourceID != f.identity.CertificateID || r[0].Kind != "device_expiry" {
		t.Fatal("durable reminder/history missing", err)
	}
	for _, actor := range []string{"operator", "viewer", "foreign", "missing"} {
		if got, err := s.CertificateReminders(ctx, actor, f.identity.Scope, 0, 25); err == nil || got != nil {
			t.Fatal("reminder history escaped certificate scope")
		}
	}
	for _, scope := range []access.Scope{{TenantID: 1, SiteID: 12}, {TenantID: 2}} {
		if got, err := s.CertificateReminders(ctx, "admin", scope, 0, 25); err != nil || len(got) != 0 {
			t.Fatal("reminder history crossed site or organization", err)
		}
	}
	if got, err := s.CertificateReminders(ctx, "second", access.Scope{TenantID: 1}, 0, 25); err != nil || len(got) != 1 {
		t.Fatal("organization history unavailable", err)
	}
	d := certificateReminderTestDelivery(t, s, "second")
	var first CertificateExpiryMessage
	if err := s.deliverCertificateReminder(ctx, d.id, func(_ context.Context, _ *sql.Tx, m CertificateExpiryMessage) error {
		first = m
		return errors.New("private SMTP response")
	}); err != nil {
		t.Fatal(err)
	}
	d = certificateReminderTestDelivery(t, s, "second")
	if d.phase != "pending" || d.attempts != 1 || d.reason != "smtp_failed" || time.Until(d.next) < 4*time.Minute {
		t.Fatal("retry was not persisted")
	}
	if err := s.deliverCertificateReminder(ctx, d.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
		t.Error("early retry contacted SMTP")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	certificateReminderTestDue(t, s, d.id)
	if _, err := s.db.Exec(`UPDATE users SET email='changed@example.test' WHERE uid='second'`); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStoreWithMasterKey(s.db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.deliverCertificateReminder(ctx, d.id, func(_ context.Context, _ *sql.Tx, m CertificateExpiryMessage) error {
		if m.ID != first.ID || m.Recipient != "changed@example.test" || m.DeviceID != f.identity.DeviceID || m.Fingerprint != f.identity.FingerprintSHA256 || m.Stage != 1 || !m.Deadline.Equal(f.certificate.NotAfter) || m.PendingReplacement {
			t.Fatal("delivery lost stable identity or current recipient")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	certificateReminderTestReconcile(t, f)
	if err := s.deliverCertificateReminder(ctx, d.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
		t.Error("accepted reminder repeated")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	d = certificateReminderTestDelivery(t, s, "second")
	if d.phase != "accepted" || d.attempts != 2 || d.accepted == nil {
		t.Fatal("SMTP acceptance not retained")
	}
	for _, value := range []any{first, r[0], d} {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), f.identity.DeviceID) || strings.Contains(fmt.Sprintf("%+v %#v", value, value), f.identity.DeviceID) {
			t.Fatal("generic reminder formatting leaked identity")
		}
	}
	var all string
	if err := s.db.QueryRow(`SELECT json_agg(d)::text FROM mdm_windows_certificate_deliveries d`).Scan(&all); err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"@example.test", "private SMTP response", f.secrets.ClientSecret, f.identity.FingerprintSHA256} {
		if strings.Contains(all, private) {
			t.Fatal("delivery queue stored sensitive metadata", private)
		}
	}
	if _, err := s.db.Exec(`UPDATE users SET email_verified=false WHERE uid='admin'`); err != nil {
		t.Fatal(err)
	}
	admin := certificateReminderTestDelivery(t, s, "admin")
	if err := s.deliverCertificateReminder(ctx, admin.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
		t.Error("unverified recipient received mail")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if certificateReminderTestDelivery(t, s, "admin").reason != "recipient_unavailable" {
		t.Fatal("ineligible recipient not canceled")
	}
	if _, err := s.db.Exec(`UPDATE users SET email_verified=true WHERE uid='admin'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE users SET email='invalid address' WHERE uid='admin'`); err != nil {
		t.Fatal(err)
	}
	certificateReminderTestReconcile(t, f)
	if certificateReminderTestDelivery(t, s, "admin").phase != "canceled" {
		t.Fatal("invalid address was requeued repeatedly")
	}
	if _, err := s.db.Exec(`UPDATE users SET email='admin@example.test' WHERE uid='admin'`); err != nil {
		t.Fatal(err)
	}
	certificateReminderTestReconcile(t, f)
	if certificateReminderTestDelivery(t, s, "admin").phase != "pending" {
		t.Fatal("eligible recipient could not resume")
	}
}

func TestWindowsCertificateReminderCycleAdvancesPastCorruptDeliveryBatch(t *testing.T) {
	f := certificateReminderTestStore(t)
	s := f.store
	if _, err := s.db.Exec(`INSERT INTO users(uid,email,email_verified,register) SELECT 'batch-'||i,'batch-'||i||'@example.test',true,'users.completed' FROM generate_series(1,101) i; INSERT INTO uem_access_grants(user_id,role,tenant_id,site_id) SELECT uid,'organization_admin',1,0 FROM users WHERE uid LIKE 'batch-%'`); err != nil {
		t.Fatal(err)
	}
	certificateReminderTestReconcile(t, f)
	if _, err := s.db.Exec(`ALTER TABLE mdm_windows_certificate_deliveries DISABLE TRIGGER mdm_windows_certificate_delivery_identity; WITH selected AS(SELECT id FROM mdm_windows_certificate_deliveries ORDER BY next_attempt_at,id LIMIT 100) UPDATE mdm_windows_certificate_deliveries SET encrypted_state=set_byte(encrypted_state,20,get_byte(encrypted_state,20)#1) WHERE id IN(SELECT id FROM selected); ALTER TABLE mdm_windows_certificate_deliveries ENABLE TRIGGER mdm_windows_certificate_delivery_identity`); err != nil {
		t.Fatal(err)
	}
	cursor := certificateReminderCursor{}
	var calls int
	send := func(context.Context, *sql.Tx, CertificateExpiryMessage) error { calls++; return nil }
	if err := s.certificateReminderCycle(t.Context(), send, &cursor); err == nil || calls != 0 || cursor.id == "" {
		t.Fatal("corrupt batch did not advance its cursor", err, calls)
	}
	if err := s.certificateReminderCycle(t.Context(), send, &cursor); err == nil || calls != 3 {
		t.Fatal("corrupt batch starved later valid deliveries", err, calls)
	}
}

func TestWindowsCertificateReminderPendingConfirmationAndRetirement(t *testing.T) {
	f := certificateReminderTestStore(t)
	s := f.store
	ctx := t.Context()
	certificateReminderTestReconcile(t, f)
	d := certificateReminderTestDelivery(t, s, "second")
	first, err := f.process(f.initial(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.renew(f.request(t, f.key)); err != nil {
		t.Fatal(err)
	}
	r := f.history(t)[0]
	if err := s.deliverCertificateReminder(ctx, d.id, func(_ context.Context, _ *sql.Tx, m CertificateExpiryMessage) error {
		if !m.PendingReplacement || m.Fingerprint != f.identity.FingerprintSHA256 {
			t.Fatal("pending replacement hid current expiry")
		}
		return ErrCertificateReminderSMTP
	}); err != nil {
		t.Fatal(err)
	}
	candidate := f.candidate(t, r.RenewedCertificateID, f.key)
	if _, err := candidate.process(syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))); err != nil {
		t.Fatal(err)
	}
	// Supersession cancels an old delivery even while it is in SMTP backoff.
	certificateReminderTestReconcile(t, f)
	old, err := scanCertificateDelivery(s.db.QueryRow(`SELECT `+certificateDeliveryColumns+` FROM mdm_windows_certificate_deliveries WHERE id=$1`, d.id))
	if err != nil || old.phase != "canceled" || old.reason != "superseded" {
		t.Fatal("confirmed renewal left stale backlog", err)
	}
	if err := s.deliverCertificateReminder(ctx, d.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
		t.Error("superseded certificate sent mail")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	d = certificateReminderTestDelivery(t, s, "second")
	if err := s.RevokeDevice(ctx, "admin", f.identity.Scope, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverCertificateReminder(ctx, d.id, func(context.Context, *sql.Tx, CertificateExpiryMessage) error {
		t.Error("retired device sent expiry mail")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if certificateReminderTestDelivery(t, s, "second").reason != "superseded" {
		t.Fatal("retired identity delivery remained pending")
	}
}

func TestWindowsCertificateReminderReplicasAuditFailureAndCancellation(t *testing.T) {
	f := certificateReminderTestStore(t)
	s := f.store
	var group sync.WaitGroup
	for range 6 {
		group.Go(func() {
			if err := s.reconcileCertificateReminder(t.Context(), "device_expiry", f.identity.DeviceID); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	d := certificateReminderTestDelivery(t, s, "second")
	var calls atomic.Int32
	send := func(context.Context, *sql.Tx, CertificateExpiryMessage) error { calls.Add(1); return nil }
	for range 6 {
		group.Go(func() {
			if err := s.deliverCertificateReminder(t.Context(), d.id, send); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatal("replicas duplicated accepted SMTP", calls.Load())
	}
	admin := certificateReminderTestDelivery(t, s, "admin")
	if _, err := s.db.Exec(`CREATE FUNCTION fail_windows_reminder_acceptance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='delivery.accepted' THEN RAISE EXCEPTION 'synthetic reminder audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_windows_reminder_acceptance BEFORE INSERT ON mdm_windows_certificate_reminder_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_reminder_acceptance()`); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverCertificateReminder(t.Context(), admin.id, send); err == nil {
		t.Fatal("SMTP acceptance committed without audit")
	}
	if certificateReminderTestDelivery(t, s, "admin").phase != "pending" {
		t.Fatal("audit failure retained acceptance")
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_windows_reminder_acceptance ON mdm_windows_certificate_reminder_audit`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := s.deliverCertificateReminder(ctx, admin.id, func(ctx context.Context, _ *sql.Tx, _ CertificateExpiryMessage) error { cancel(); return ctx.Err() }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if certificateReminderTestDelivery(t, s, "admin").attempts != 0 {
		t.Fatal("canceled operation retained delivery state")
	}
	if err := s.deliverCertificateReminder(t.Context(), admin.id, func(_ context.Context, _ *sql.Tx, m CertificateExpiryMessage) error {
		if m.ID != admin.id {
			t.Fatal("ambiguous retry changed Message-ID")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
