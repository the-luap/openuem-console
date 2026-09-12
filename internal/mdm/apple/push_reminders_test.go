package apple

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func reminderStore(t *testing.T) *Store {
	t.Helper()
	s := testStore(t)
	if _, err := s.db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY,email TEXT NOT NULL,email_verified BOOLEAN NOT NULL DEFAULT true,register TEXT NOT NULL DEFAULT 'users.completed')`); err != nil {
		t.Fatal(err)
	}
	a, err := access.NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO users(uid,email) VALUES('admin','admin@example.test'),('org','org@example.test'),('other','other@example.test'),('operator','operator@example.test'),('viewer','viewer@example.test'),('revoked','revoked@example.test'),('unverified','unverified@example.test');
 INSERT INTO uem_access_grants(user_id,role,tenant_id,site_id) VALUES('admin','administrator',0,0),('org','organization_admin',1,0),('other','organization_admin',2,0),('operator','operator',1,0),('viewer','viewer',1,1),('revoked','organization_admin',1,0),('unverified','organization_admin',1,0);
 UPDATE users SET register='users.certificate_revoked' WHERE uid='revoked'; UPDATE users SET email_verified=false WHERE uid='unverified'`); err != nil {
		t.Fatal(err)
	}
	testSettings(t, s, 1)
	request := newTestPushRequest(t, s, 1)
	cert := issueTestPushCertificate(t, s, 1, request.ID, "com.apple.mgmt.test", time.Now().Add(20*24*time.Hour))
	if err = s.ImportPushCertificate(t.Context(), 1, request.ID, cert, "admin"); err != nil {
		t.Fatal(err)
	}
	return s
}

func reminderID(t *testing.T, s *Store, user string) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(`SELECT id FROM mdm_apple_push_reminder_deliveries WHERE user_id=$1 AND status='pending'`, user).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPushReminderThresholds(t *testing.T) {
	issuer, key := testPushCA(t)
	leaf := pushLeafTemplate()
	expires := time.Now().Add(40 * 24 * time.Hour).Truncate(time.Second)
	leaf.NotAfter = expires
	cert := signPushLeaf(t, leaf, issuer, &key.PublicKey, key)
	for _, tc := range []struct {
		before time.Duration
		stage  int
	}{{31 * 24 * time.Hour, -1}, {30*24*time.Hour + time.Nanosecond, -1}, {30 * 24 * time.Hour, 30}, {14 * 24 * time.Hour, 14}, {7 * 24 * time.Hour, 7}, {24 * time.Hour, 1}, {time.Nanosecond, 1}, {0, 0}, {-time.Hour, 0}} {
		fp, expiry, stage, err := pushReminderIdentity(cert, expires.Add(-tc.before))
		if err != nil || len(fp) != 64 || !expiry.Equal(expires) || stage != tc.stage {
			t.Fatalf("before=%s stage=%d want=%d: %v", tc.before, stage, tc.stage, err)
		}
	}
	if _, _, _, err := pushReminderIdentity([]byte("not a certificate"), time.Now()); err == nil {
		t.Fatal("invalid certificate admitted")
	}
	if reminderRetry(1) != 5*time.Minute || reminderRetry(2) != 10*time.Minute || reminderRetry(30) != 24*time.Hour {
		t.Fatal("retry schedule")
	}
}

func TestPushRemindersDurabilityScopeAndRetry(t *testing.T) {
	s := reminderStore(t)
	ctx := t.Context()
	// Neither old connection evidence nor decryption is required for reminders.
	if _, err := s.db.Exec(`UPDATE mdm_apple_settings SET push_checked_at=NULL,push_fingerprint='',push_key='broken',ca_key='broken',apple_account='never-send-here@example.test'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.reconcilePushReminders(ctx, 1, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	history, err := s.PushReminderHistory(ctx, 1)
	if err != nil || len(history) != 1 || history[0].Pending != 2 || history[0].Stage != 30 {
		t.Fatalf("history %+v: %v", history, err)
	}
	other, err := s.PushReminderHistory(ctx, 2)
	if err != nil || len(other) != 0 {
		t.Fatal("history crossed organization", other, err)
	}
	id := reminderID(t, s, "org")
	var original PushExpiryMessage
	if err = s.deliverPushReminder(ctx, id, 1, func(_ context.Context, _ *sql.Tx, m PushExpiryMessage) error {
		original = m
		return errors.New("secret SMTP response never stored")
	}); err != nil {
		t.Fatal(err)
	}
	var code string
	var attempts int
	var due time.Time
	if err = s.db.QueryRow(`SELECT last_error,attempts,next_attempt_at FROM mdm_apple_push_reminder_deliveries WHERE id=$1`, id).Scan(&code, &attempts, &due); err != nil || code != "smtp_failed" || attempts != 1 || time.Until(due) < 4*time.Minute {
		t.Fatal(code, attempts, due, err)
	}
	if err = s.deliverPushReminder(ctx, id, 1, func(context.Context, *sql.Tx, PushExpiryMessage) error { t.Error("retry sent before due"); return nil }); err != nil {
		t.Fatal(err)
	}
	// Restart the store and edit the user's email before retry: read the current
	// address, retain the Message-ID and never use the Apple account metadata.
	restarted, err := NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	// The delivery guard uses the application clock. Make this retry clearly due
	// on that same clock instead of relying on exact host/database clock agreement.
	if _, err = s.db.Exec(`UPDATE users SET email='new-org@example.test' WHERE uid='org'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_push_reminder_deliveries SET next_attempt_at=$1`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	retrySent := false
	if err = restarted.deliverPushReminder(ctx, id, 1, func(_ context.Context, _ *sql.Tx, m PushExpiryMessage) error {
		retrySent = true
		if m.ID != original.ID || m.Recipient != "new-org@example.test" || m.TenantID != 1 || m.Fingerprint != history[0].Fingerprint {
			t.Errorf("incorrect message %+v", m)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !retrySent {
		t.Fatal("due retry did not reach the SMTP fixture")
	}
	if err = restarted.pushReminderCycle(ctx, func(_ context.Context, _ *sql.Tx, m PushExpiryMessage) error {
		if m.Recipient != "admin@example.test" {
			t.Error("unauthorized or repeated recipient", m.Recipient)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = restarted.pushReminderCycle(ctx, func(context.Context, *sql.Tx, PushExpiryMessage) error {
		t.Error("duplicate successful delivery")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	history, err = s.PushReminderHistory(ctx, 1)
	if err != nil || history[0].Sent != 2 || history[0].Pending != 0 {
		t.Fatal(history, err)
	}
}

func TestPushRemindersRecheckAuthorityAndRenewal(t *testing.T) {
	for _, change := range []string{"permission", "verification", "revocation", "deletion", "invalid_email", "renewal"} {
		t.Run(change, func(t *testing.T) {
			s := reminderStore(t)
			ctx := t.Context()
			if err := s.reconcilePushReminders(ctx, 1, time.Now()); err != nil {
				t.Fatal(err)
			}
			id := reminderID(t, s, "org")
			queries := map[string]string{"permission": `DELETE FROM uem_access_grants WHERE user_id='org'`, "verification": `UPDATE users SET email_verified=false WHERE uid='org'`, "revocation": `UPDATE users SET register='users.certificate_revoked' WHERE uid='org'`, "deletion": `DELETE FROM uem_access_grants WHERE user_id='org'; DELETE FROM users WHERE uid='org'`, "invalid_email": `UPDATE users SET email='bad@@example.test' WHERE uid='org'`}
			if change == "renewal" {
				testSettings(t, s, 1)
			} else if _, err := s.db.Exec(queries[change]); err != nil {
				t.Fatal(err)
			}
			if err := s.deliverPushReminder(ctx, id, 1, func(context.Context, *sql.Tx, PushExpiryMessage) error {
				t.Error("stale delivery attempted")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			var status string
			if err := s.db.QueryRow(`SELECT status FROM mdm_apple_push_reminder_deliveries WHERE id=$1`, id).Scan(&status); err != nil || status != "cancelled" {
				t.Fatal(status, err)
			}
			if change == "renewal" {
				if err := s.reconcilePushReminders(ctx, 1, time.Now()); err != nil {
					t.Fatal(err)
				}
				history, err := s.PushReminderHistory(ctx, 1)
				if err != nil || history[0].ResolvedAt == nil || history[0].Pending != 0 {
					t.Fatal(history, err)
				}
			}
		})
	}
}

func TestPushRemindersStagesAndNewAdministrators(t *testing.T) {
	s := reminderStore(t)
	ctx := t.Context()
	now := time.Now()
	if _, err := s.db.Exec(`DELETE FROM uem_access_grants`); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcilePushReminders(ctx, 1, now); err != nil {
		t.Fatal(err)
	}
	h, err := s.PushReminderHistory(ctx, 1)
	if err != nil || len(h) != 1 || h[0].Pending != 0 {
		t.Fatal(h, err)
	}
	if _, err = s.db.Exec(`INSERT INTO uem_access_grants(user_id,role,tenant_id,site_id) VALUES('org','organization_admin',1,0)`); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcilePushReminders(ctx, 1, now); err != nil {
		t.Fatal(err)
	}
	id := reminderID(t, s, "org")
	// Downtime skips both 14-day and 7-day notifications.
	if err = s.reconcilePushReminders(ctx, 1, now.Add(19*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	h, err = s.PushReminderHistory(ctx, 1)
	if err != nil || len(h) != 2 || h[0].Stage != 1 || h[0].Pending != 1 || h[1].ResolvedAt == nil || h[1].Cancelled != 1 {
		t.Fatal(h, err)
	}
	var status string
	if err = s.db.QueryRow(`SELECT status FROM mdm_apple_push_reminder_deliveries WHERE id=$1`, id).Scan(&status); err != nil || status != "cancelled" {
		t.Fatal(status, err)
	}
	if err = s.reconcilePushReminders(ctx, 1, now.Add(21*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	h, err = s.PushReminderHistory(ctx, 1)
	if err != nil || len(h) != 3 || h[0].Stage != 0 || h[0].Pending != 1 {
		t.Fatal(h, err)
	}
}

func TestPushRemindersReplicasAndPermissionLock(t *testing.T) {
	s := reminderStore(t)
	ctx := t.Context()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := s.reconcilePushReminders(ctx, 1, time.Now()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	id := reminderID(t, s, "org")
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	first := make(chan error, 1)
	go func() {
		first <- s.deliverPushReminder(ctx, id, 1, func(context.Context, *sql.Tx, PushExpiryMessage) error {
			calls.Add(1)
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not start")
	}
	locked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	// Production permission mutations use this exact global advisory lock.
	tx, err := s.db.BeginTx(locked, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(locked, `SELECT pg_advisory_xact_lock(684627902)`)
	tx.Rollback()
	cancel()
	if err == nil {
		t.Fatal("permissions could change during delivery")
	}
	for range 3 {
		wg.Go(func() {
			if err := s.deliverPushReminder(ctx, id, 1, func(context.Context, *sql.Tx, PushExpiryMessage) error { calls.Add(1); return nil }); err != nil {
				t.Error(err)
			}
		})
	}
	close(release)
	if err = <-first; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("replicas sent duplicates", calls.Load())
	}
}

func TestPushRemindersSMTPAcceptanceRollbackAndCancellation(t *testing.T) {
	s := reminderStore(t)
	ctx := t.Context()
	if err := s.reconcilePushReminders(ctx, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	id := reminderID(t, s, "org")
	if _, err := s.db.Exec(`CREATE FUNCTION fail_reminder_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.push_expiry.smtp_accepted' THEN RAISE EXCEPTION 'test failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_reminder_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION fail_reminder_audit()`); err != nil {
		t.Fatal(err)
	}
	var ids []string
	send := func(_ context.Context, _ *sql.Tx, m PushExpiryMessage) error { ids = append(ids, m.ID); return nil }
	if err := s.deliverPushReminder(ctx, id, 1, send); err == nil {
		t.Fatal("audit failure did not roll back")
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_reminder_audit ON mdm_apple_audit`); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverPushReminder(ctx, id, 1, send); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatal("ambiguous SMTP retry changed Message-ID", ids)
	}
	id = reminderID(t, s, "admin")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.deliverPushReminder(cancelled, id, 1, send); err == nil {
		t.Fatal("cancelled job succeeded")
	}
	if len(ids) != 2 {
		t.Fatal("cancelled job sent mail")
	}
	if err := s.deliverPushReminder(ctx, id, 1, func(context.Context, *sql.Tx, PushExpiryMessage) error { return ErrReminderSMTPUnavailable }); err != nil {
		t.Fatal(err)
	}
	var code string
	if err := s.db.QueryRow(`SELECT last_error FROM mdm_apple_push_reminder_deliveries WHERE id=$1`, id).Scan(&code); err != nil || !strings.EqualFold(code, "smtp_unavailable") {
		t.Fatal(code, err)
	}
}
