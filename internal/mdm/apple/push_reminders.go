package apple

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"time"

	"github.com/google/uuid"
)

// PushReminderSummary contains no recipient addresses or credential material.
// Only organization certificate administrators may read this history.
type PushReminderSummary struct {
	Fingerprint                      string
	Stage                            int
	CreatedAt, ExpiresAt             time.Time
	ResolvedAt                       *time.Time
	Pending, Sent, Cancelled, Failed int
	NextAttemptAt                    *time.Time
}

func (r PushReminderSummary) Label() string {
	if r.Stage == 0 {
		return "Expired"
	}
	if r.Stage == 1 {
		return "Within 1 day"
	}
	return fmt.Sprintf("Within %d days", r.Stage)
}

// PushExpiryMessage is rebuilt from current settings and user records at send
// time. The responsible Apple account is deliberately absent.
type PushExpiryMessage struct {
	ID, Recipient, Organization, Fingerprint string
	TenantID, Stage                          int
	CreatedAt, ExpiresAt                     time.Time
}

// PushReminderSender must honor context cancellation and return a fixed error
// classification. The transaction also supplies the current SMTP configuration.
type PushReminderSender func(context.Context, *sql.Tx, PushExpiryMessage) error

var ErrReminderSMTPUnavailable = errors.New("SMTP configuration is unavailable")

// Certificate metadata is read directly from the public leaf, including legacy
// imports without a recorded connection fingerprint. No key is decrypted.
func pushReminderIdentity(certificate []byte, now time.Time) (string, time.Time, int, error) {
	block, _ := pem.Decode(certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", time.Time{}, -1, ErrPushCertificate
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, -1, ErrPushCertificate
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	stage := -1
	for _, days := range []int{30, 14, 7, 1, 0} {
		if !now.Before(leaf.NotAfter.Add(-time.Duration(days) * 24 * time.Hour)) {
			stage = days
		}
	}
	return hex.EncodeToString(fingerprint[:]), leaf.NotAfter, stage, nil
}

// Keep this predicate aligned with ManageCertificates in security/access.
// Pending, revoked and unverified accounts never receive certificate mail.
const reminderRecipient = `u.email_verified AND u.register IN ('users.completed','users.approved')
 AND EXISTS (SELECT 1 FROM uem_access_grants g WHERE g.user_id=u.uid AND g.site_id=0
 AND ((g.role='administrator' AND g.tenant_id=0) OR (g.role='organization_admin' AND g.tenant_id=$1)))`

func (s *Store) reconcilePushReminders(ctx context.Context, tenant int, now time.Time) error {
	tx, err := s.pushRequestTx(ctx, tenant, "system:push-expiry")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cert []byte
	if err = tx.QueryRowContext(ctx, `SELECT push_certificate FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&cert); err != nil {
		return err
	}
	fingerprint, expires, stage, err := pushReminderIdentity(cert, now)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_reminder_deliveries d SET status='cancelled',last_error='superseded'
 FROM mdm_apple_push_reminders r WHERE d.reminder_id=r.id AND r.tenant_id=$1 AND d.status='pending' AND (r.fingerprint<>$2 OR r.stage<>$3)`, tenant, fingerprint, stage); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_reminders SET resolved_at=COALESCE(resolved_at,$4) WHERE tenant_id=$1 AND (fingerprint<>$2 OR stage<>$3)`, tenant, fingerprint, stage, now); err != nil {
		return err
	}
	if stage < 0 {
		return tx.Commit()
	}
	id := uuid.NewString()
	result, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_push_reminders(id,tenant_id,fingerprint,expires_at,stage,created_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,fingerprint,stage) DO NOTHING`, id, tenant, fingerprint, expires, stage, now)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 1 {
		if err = audit(ctx, tx, tenant, "system:push-expiry", "apple.push_expiry.create", id); err != nil {
			return err
		}
	}
	if err = tx.QueryRowContext(ctx, `UPDATE mdm_apple_push_reminders SET resolved_at=NULL WHERE tenant_id=$1 AND fingerprint=$2 AND stage=$3 RETURNING id`, tenant, fingerprint, stage).Scan(&id); err != nil {
		return err
	}
	// Add newly eligible administrators without repeating successful deliveries.
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_push_reminder_deliveries(id,reminder_id,user_id,next_attempt_at)
 SELECT gen_random_uuid(),$2,u.uid,$3 FROM users u WHERE `+reminderRecipient+`
 ON CONFLICT(reminder_id,user_id) DO UPDATE SET status='pending',last_error='',next_attempt_at=EXCLUDED.next_attempt_at
 WHERE mdm_apple_push_reminder_deliveries.status='cancelled'`, tenant, id, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_reminder_deliveries d SET status='cancelled',last_error='recipient_unavailable'
 WHERE d.reminder_id=$2 AND d.status='pending' AND NOT EXISTS(SELECT 1 FROM users u WHERE u.uid=d.user_id AND `+reminderRecipient+`)`, tenant, id); err != nil {
		return err
	}
	return tx.Commit()
}

func reminderRetry(attempts int) time.Duration {
	if attempts > 8 {
		return 24 * time.Hour
	}
	return min(5*time.Minute*time.Duration(1<<max(0, attempts-1)), 24*time.Hour)
}

func (s *Store) deliverPushReminder(ctx context.Context, id string, tenant int, send PushReminderSender) error {
	// Lock order: organization, global access, delivery, user. This serializes
	// renewal and permission changes with the bounded SMTP operation. A completed
	// revocation is visible before the final recipient check; no stale email is
	// retained in the queue. Lock contention is also bounded by the caller.
	tx, err := s.pushRequestTx(ctx, tenant, "system:push-expiry")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		return err
	}
	var m PushExpiryMessage
	var user, status string
	var attempts int
	var due time.Time
	var resolved *time.Time
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.user_id,d.status,d.attempts,d.next_attempt_at,r.fingerprint,r.stage,r.created_at,r.expires_at,r.resolved_at
 FROM mdm_apple_push_reminder_deliveries d JOIN mdm_apple_push_reminders r ON r.id=d.reminder_id WHERE d.id=$1 AND r.tenant_id=$2 FOR UPDATE OF d`, id, tenant).Scan(&m.ID, &user, &status, &attempts, &due, &m.Fingerprint, &m.Stage, &m.CreatedAt, &m.ExpiresAt, &resolved)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "pending" || time.Now().Before(due) {
		return nil
	}
	cancel := func(reason string) error {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_push_reminder_deliveries SET status='cancelled',last_error=$2 WHERE id=$1`, id, reason); err != nil {
			return err
		}
		return tx.Commit()
	}
	var cert []byte
	m.TenantID = tenant
	if err = tx.QueryRowContext(ctx, `SELECT push_certificate,organization FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&cert, &m.Organization); err != nil {
		return err
	}
	fingerprint, expires, stage, err := pushReminderIdentity(cert, time.Now())
	if err != nil {
		return err
	}
	if resolved != nil || fingerprint != m.Fingerprint || stage != m.Stage || !expires.Equal(m.ExpiresAt) {
		return cancel("superseded")
	}
	err = tx.QueryRowContext(ctx, `SELECT u.email FROM users u WHERE u.uid=$2 AND `+reminderRecipient+` FOR SHARE OF u`, tenant, user).Scan(&m.Recipient)
	if errors.Is(err, sql.ErrNoRows) {
		return cancel("recipient_unavailable")
	}
	if err != nil {
		return err
	}
	address, err := mail.ParseAddress(m.Recipient)
	if err != nil || address.Address != m.Recipient {
		return cancel("recipient_unavailable")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if send == nil {
		return ErrReminderSMTPUnavailable
	}
	err = send(ctx, tx, m)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_reminder_deliveries SET status='sent',sent_at=now(),attempts=attempts+1,last_error='' WHERE id=$1`, id); err != nil {
			return err
		}
		if err = audit(ctx, tx, tenant, "system:push-expiry", "apple.push_expiry.smtp_accepted", id); err != nil {
			return err
		}
	} else {
		code := "smtp_failed"
		if errors.Is(err, ErrReminderSMTPUnavailable) {
			code = "smtp_unavailable"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_reminder_deliveries SET attempts=attempts+1,last_error=$2,next_attempt_at=$3 WHERE id=$1`, id, code, time.Now().Add(reminderRetry(attempts+1))); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PushReminderHistory(ctx context.Context, tenant int) ([]PushReminderSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.fingerprint,r.stage,r.created_at,r.expires_at,r.resolved_at,
 count(d.id) FILTER(WHERE d.status='pending'),count(d.id) FILTER(WHERE d.status='sent'),count(d.id) FILTER(WHERE d.status='cancelled'),
 count(d.id) FILTER(WHERE d.status='pending' AND d.last_error IN ('smtp_unavailable','smtp_failed')),
 min(d.next_attempt_at) FILTER(WHERE d.status='pending')
 FROM mdm_apple_push_reminders r LEFT JOIN mdm_apple_push_reminder_deliveries d ON d.reminder_id=r.id
 WHERE r.tenant_id=$1 GROUP BY r.id ORDER BY r.created_at DESC,r.id LIMIT 25`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []PushReminderSummary
	for rows.Next() {
		var r PushReminderSummary
		if err = rows.Scan(&r.Fingerprint, &r.Stage, &r.CreatedAt, &r.ExpiresAt, &r.ResolvedAt, &r.Pending, &r.Sent, &r.Cancelled, &r.Failed, &r.NextAttemptAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// RunPushReminders is independent of the public Apple listener and NATS. Every
// console replica may run it; PostgreSQL serializes reconciliation and delivery.
func (s *Store) RunPushReminders(ctx context.Context, logger *slog.Logger, send PushReminderSender) {
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		if err := s.pushReminderCycle(ctx, send); err != nil && ctx.Err() == nil {
			// Never log SMTP responses, addresses or credentials.
			logger.Error("Apple push expiry reminder cycle failed; pending deliveries will be retried")
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (s *Store) pushReminderCycle(ctx context.Context, send PushReminderSender) error {
	var lastTenant int
	var firstError error
	for {
		var tenant int
		err := s.db.QueryRowContext(ctx, `SELECT tenant_id FROM mdm_apple_settings WHERE tenant_id>$1 ORDER BY tenant_id LIMIT 1`, lastTenant).Scan(&tenant)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		lastTenant = tenant
		work, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = s.reconcilePushReminders(work, tenant, time.Now())
		cancel()
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	// Materialize a bounded batch before opening delivery transactions.
	rows, err := s.db.QueryContext(ctx, `SELECT d.id,r.tenant_id FROM mdm_apple_push_reminder_deliveries d JOIN mdm_apple_push_reminders r ON r.id=d.reminder_id WHERE d.status='pending' AND d.next_attempt_at<=now() ORDER BY d.next_attempt_at,d.id LIMIT 100`)
	if err != nil {
		return err
	}
	type job struct {
		id     string
		tenant int
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.id, &j.tenant); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		work, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = s.deliverPushReminder(work, j.id, j.tenant, send)
		cancel()
		if err != nil && firstError == nil {
			firstError = err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return firstError
}
