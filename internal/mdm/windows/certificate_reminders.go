package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrCertificateReminderSMTP = errors.New("Windows certificate reminder SMTP configuration is unavailable")

// CertificateExpiryMessage is reconstructed under live identity and recipient
// locks. No recipient address, name, certificate bytes or key enters the outbox.
type CertificateExpiryMessage struct {
	ID, Recipient, Kind, DeviceID, Fingerprint string       `json:"-" xml:"-" yaml:"-"`
	Scope                                      access.Scope `json:"-" xml:"-" yaml:"-"`
	Stage                                      int          `json:"-" xml:"-" yaml:"-"`
	CreatedAt, AssessedAt, Deadline            time.Time    `json:"-" xml:"-" yaml:"-"`
	PendingReplacement                         bool         `json:"-" xml:"-" yaml:"-"`
}

func (CertificateExpiryMessage) String() string {
	return "[protected Windows certificate expiry message]"
}
func (v CertificateExpiryMessage) GoString() string { return v.String() }

// CertificateReminderSender must honor cancellation and avoid logging payloads
// or SMTP responses. SMTP acceptance is not inbox delivery or a database commit.
type CertificateReminderSender func(context.Context, *sql.Tx, CertificateExpiryMessage) error

type CertificateReminder struct {
	ID, Kind, ResourceID, AuthorityID, DeviceID, Fingerprint string       `json:"-" xml:"-" yaml:"-"`
	Scope                                                    access.Scope `json:"-" xml:"-" yaml:"-"`
	Stage                                                    int          `json:"-" xml:"-" yaml:"-"`
	Deadline, CreatedAt                                      time.Time    `json:"-" xml:"-" yaml:"-"`
	Pending, Accepted, Canceled, Retrying, SMTPUnavailable   int          `json:"-" xml:"-" yaml:"-"`
	NextAttemptAt                                            *time.Time   `json:"-" xml:"-" yaml:"-"`
}

func (CertificateReminder) String() string     { return "[protected Windows certificate reminder]" }
func (v CertificateReminder) GoString() string { return v.String() }

type storedCertificateReminder struct {
	CertificateReminder
	encrypted []byte
}
type certificateDelivery struct {
	id, reminderID, user, phase, reason string
	revision, attempts                  int64
	created, updated, next              time.Time
	accepted                            *time.Time
	encrypted                           []byte
}

func (certificateDelivery) String() string     { return "[protected Windows certificate delivery]" }
func (d certificateDelivery) GoString() string { return d.String() }

const certificateReminderColumns = `id,tenant_id,site_id,authority_id,COALESCE(device_id::text,''),kind,resource_id,fingerprint,deadline,stage,created_at,encrypted_identity`
const certificateDeliveryColumns = `id,reminder_id,user_id,phase,revision,attempts,created_at,updated_at,next_attempt_at,accepted_at,reason,encrypted_state`

func scanCertificateReminder(row cspScanner) (*storedCertificateReminder, error) {
	r := &storedCertificateReminder{}
	err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.AuthorityID, &r.DeviceID, &r.Kind, &r.ResourceID, &r.Fingerprint, &r.Deadline, &r.Stage, &r.CreatedAt, &r.encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}
func scanCertificateDelivery(row cspScanner) (*certificateDelivery, error) {
	d := &certificateDelivery{}
	err := row.Scan(&d.id, &d.reminderID, &d.user, &d.phase, &d.revision, &d.attempts, &d.created, &d.updated, &d.next, &d.accepted, &d.reason, &d.encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

func certificateReminderPurpose(r *storedCertificateReminder) string {
	return fmt.Sprintf("openuem/windows/certificate-reminder/v1/%s/%d/%d/%s/%s/%s/%s/%s/%s/%d/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.AuthorityID, r.DeviceID, r.Kind, r.ResourceID, r.Fingerprint, r.Deadline.UTC().Format(time.RFC3339Nano), r.Stage, r.CreatedAt.UTC().Format(time.RFC3339Nano))
}
func certificateDeliveryPurpose(d *certificateDelivery) string {
	// A JSON array preserves arbitrary user IDs without delimiter ambiguity.
	accepted := ""
	if d.accepted != nil {
		accepted = d.accepted.UTC().Format(time.RFC3339Nano)
	}
	data, _ := json.Marshal([]any{d.id, d.reminderID, d.user, d.phase, d.revision, d.attempts, d.created.UTC(), d.updated.UTC(), d.next.UTC(), accepted, d.reason})
	h := sha256.Sum256(data)
	return fmt.Sprintf("openuem/windows/certificate-delivery/v1/%x", h)
}
func (s *Store) verifyCertificateReminder(r *storedCertificateReminder) error {
	plain, err := s.secrets.open(r.encrypted, certificateReminderPurpose(r))
	defer clear(plain)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain, []byte("certificate-reminder-v1")) {
		return ErrAuthoritySecret
	}
	return nil
}
func (s *Store) verifyCertificateDelivery(d *certificateDelivery) error {
	plain, err := s.secrets.open(d.encrypted, certificateDeliveryPurpose(d))
	defer clear(plain)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain, []byte("certificate-delivery-v1")) {
		return ErrAuthoritySecret
	}
	return nil
}
func certificateReminderStage(deadline, now time.Time) int {
	stage := -1
	for _, days := range []int{30, 14, 7, 1, 0} {
		if !now.Before(deadline.Add(-time.Duration(days) * 24 * time.Hour)) {
			stage = days
		}
	}
	return stage
}
func certificateReminderRetry(attempts int64) time.Duration {
	if attempts > 8 {
		return 24 * time.Hour
	}
	return min(5*time.Minute*time.Duration(1<<max(0, attempts-1)), 24*time.Hour)
}

const certificateReminderRecipient = `u.email_verified AND u.register IN ('users.completed','users.approved')
 AND EXISTS(SELECT 1 FROM uem_access_grants g WHERE g.user_id=u.uid AND g.site_id=0
 AND ((g.role='administrator' AND g.tenant_id=0) OR (g.role='organization_admin' AND g.tenant_id=$1)))`

func certificateReminderLock(ctx context.Context, tx *sql.Tx, kind, source string) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627902)`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,684627956))`, "windows-certificate-reminder/"+kind+"/"+source)
	return err
}

type certificateReminderSource struct {
	CertificateReminder
	now     time.Time
	pending bool
}

// The device row is locked before selecting its current generation. All writers
// that confirm, cancel or retire a native identity serialize with this read.
func (s *Store) certificateReminderSource(ctx context.Context, tx *sql.Tx, kind, source string) (*certificateReminderSource, error) {
	if kind != "device_expiry" && kind != "issuer_expiry" && kind != "issuer_issuance" {
		return nil, ErrConsoleInput
	}
	r := &certificateReminderSource{CertificateReminder: CertificateReminder{Kind: kind}}
	if kind == "device_expiry" {
		err := tx.QueryRowContext(ctx, `SELECT tenant_id,site_id FROM mdm_windows_devices WHERE id=$1`, source).Scan(&r.Scope.TenantID, &r.Scope.SiteID)
		if err != nil {
			return nil, err
		}
		if err := lockEnrollmentScope(ctx, tx, r.Scope); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, nil
			}
			return nil, err
		}
		var revoked *time.Time
		if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM mdm_windows_devices WHERE id=$1 FOR SHARE`, source).Scan(&revoked); err != nil {
			return nil, err
		}
		if revoked != nil {
			return nil, nil
		}
		if err := tx.QueryRowContext(ctx, `SELECT c.id,c.authority_id`+deviceMetadataJoin+`WHERE d.id=$1 AND d.tenant_id=$2 AND d.site_id=$3`, source, r.Scope.TenantID, r.Scope.SiteID).Scan(&r.ResourceID, &r.AuthorityID); err != nil {
			return nil, err
		}
		r.DeviceID = source
	} else {
		r.AuthorityID, r.ResourceID = source, source
		if err := tx.QueryRowContext(ctx, `SELECT a.tenant_id FROM mdm_windows_authorities a JOIN tenants t ON t.id=a.tenant_id WHERE a.id=$1 FOR SHARE OF t`, source).Scan(&r.Scope.TenantID); err != nil {
			return nil, err
		}
	}
	a, err := scanAuthority(tx.QueryRowContext(ctx, `SELECT `+authorityColumns+` FROM mdm_windows_authorities WHERE id=$1 AND tenant_id=$2 FOR SHARE`, r.AuthorityID, r.Scope.TenantID))
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	if err := tx.QueryRowContext(ctx, `SELECT encrypted_key FROM mdm_windows_authorities WHERE id=$1`, a.ID).Scan(&encrypted); err != nil {
		return nil, err
	}
	signer, err := s.authenticateAuthority(*a, encrypted)
	if err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.now); err != nil {
		return nil, err
	}
	if kind == "device_expiry" {
		health, err := s.deviceCertificateHealth(ctx, tx, r.Scope, source, r.ResourceID, *a, r.now, 30, "")
		if err != nil {
			return nil, err
		}
		if health.Current.RevokedAt != nil {
			return nil, nil
		}
		r.Fingerprint, r.Deadline = health.Current.FingerprintSHA256, health.Current.ExpiresAt
		r.pending = health.Pending != nil
	} else {
		r.Fingerprint, r.Deadline = a.FingerprintSHA256, signer.certificate.NotAfter
		if kind == "issuer_issuance" {
			r.Deadline = r.Deadline.Add(-time.Duration(a.ValiditySeconds)*time.Second - 5*time.Minute)
		}
	}
	// Any certificate/history lock waits above precede the final stage check.
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.now); err != nil {
		return nil, err
	}
	r.Stage = certificateReminderStage(r.Deadline, r.now)
	return r, nil
}

func auditCertificateReminder(ctx context.Context, tx *sql.Tx, rid, did, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_certificate_reminder_audit(reminder_id,delivery_id,actor,action) VALUES($1,NULLIF($2,'')::uuid,$3,$4)`, rid, did, actor, action)
	return err
}

func (s *Store) saveCertificateDelivery(ctx context.Context, tx *sql.Tx, d *certificateDelivery, action string) error {
	var err error
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&d.updated); err != nil {
		return err
	}
	if d.updated.Before(d.created) {
		return ErrCSPDeadline
	}
	d.revision++
	if d.phase == "accepted" {
		d.accepted = &d.updated
	}
	d.encrypted, err = s.secrets.seal([]byte("certificate-delivery-v1"), certificateDeliveryPurpose(d))
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE mdm_windows_certificate_deliveries SET phase=$2,revision=$3,attempts=$4,updated_at=$5,next_attempt_at=$6,accepted_at=$7,reason=$8,encrypted_state=$9 WHERE id=$1 AND revision=$10`, d.id, d.phase, d.revision, d.attempts, d.updated, d.next, d.accepted, d.reason, d.encrypted, d.revision-1)
	if err := syncMLUpdated(result, err); err != nil {
		return err
	}
	return auditCertificateReminder(ctx, tx, d.reminderID, d.id, "system:windows-expiry", action)
}

func (s *Store) reconcileCertificateReminder(ctx context.Context, kind, source string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := certificateReminderLock(ctx, tx, kind, source); err != nil {
		return err
	}
	live, err := s.certificateReminderSource(ctx, tx, kind, source)
	if err != nil {
		return err
	}
	if err := s.cancelSupersededCertificateReminders(ctx, tx, kind, source, live); err != nil {
		return err
	}
	if live == nil || live.Stage < 0 {
		return tx.Commit()
	}
	r, err := scanCertificateReminder(tx.QueryRowContext(ctx, `SELECT `+certificateReminderColumns+` FROM mdm_windows_certificate_reminders WHERE kind=$1 AND resource_id=$2 AND stage=$3`, kind, live.ResourceID, live.Stage))
	if errors.Is(err, ErrNotFound) {
		r = &storedCertificateReminder{CertificateReminder: live.CertificateReminder}
		r.ID, r.CreatedAt = uuid.NewString(), live.now
		r.encrypted, err = s.secrets.seal([]byte("certificate-reminder-v1"), certificateReminderPurpose(r))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_certificate_reminders(id,tenant_id,site_id,authority_id,device_id,kind,resource_id,fingerprint,deadline,stage,created_at,encrypted_identity) VALUES($1,$2,$3,$4,NULLIF($5,'')::uuid,$6,$7,$8,$9,$10,$11,$12)`, r.ID, r.Scope.TenantID, r.Scope.SiteID, r.AuthorityID, r.DeviceID, r.Kind, r.ResourceID, r.Fingerprint, r.Deadline, r.Stage, r.CreatedAt, r.encrypted)
		if err != nil {
			return err
		}
		if err := auditCertificateReminder(ctx, tx, r.ID, "", "system:windows-expiry", "reminder.created"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err := s.verifyCertificateReminder(r); err != nil {
		return err
	}
	if r.Fingerprint != live.Fingerprint || !r.Deadline.Equal(live.Deadline) || r.Scope != live.Scope || r.DeviceID != live.DeviceID {
		return ErrAuthoritySecret
	}
	rows, err := tx.QueryContext(ctx, `SELECT u.uid,COALESCE(u.email,'') FROM users u WHERE `+certificateReminderRecipient+` ORDER BY u.uid`, r.Scope.TenantID)
	if err != nil {
		return err
	}
	users := []string{}
	for rows.Next() {
		var user, recipient string
		if err = rows.Scan(&user, &recipient); err != nil {
			rows.Close()
			return err
		}
		address, err := mail.ParseAddress(recipient)
		if err == nil && address.Address == recipient {
			users = append(users, user)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, user := range users {
		d, err := scanCertificateDelivery(tx.QueryRowContext(ctx, `SELECT `+certificateDeliveryColumns+` FROM mdm_windows_certificate_deliveries WHERE reminder_id=$1 AND user_id=$2 FOR UPDATE`, r.ID, user))
		if errors.Is(err, ErrNotFound) {
			d = &certificateDelivery{id: uuid.NewString(), reminderID: r.ID, user: user, phase: "pending", revision: 1, created: live.now, updated: live.now, next: live.now}
			d.encrypted, err = s.secrets.seal([]byte("certificate-delivery-v1"), certificateDeliveryPurpose(d))
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_certificate_deliveries(id,reminder_id,user_id,phase,revision,attempts,created_at,updated_at,next_attempt_at,reason,encrypted_state) VALUES($1,$2,$3,'pending',1,0,$4,$4,$4,'',$5)`, d.id, d.reminderID, d.user, d.created, d.encrypted)
			if err != nil {
				return err
			}
			if err := auditCertificateReminder(ctx, tx, r.ID, d.id, "system:windows-expiry", "delivery.created"); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			if err := s.verifyCertificateDelivery(d); err != nil {
				return err
			}
			if d.phase == "canceled" && d.reason == "recipient_unavailable" {
				d.phase, d.reason, d.next = "pending", "", live.now
				if err := s.saveCertificateDelivery(ctx, tx, d, "delivery.resumed"); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func (s *Store) cancelSupersededCertificateReminders(ctx context.Context, tx *sql.Tx, kind, source string, live *certificateReminderSource) error {
	rows, err := tx.QueryContext(ctx, `SELECT d.id FROM mdm_windows_certificate_deliveries d JOIN mdm_windows_certificate_reminders r ON r.id=d.reminder_id WHERE r.kind=$1 AND (CASE WHEN r.kind='device_expiry' THEN r.device_id ELSE r.authority_id END)=$2::uuid AND d.phase='pending' ORDER BY d.id`, kind, source)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		d, err := scanCertificateDelivery(tx.QueryRowContext(ctx, `SELECT `+certificateDeliveryColumns+` FROM mdm_windows_certificate_deliveries WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if err := s.verifyCertificateDelivery(d); err != nil {
			return err
		}
		r, err := scanCertificateReminder(tx.QueryRowContext(ctx, `SELECT `+certificateReminderColumns+` FROM mdm_windows_certificate_reminders WHERE id=$1`, d.reminderID))
		if err != nil {
			return err
		}
		if err := s.verifyCertificateReminder(r); err != nil {
			return err
		}
		if live == nil || live.Stage < 0 || r.ResourceID != live.ResourceID || r.Stage != live.Stage {
			d.phase, d.reason = "canceled", "superseded"
			if err := s.saveCertificateDelivery(ctx, tx, d, "delivery.canceled"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) deliverCertificateReminder(ctx context.Context, id string, send CertificateReminderSender) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	before, err := scanCertificateReminder(tx.QueryRowContext(ctx, `SELECT `+certificateReminderColumns+` FROM mdm_windows_certificate_reminders WHERE id=(SELECT reminder_id FROM mdm_windows_certificate_deliveries WHERE id=$1)`, id))
	if err != nil {
		return err
	}
	if err := s.verifyCertificateReminder(before); err != nil {
		return err
	}
	source := before.AuthorityID
	if before.Kind == "device_expiry" {
		source = before.DeviceID
	}
	if err := certificateReminderLock(ctx, tx, before.Kind, source); err != nil {
		return err
	}
	live, err := s.certificateReminderSource(ctx, tx, before.Kind, source)
	if err != nil {
		return err
	}
	d, err := scanCertificateDelivery(tx.QueryRowContext(ctx, `SELECT `+certificateDeliveryColumns+` FROM mdm_windows_certificate_deliveries WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return err
	}
	if err := s.verifyCertificateDelivery(d); err != nil {
		return err
	}
	if d.reminderID != before.ID {
		return ErrAuthoritySecret
	}
	if d.phase != "pending" {
		return nil
	}
	finish := func(reason string) error {
		d.phase, d.reason = "canceled", reason
		if err := s.saveCertificateDelivery(ctx, tx, d, "delivery.canceled"); err != nil {
			return err
		}
		return tx.Commit()
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if now.Before(d.updated) || now.Before(before.CreatedAt) {
		return ErrCSPDeadline
	}
	if live == nil || live.ResourceID != before.ResourceID || live.Fingerprint != before.Fingerprint || !live.Deadline.Equal(before.Deadline) || live.Scope != before.Scope || certificateReminderStage(before.Deadline, now) != before.Stage {
		return finish("superseded")
	}
	var recipient string
	err = tx.QueryRowContext(ctx, `SELECT u.email FROM users u WHERE u.uid=$2 AND `+certificateReminderRecipient+` FOR SHARE OF u`, before.Scope.TenantID, d.user).Scan(&recipient)
	if errors.Is(err, sql.ErrNoRows) {
		return finish("recipient_unavailable")
	}
	if err != nil {
		return err
	}
	address, err := mail.ParseAddress(recipient)
	if err != nil || address.Address != recipient {
		return finish("recipient_unavailable")
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, d.user, access.ManageCertificates, before.Scope); err != nil {
		if errors.Is(err, access.ErrDenied) {
			return finish("recipient_unavailable")
		}
		return err
	}
	// Recipient locks can wait past a stage boundary. Check database time again
	// immediately before the bounded external operation.
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if now.Before(d.updated) || now.Before(before.CreatedAt) {
		return ErrCSPDeadline
	}
	if certificateReminderStage(before.Deadline, now) != before.Stage {
		return finish("superseded")
	}
	if now.Before(d.next) {
		return nil
	}
	if d.attempts >= 2147483647 {
		return ErrCSPDeadline
	}
	m := CertificateExpiryMessage{ID: d.id, Recipient: recipient, Kind: before.Kind, DeviceID: before.DeviceID, Fingerprint: before.Fingerprint, Scope: before.Scope, Stage: before.Stage, CreatedAt: before.CreatedAt, AssessedAt: now, Deadline: before.Deadline, PendingReplacement: live.pending}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	err = ErrCertificateReminderSMTP
	if send != nil {
		err = send(ctx, tx, m)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	d.attempts++
	if err == nil {
		d.phase, d.reason = "accepted", ""
		if err := s.saveCertificateDelivery(ctx, tx, d, "delivery.accepted"); err != nil {
			return err
		}
	} else {
		d.reason = "smtp_failed"
		if errors.Is(err, ErrCertificateReminderSMTP) {
			d.reason = "smtp_unavailable"
		}
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		d.next = now.Add(certificateReminderRetry(d.attempts))
		if err := s.saveCertificateDelivery(ctx, tx, d, "delivery.retry"); err != nil {
			return err
		}
	}
	return tx.Commit()
}
