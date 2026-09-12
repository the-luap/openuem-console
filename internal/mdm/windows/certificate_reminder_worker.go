package windows

import (
	"context"
	"log/slog"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// A cursor rotates failed due deliveries rather than allowing one corrupt batch
// to starve later work. PostgreSQL advisory locks serialize concurrent replicas.
type certificateReminderCursor struct {
	due time.Time
	id  string
}

func (s *Store) RunCertificateReminders(ctx context.Context, logger *slog.Logger, send CertificateReminderSender) {
	if logger == nil {
		logger = slog.Default()
	}
	if s == nil || s.db == nil || s.secrets == nil {
		logger.Error("Windows certificate reminders require the encrypted registry")
		return
	}
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	cursor := certificateReminderCursor{}
	for {
		if err := s.certificateReminderCycle(ctx, send, &cursor); err != nil && ctx.Err() == nil {
			logger.Error("Windows certificate reminder cycle failed; remaining work will be retried")
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (s *Store) certificateReminderCycle(ctx context.Context, send CertificateReminderSender, cursor *certificateReminderCursor) error {
	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	for _, kind := range []string{"issuer_expiry", "issuer_issuance", "device_expiry"} {
		table := "mdm_windows_authorities"
		if kind == "device_expiry" {
			table = "mdm_windows_devices"
		}
		var upper string
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(max(id::text),'') FROM `+table).Scan(&upper); err != nil {
			return err
		}
		last := ""
		for upper != "" {
			rows, err := s.db.QueryContext(ctx, `SELECT id::text FROM `+table+` WHERE id>COALESCE(NULLIF($1,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) AND id<=$2::uuid ORDER BY id LIMIT 50`, last, upper)
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
			if len(ids) == 0 {
				break
			}
			for _, id := range ids {
				work, cancel := context.WithTimeout(ctx, 15*time.Second)
				record(s.reconcileCertificateReminder(work, kind, id))
				cancel()
				last = id
				if ctx.Err() != nil {
					return ctx.Err()
				}
			}
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,next_attempt_at FROM mdm_windows_certificate_deliveries WHERE phase='pending' AND next_attempt_at<=clock_timestamp() AND ($1::timestamptz IS NULL OR (next_attempt_at,id)>($1,NULLIF($2,'')::uuid)) ORDER BY next_attempt_at,id LIMIT 100`, nullableReminderTime(cursor.due), cursor.id)
	if err != nil {
		return err
	}
	type job struct {
		id  string
		due time.Time
	}
	jobs := []job{}
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.id, &j.due); err != nil {
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
		record(s.deliverCertificateReminder(work, j.id, send))
		cancel()
		cursor.due, cursor.id = j.due, j.id
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if len(jobs) < 100 {
		*cursor = certificateReminderCursor{}
	}
	return firstError
}
func nullableReminderTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// CertificateReminders returns bounded, authenticated history without recipient
// identities. An organization-wide read still needs an organization-wide grant.
func (s *Store) CertificateReminders(ctx context.Context, actor string, scope access.Scope, offset, limit int) ([]CertificateReminder, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !validConsolePage(offset, limit) {
		return nil, ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeConsole(ctx, tx, actor, scope, access.ReadDevices); err != nil {
		return nil, err
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageCertificates, scope); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.id FROM mdm_windows_certificate_reminders r LEFT JOIN sites site ON site.id=r.site_id AND site.tenant_sites=r.tenant_id WHERE r.tenant_id=$1 AND ($2::bigint=0 OR r.site_id=0 OR r.site_id=$2) AND (r.site_id=0 OR site.id IS NOT NULL) ORDER BY r.created_at DESC,r.id LIMIT $3 OFFSET $4`, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []CertificateReminder{}
	for _, id := range ids {
		r, err := scanCertificateReminder(tx.QueryRowContext(ctx, `SELECT `+certificateReminderColumns+` FROM mdm_windows_certificate_reminders WHERE id=$1 AND tenant_id=$2`, id, scope.TenantID))
		if err != nil {
			return nil, err
		}
		if err := s.verifyCertificateReminder(r); err != nil {
			return nil, err
		}
		if r.Scope.SiteID > 0 {
			if err := lockEnrollmentScope(ctx, tx, r.Scope); err != nil {
				return nil, err
			}
		}
		deliveries, err := tx.QueryContext(ctx, `SELECT `+certificateDeliveryColumns+` FROM mdm_windows_certificate_deliveries WHERE reminder_id=$1 ORDER BY id`, id)
		if err != nil {
			return nil, err
		}
		for deliveries.Next() {
			d, err := scanCertificateDelivery(deliveries)
			if err != nil {
				deliveries.Close()
				return nil, err
			}
			if err := s.verifyCertificateDelivery(d); err != nil {
				deliveries.Close()
				return nil, err
			}
			switch d.phase {
			case "pending":
				r.Pending++
				if d.reason == "smtp_unavailable" || d.reason == "smtp_failed" {
					r.Retrying++
					if d.reason == "smtp_unavailable" {
						r.SMTPUnavailable++
					}
				}
				if r.NextAttemptAt == nil || d.next.Before(*r.NextAttemptAt) {
					next := d.next
					r.NextAttemptAt = &next
				}
			case "accepted":
				r.Accepted++
			case "canceled":
				r.Canceled++
			default:
				deliveries.Close()
				return nil, ErrAuthoritySecret
			}
		}
		err = deliveries.Err()
		deliveries.Close()
		if err != nil {
			return nil, err
		}
		if err := auditCertificateReminder(ctx, tx, id, "", actor, "reminder.read"); err != nil {
			return nil, err
		}
		result = append(result, r.CertificateReminder)
	}
	if err := auditWindowsConsole(ctx, tx, actor, scope, "certificate_reminders.read", ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
