package webserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"sync"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/notifications"
)

type windowsMaintenance interface {
	RunUpdateSchedules(context.Context, *slog.Logger)
	RunCertificateReminders(context.Context, *slog.Logger, windows.CertificateReminderSender)
}

func runWindowsMaintenance(ctx context.Context, logger *slog.Logger, store windowsMaintenance, send windows.CertificateReminderSender) {
	var workers sync.WaitGroup
	workers.Go(func() { store.RunUpdateSchedules(ctx, logger) })
	workers.Go(func() { store.RunCertificateReminders(ctx, logger, send) })
	workers.Wait()
}

func windowsCertificateSender(masterKey string) windows.CertificateReminderSender {
	return func(ctx context.Context, tx *sql.Tx, m windows.CertificateExpiryMessage) error {
		err := notifications.Send(ctx, tx, m.Scope.TenantID, masterKey, windowsCertificateExpiryEmail(m))
		if errors.Is(err, notifications.ErrConfiguration) {
			return windows.ErrCertificateReminderSMTP
		}
		return err
	}
}

func windowsCertificateExpiryEmail(m windows.CertificateExpiryMessage) notifications.Message {
	subject, verb := "Windows device certificate", "expires"
	detail := fmt.Sprintf("Device ID: %s\nSite: %d", m.DeviceID, m.Scope.SiteID)
	switch m.Kind {
	case "issuer_expiry":
		subject, detail = "Windows certificate authority", "CA expiry can prevent certificate validation. Review the authority and device continuity before replacing it."
	case "issuer_issuance":
		subject, verb, detail = "Windows certificate issuance", "ends", "This deadline is earlier than CA expiry: it leaves room for the full device certificate lifetime and a five-minute margin. It does not change existing device certificate expiry."
	}
	status := fmt.Sprintf("%s within %d days", verb, m.Stage)
	if m.Stage == 1 {
		status = verb + " within 1 day"
	}
	if m.Stage == 0 {
		status = "has expired"
		if m.Kind == "issuer_issuance" {
			status = "is unavailable"
		}
	}
	text := fmt.Sprintf("%s %s for OpenUEM organization %d.\n\n%s\nDeadline (UTC): %s\nSHA-256: %s\nAssessed (UTC): %s\n", subject, status, m.Scope.TenantID, detail, m.Deadline.UTC().Format("2006-01-02 15:04:05"), m.Fingerprint, m.AssessedAt.UTC().Format("2006-01-02 15:04:05"))
	if m.PendingReplacement {
		text += "\nAn issued replacement is awaiting confirmation. It has not replaced the current confirmed identity.\n"
	}
	text += "\nOpen Native Windows management, then Certificate health in your OpenUEM console to review current status and renewal history. This reminder does not schedule or perform a renewal.\n\nYou received this reminder because your verified OpenUEM account has certificate administration permission for this organization. SMTP acceptance does not confirm delivery to your inbox."
	return notifications.Message{ID: m.ID, To: m.Recipient, CreatedAt: m.CreatedAt, Subject: "OpenUEM: " + subject + " " + status, Text: text, HTML: "<!doctype html><html lang=\"en\"><body><h1>Windows certificate reminder</h1><div style=\"white-space:pre-wrap;overflow-wrap:anywhere\">" + html.EscapeString(text) + "</div></body></html>"}
}
