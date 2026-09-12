package webserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"sync"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/notifications"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type appleMaintenance interface {
	RunPushReminders(context.Context, *slog.Logger, apple.PushReminderSender)
	RunUpdateSchedules(context.Context, *access.Store, inventory.DeviceSources, *slog.Logger)
}

func runAppleMaintenance(ctx context.Context, logger *slog.Logger, store appleMaintenance, permissions *access.Store, sources inventory.DeviceSources, send apple.PushReminderSender) {
	var workers sync.WaitGroup
	workers.Go(func() { store.RunPushReminders(ctx, logger, send) })
	workers.Go(func() { store.RunUpdateSchedules(ctx, permissions, sources, logger) })
	workers.Wait()
}

func (w *WebServer) startAppleReminders() {
	w.reminderMu.Lock()
	defer w.reminderMu.Unlock()
	if w.reminderCancel != nil {
		return
	}
	if w.Handler.Apple == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.reminderCancel = cancel
	w.reminderDone = make(chan struct{})
	sources := inventory.DeviceSources{Apple: true, Windows: w.Handler.Windows != nil}
	go func() {
		defer close(w.reminderDone)
		runAppleMaintenance(ctx, slog.Default(), w.Handler.Apple, w.Handler.Access, sources, func(ctx context.Context, tx *sql.Tx, m apple.PushExpiryMessage) error {
			message := pushExpiryEmail(m)
			err := notifications.Send(ctx, tx, m.TenantID, w.Handler.EncryptionMasterKey, message)
			if errors.Is(err, notifications.ErrConfiguration) {
				return apple.ErrReminderSMTPUnavailable
			}
			return err
		})
	}()
}

func (w *WebServer) stopAppleReminders() {
	w.reminderMu.Lock()
	cancel, done := w.reminderCancel, w.reminderDone
	w.reminderMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func pushExpiryEmail(m apple.PushExpiryMessage) notifications.Message {
	status := fmt.Sprintf("expires within %d days", m.Stage)
	if m.Stage == 1 {
		status = "expires within 1 day"
	}
	if m.Stage == 0 {
		status = "has expired"
	}
	text := fmt.Sprintf("The Apple MDM push certificate for %s (organization %d) %s.\n\nExpires (UTC): %s\nSHA-256: %s\n\nOpen Apple setup in your OpenUEM console and renew the existing certificate in Apple's Push Certificates Portal with the same Apple account and MDM topic. Import the renewed certificate into OpenUEM. An expired push certificate can prevent devices from receiving management notifications.\n\nYou received this reminder because your verified OpenUEM account has certificate administration permissions for this organization. SMTP acceptance does not confirm delivery to your inbox.", m.Organization, m.TenantID, status, m.ExpiresAt.UTC().Format("2006-01-02 15:04:05"), m.Fingerprint)
	return notifications.Message{ID: m.ID, To: m.Recipient, CreatedAt: m.CreatedAt, Subject: "OpenUEM: Apple push certificate " + status, Text: text, HTML: "<!doctype html><html lang=\"en\"><body><h1>Apple push certificate reminder</h1><div style=\"white-space:pre-wrap;overflow-wrap:anywhere\">" + html.EscapeString(text) + "</div></body></html>"}
}
