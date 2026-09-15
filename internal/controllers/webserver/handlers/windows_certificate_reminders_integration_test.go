package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsCertificateReminders(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	admin := "renewal-organization-admin"
	if _, err := h.Model.DB.ExecContext(ctx, `UPDATE users SET email_verified=true,register='users.completed' WHERE uid=$1`, admin); err != nil {
		t.Fatal(err)
	}
	work, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Windows.RunCertificateReminders(work, slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context, *sql.Tx, windows.CertificateExpiryMessage) error {
			return windows.ErrCertificateReminderSMTP
		})
	}()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		history, err := h.Windows.CertificateReminders(ctx, admin, scope, 0, 25)
		if err != nil {
			t.Fatal(err)
		}
		if len(history) > 0 && history[0].Retrying > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("synthetic worker did not persist a missing-SMTP retry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	path := fmt.Sprintf("/tenant/%d/site/%d/windows/certificate-reminders", scope.TenantID, scope.SiteID)
	for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", scope.TenantID), fmt.Sprintf("/tenant/%d/site/%d", scope.TenantID, scope.SiteID)} {
		for _, user := range []string{"renewal-viewer", "renewal-operator"} {
			if w := request(user, "GET", prefix+"/windows/certificate-reminders", nil); w.Code != 403 {
				t.Fatal("nonadministrator reached reminder history", user, w.Code)
			}
		}
		w := request(admin, "GET", prefix+"/windows/certificate-reminders", nil)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("reminder route unavailable or cacheable", w.Code)
		}
		for _, want := range []string{"Device certificate expiry", "Within 1 day", "Deliveries awaiting retry", "valid SMTP settings.", "Next pending attempt:", "SMTP accepted"} {
			if !strings.Contains(w.Body.String(), want) {
				t.Fatal("reminder history missing", want)
			}
		}
		if strings.Contains(w.Body.String(), "@example.test") || strings.Contains(w.Body.String(), "owin1.") || strings.Contains(w.Body.String(), "PRIVATE KEY") {
			t.Fatal("reminder route exposed private metadata")
		}
		artifact("windows-certificate-reminders-retry", w)
	}
	for _, suffix := range []string{"?", "?offset=", "?offset=01", "?offset=-1", "?offset=100001", "?offset=1&offset=2", "?q=private", "?offset=%zz"} {
		if w := request(admin, "GET", path+suffix, nil); w.Code != 400 {
			t.Fatal("invalid reminder history query admitted", suffix, w.Code)
		}
	}
	for _, target := range []string{path + "?offset=1", fmt.Sprintf("/tenant/%d/site/%d/windows/certificate-reminders", scope.TenantID, sibling)} {
		w := request(admin, "GET", target, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "No certificate reminders in this view.") {
			t.Fatal("reminder page or sibling scope leaked history", w.Code)
		}
	}
	if w := request("organization-admin", "GET", path, nil); w.Code != 404 {
		t.Fatal("foreign organization read reminders", w.Code)
	}
	if w := request(admin, "GET", fmt.Sprintf("/tenant/%d/site/%d/windows/certificate-health", scope.TenantID, scope.SiteID), nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Expiry reminder history") {
		t.Fatal("health view omitted reminder history link", w.Code)
	}
}
