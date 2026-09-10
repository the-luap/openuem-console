package windows_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestWindowsCertificateReminderViewsSeparateDeadlineAndDelivery(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "synthetic-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "-1", CSRFToken: "synthetic-csrf"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/windows/certificate-reminders", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 10, 12, 13, 14, 123456000, time.UTC)
	for _, state := range []string{"mixed", "empty"} {
		history := []windows.CertificateReminder{}
		if state == "mixed" {
			history = []windows.CertificateReminder{
				{ID: "<script>synthetic</script>", Kind: "device_expiry", DeviceID: "10000000-0000-4000-8000-000000000001", Fingerprint: strings.Repeat("ab", 32), Scope: access.Scope{TenantID: 1, SiteID: 11}, Stage: 1, CreatedAt: now, Deadline: now.Add(time.Hour), Accepted: 2, Pending: 3, Retrying: 2, SMTPUnavailable: 1, Canceled: 1, NextAttemptAt: &now},
				{ID: "issuer-issuance", Kind: "issuer_issuance", Fingerprint: strings.Repeat("cd", 32), Scope: access.Scope{TenantID: 1}, Stage: 0, CreatedAt: now, Deadline: now},
				{ID: "issuer-expiry", Kind: "issuer_expiry", Fingerprint: strings.Repeat("ef", 32), Scope: access.Scope{TenantID: 1}, Stage: 30, CreatedAt: now, Deadline: now.Add(30 * 24 * time.Hour)},
			}
		}
		var out bytes.Buffer
		if err := CertificateReminders(c, info, history, 25, true).Render(ctx, &out); err != nil {
			t.Fatal(err)
		}
		html := out.String()
		for _, want := range []string{"Windows certificate expiry reminders", "SMTP acceptance does not prove inbox delivery", "/tenant/1/windows/certificate-reminders?offset=0", "/tenant/1/windows/certificate-reminders?offset=50", "Current certificate health"} {
			if !strings.Contains(html, want) {
				t.Fatal("reminder navigation or evidence boundary missing", want)
			}
		}
		if state == "mixed" {
			for _, want := range []string{"Device certificate expiry", "Within 1 day", "Full-lifetime issuance deadline", "Deadline reached", "CA certificate expiry", "Within 30 days", "No eligible recipient has been queued", "1 pending delivery needs valid SMTP settings.", "&lt;script&gt;synthetic&lt;/script&gt;", "/tenant/1/site/11/windows/10000000-0000-4000-8000-000000000001/renewals"} {
				if !strings.Contains(html, want) {
					t.Fatal("reminder status missing", want)
				}
			}
		}
		if strings.Contains(html, "<script>synthetic</script>") || strings.Contains(html, `method="post"`) {
			t.Fatal("reminder view failed escaping or offered unrequested mutation")
		}
		if state == "empty" && !strings.Contains(html, "No certificate reminders in this view.") {
			t.Fatal("empty reminder view missing")
		}
		if dir := os.Getenv("OPENUEM_WINDOWS_REMINDER_UI_ARTIFACTS"); dir != "" {
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "reminders-"+state+".html"), out.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
