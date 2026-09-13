package admin_views

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestSMTPSettingsViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	for _, scope := range []string{"global", "organization"} {
		base, tenant := "/admin/smtp", "-1"
		if scope == "organization" {
			base, tenant = "/tenant/1/admin/smtp", "1"
		}
		info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: tenant, SiteID: "-1", CSRFToken: "owned-smtp-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
		c := echo.New().NewContext(httptest.NewRequest("GET", base, nil).WithContext(ctx), httptest.NewRecorder())
		for _, kind := range []string{"normal", "empty", "saved", "sent", "unconfirmed", "changed", "long"} {
			review := &consolesettings.SMTPReview{ID: 17, Revision: "10000000-0000-4000-8000-000000000001", PasswordSet: true, Config: consolesettings.SMTPConfig{Server: "smtp.example.invalid", Port: 1587, User: "Owned <SMTP> user", Auth: "PLAIN", From: "owned@example.invalid", Encryption: "starttls"}}
			if kind == "empty" {
				review.PasswordSet = false
			}
			if kind == "sent" || kind == "unconfirmed" || kind == "changed" {
				status := "sent"
				if kind == "unconfirmed" {
					status = "unconfirmed"
				}
				revision := review.Revision
				if kind == "changed" {
					revision = "10000000-0000-4000-8000-000000000009"
				}
				review.LastTest = &consolesettings.SMTPTestResult{ID: "10000000-0000-4000-8000-000000000002", Status: status, Revision: revision, CreatedAt: time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)}
			}
			if kind == "long" {
				review.Config.Server = strings.Repeat("w", 63) + "." + strings.Repeat("x", 63) + ".example.invalid"
				review.Config.User = strings.Repeat("界", 341)
			}
			var body bytes.Buffer
			body.WriteString("<!doctype html><html lang=\"en\" class=\"uk-theme-openuem\"><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"stylesheet\" href=\"/assets/css/main.css\"><script src=\"/assets/js/htmx.min.js\" defer></script></head><body class=\"bg-background text-foreground\"><div id=\"main\">")
			require.NoError(t, SMTPSettings(c, review, info, base, kind == "saved", "10000000-0000-4000-8000-000000000003").Render(ctx, &body))
			body.WriteString("</div></body></html>")
			html := body.String()
			require.Contains(t, html, "Keep stored password")
			require.Contains(t, html, "name=\"csrf\" value=\"owned-smtp-csrf\"")
			require.Contains(t, html, "name=\"confirm\" value=\"send\" required")
			require.NotContains(t, html, "@cmp")
			require.NotContains(t, html, "MISSING")
			if kind == "changed" {
				require.Contains(t, html, "settings have changed since this test")
			}
			if directory := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); directory != "" {
				require.NoError(t, os.MkdirAll(directory, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(directory, fmt.Sprintf("smtp-settings-%s-%s.html", scope, kind)), body.Bytes(), 0600))
			}
		}
	}
}
