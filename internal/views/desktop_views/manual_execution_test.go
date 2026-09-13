package desktop_views

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestManualExecutionViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-manual-admin")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "2", CSRFToken: "owned-manual-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/2/computers/owned-endpoint/execution", nil).WithContext(ctx), httptest.NewRecorder())
	target := inventory.ManualTarget{ID: "owned-endpoint", Name: "Owned <endpoint>", Platform: "windows", Scope: access.Scope{TenantID: 1, SiteID: 2}}
	instant := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"choices-task", "choices-profile", "choices-empty", "choices-pending", "choices-long", "review-task", "review-profile", "review-long", "queued", "sending", "accepted", "rejected", "stopped", "unconfirmed"} {
		t.Run(kind, func(t *testing.T) {
			var component templ.Component
			source := inventory.ManualSource{ID: 17, ProfileID: 7, Name: "Owned <task>", ProfileName: "Owned <profile>", Kind: "task", Version: 3, Revision: strings.Repeat("a", 64), TaskCount: 2, Scope: access.Scope{TenantID: 1}}
			if strings.Contains(kind, "profile") {
				source.Kind = "profile"
				source.ID = 7
				source.Name = source.ProfileName
			}
			if strings.HasSuffix(kind, "long") {
				source.Name = strings.Repeat("W", 512)
				source.ProfileName = strings.Repeat("界", 512)
			}
			switch {
			case strings.HasPrefix(kind, "choices"):
				page := &inventory.ManualChoices{Target: target, Kind: source.Kind, Search: "Owned %_", Sources: []inventory.ManualSource{source}, More: true}
				if kind == "choices-empty" {
					page.Sources = nil
					page.More = false
				}
				if kind == "choices-pending" {
					page.Latest = &inventory.ManualRequest{ID: "10000000-0000-4000-8000-000000000001", Status: "queued", AttemptedAt: &instant}
				}
				component = ManualChoices(c, info, page)
			case strings.HasPrefix(kind, "review"):
				component = ManualReview(c, info, &inventory.ManualReview{Target: target, Source: source}, "10000000-0000-4000-8000-000000000001", "Owned %_")
			default:
				request := &inventory.ManualRequest{ID: "10000000-0000-4000-8000-000000000001", DeviceID: target.ID, Kind: "task", Scope: target.Scope, SourceID: 17, ProfileID: 7, Status: kind, RequestedAt: instant, ExpiresAt: instant.Add(2 * time.Minute)}
				if kind == "sending" {
					request.Status = "queued"
					request.AttemptedAt = &instant
				}
				if kind != "queued" && kind != "sending" {
					request.FinishedAt = &instant
				}
				if kind == "unconfirmed" {
					request.Reason = "delivery_unconfirmed"
				}
				component = ManualReceipt(c, info, request)
			}
			var body bytes.Buffer
			body.WriteString("<!doctype html><html class=\"uk-theme-openuem\"><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"stylesheet\" href=\"/assets/css/main.css\"><script src=\"/assets/js/htmx.min.js\" defer></script><script src=\"/assets/js/timestamps.js\" defer></script></head><body class=\"bg-background text-foreground\"><main id=\"main\">")
			require.NoError(t, component.Render(ctx, &body))
			body.WriteString("</main></body></html>")
			html := body.String()
			require.NotContains(t, html, "manual_execution.")
			require.NotContains(t, html, "executed successfully")
			require.Equal(t, 1, strings.Count(html, "id=\"manual-execution-heading\""))
			if strings.HasPrefix(kind, "review") {
				require.Contains(t, html, "name=\"confirmed\" value=\"yes\" required")
				require.Contains(t, html, "name=\"request_id\" value=\"10000000-0000-4000-8000-000000000001\"")
				require.Contains(t, html, "name=\"revision\" value=\""+source.Revision+"\"")
				require.Contains(t, html, "name=\"csrf\" value=\"owned-manual-csrf\"")
				require.NotContains(t, html, " checked")
				require.Contains(t, html, "q=Owned+%25_")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("manual-execution-%s.html", kind)), body.Bytes(), 0600))
			}
		})
	}
}

func TestDesktopTaskHistoryViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "2", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/2/computers/owned-endpoint/tasks?page=2&pageSize=5", nil).WithContext(ctx), httptest.NewRecorder())
	instant := time.Date(2026, 9, 13, 12, 0, 0, 123456789, time.UTC)
	for _, kind := range []string{"normal", "empty", "missing", "disabled", "long"} {
		page := &inventory.DesktopTasksPage{Target: inventory.ManualTarget{ID: "owned-endpoint", Name: "Owned <endpoint>", Platform: "windows", Scope: access.Scope{TenantID: 1, SiteID: 2}}, Status: "Enabled", Page: 2, PageSize: 5, Total: 11, Reports: []inventory.DesktopTaskReport{{ProfileIssueReport: inventory.ProfileIssueReport{ID: 27, TaskID: 17, TaskName: "Owned <task>", Failed: true, Output: "Owned <stdout>", Error: "Owned <stderr>", End: &instant}, ProfileID: 7, ProfileName: "Owned <profile>", ProfileScope: access.Scope{TenantID: 1}, CanReview: true}}}
		switch kind {
		case "empty":
			page.Reports = nil
			page.Total = 0
			page.Page = 1
		case "missing":
			page.Reports[0].TaskID = 0
			page.Reports[0].ProfileID = 0
			page.Reports[0].CanReview = false
			page.Reports[0].End = nil
			page.Reports[0].RawEnd = "Owned invalid time"
		case "disabled":
			page.Status = "Disabled"
			page.Reports[0].TaskDisabled = true
			page.Reports[0].CanReview = false
		case "long":
			page.Reports[0].TaskName = strings.Repeat("W", 512)
			page.Reports[0].ProfileName = strings.Repeat("界", 512)
			page.Reports[0].Output = strings.Repeat("界", 4096)
			page.Reports[0].Error = strings.Repeat("E", 4096)
			page.Reports[0].OutputTruncated = true
			page.Reports[0].ErrorTruncated = true
		}
		var body bytes.Buffer
		body.WriteString("<!doctype html><html class=\"uk-theme-openuem\"><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"stylesheet\" href=\"/assets/css/main.css\"><script src=\"/assets/js/htmx.min.js\" defer></script><script src=\"/assets/js/timestamps.js\" defer></script></head><body class=\"bg-background text-foreground\"><main id=\"main\">")
		require.NoError(t, TaskHistory(c, info, page).Render(ctx, &body))
		body.WriteString("</main></body></html>")
		require.NotContains(t, body.String(), "manual_execution.")
		if kind != "empty" {
			require.Contains(t, body.String(), "Reported result")
			require.Contains(t, body.String(), "Failed")
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "desktop-task-history-"+kind+".html"), body.Bytes(), 0600))
		}
	}
}
