package mdm_views

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
	"github.com/stretchr/testify/require"
)

func TestProfileIssueHistoryViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	instant := time.Date(2026, 3, 29, 1, 30, 45, 123456789, time.UTC)
	for scope, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}} {
		for _, kind := range []string{"list", "list-orphan", "list-empty", "reports", "reports-orphan", "reports-empty", "reports-long"} {
			issue := inventory.ProfileIssueSummary{ID: 27, When: &instant, EndpointID: "owned-endpoint", EndpointName: "Owned <endpoint>", EndpointState: "available", EndpointScope: access.Scope{TenantID: 1, SiteID: 2}, Reports: 26, Failed: 1}
			if strings.HasSuffix(kind, "orphan") {
				issue.EndpointID = ""
				issue.EndpointName = ""
				issue.EndpointState = "missing"
				issue.When = nil
				issue.Error = "Owned <history> error"
			}
			var body bytes.Buffer
			body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/timestamps.js" defer></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4" hx-include="#owned-history-context"><form id="owned-history-context"><input type="hidden" name="unrelated" value="private context"></form>`)
			if strings.HasPrefix(kind, "list") {
				page := &inventory.ProfileIssuesPage{ProfileID: 17, ProfileName: "Owned <profile>", Page: 2, PageSize: 5, Total: 11, Issues: []inventory.ProfileIssueSummary{issue}}
				if kind == "list-empty" {
					page.Total = 0
					page.Page = 1
					page.Issues = nil
				}
				require.NoError(t, profiles_views.ProfileIssuesContent(page, info).Render(ctx, &body))
			} else {
				page := &inventory.ProfileIssueReportsPage{ProfileID: 17, ProfileName: "Owned <profile>", Issue: issue, Page: 1, Total: 26, Reports: []inventory.ProfileIssueReport{{ID: 101, TaskID: 37, TaskName: "Owned disabled task", TaskDisabled: true, Failed: true, Output: "Owned <stdout> & output", Error: "Owned <stderr>", End: &instant}}}
				if kind == "reports-orphan" {
					page.Reports[0].TaskID = 0
					page.Reports[0].TaskName = ""
					page.Reports[0].End = nil
					page.Reports[0].RawEnd = "unrecognized <time>"
				}
				if kind == "reports-empty" {
					page.Total = 0
					page.Reports = nil
				}
				if kind == "reports-long" {
					page.ProfileName = strings.Repeat("W", 512)
					page.Reports[0].TaskName = strings.Repeat("W", 512)
					page.Reports[0].Output = strings.Repeat("界", 4096)
					page.Reports[0].Error = strings.Repeat("E", 4096)
					page.Reports[0].OutputTruncated = true
					page.Reports[0].ErrorTruncated = true
					page.Issue.Error = strings.Repeat("E", 1024)
					page.Issue.ErrorTruncated = true
				}
				require.NoError(t, profiles_views.ProfileIssueReportsContent(page, 2, 5, info).Render(ctx, &body))
			}
			body.WriteString(`</main>`)
			if kind == "list" {
				body.WriteString(`<template id="owned-history-next-response"><main id="main" class="p-4">`)
				next := &inventory.ProfileIssuesPage{ProfileID: 17, ProfileName: "Owned <profile>", Page: 3, PageSize: 5, Total: 11, Issues: []inventory.ProfileIssueSummary{issue}}
				require.NoError(t, profiles_views.ProfileIssuesContent(next, info).Render(ctx, &body))
				body.WriteString(`</main></template>`)
			}
			body.WriteString(`</body></html>`)
			require.NotContains(t, body.String(), "!(MISSING:")
			require.NotContains(t, body.String(), "uk-modal")
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("profile-history-%s-%s.html", scope, kind)), body.Bytes(), 0644))
			}
		}
	}
}
