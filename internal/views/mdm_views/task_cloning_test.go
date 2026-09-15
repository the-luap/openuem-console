package mdm_views

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/tasks_views"
	"github.com/stretchr/testify/require"
)

func TestTaskCloningFormsAndTargetSearch(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for state, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}, "long": {TenantID: "1", SiteID: "2"}, "empty": {TenantID: "1", SiteID: "2"}} {
		review := &inventory.TaskCloneReview{ID: 101, ProfileID: 17, Name: "Owned <cloning> task\n第二行", HasMore: true, Targets: []inventory.TaskCloneTarget{{ID: 21, Name: "Global destination"}, {ID: 22, Name: "Organization destination", Scope: access.Scope{TenantID: 1}, Organization: "Owned organization"}, {ID: 23, Name: "Site destination", Scope: access.Scope{TenantID: 1, SiteID: 2}, Organization: "Owned organization", Site: "Owned site"}}}
		if state == "long" {
			review.Name = strings.Repeat("x", 2048)
			review.Targets[2].Name = strings.Repeat("界", 512)
		}
		if state == "empty" {
			review.Name = ""
			review.Targets = nil
			review.HasMore = false
		}
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/_hyperscript.min.js" defer></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
		require.NoError(t, tasks_views.TaskCloneForm(review, info).Render(ctx, &body))
		body.WriteString(`<template id="owned-target-response">`)
		require.NoError(t, tasks_views.TaskCloneTargets(&inventory.TaskCloneReview{Targets: []inventory.TaskCloneTarget{{ID: 31, Name: "Found destination", Scope: access.Scope{TenantID: 1, SiteID: 2}, Organization: "Owned organization", Site: "Owned site"}}}).Render(ctx, &body))
		body.WriteString(`</template></main></body></html>`)
		require.NotContains(t, body.String(), "MISSING")
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "task-cloning-"+state+".html"), body.Bytes(), 0644))
		}
	}
}
