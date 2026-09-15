package mdm_views

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
	"github.com/stretchr/testify/require"
)

func TestTaskStatusActionsAndResponses(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	var body bytes.Buffer
	body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js"></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4"><label for="owned-unsaved">Unsaved profile name</label><input id="owned-unsaved" class="uk-input" value="Original name">`)
	p := partials.PaginationAndSort{CurrentPage: 2, PageSize: 50, SortBy: "name", SortOrder: "asc"}
	for i, info := range []*partials.CommonInfo{{TenantID: "-1", SiteID: "-1"}, {TenantID: "1", SiteID: "-1"}, {TenantID: "1", SiteID: "2"}} {
		for j, disabled := range []bool{true, false} {
			id := 17 + i*2 + j
			fmt.Fprintf(&body, `<section id="task-status-%d-%t">`, i, disabled)
			require.NoError(t, profiles_views.TaskStatusIndicator(id, disabled, false).Render(ctx, &body))
			require.NoError(t, profiles_views.TaskStatusAction(&ent.Task{ID: id, Disabled: disabled}, p, info, "").Render(ctx, &body))
			body.WriteString(`</section>`)
			fmt.Fprintf(&body, `<template id="task-response-%d">`, id)
			feedback := "Task enabled."
			if !disabled {
				feedback = "Task disabled."
			}
			require.NoError(t, profiles_views.TaskStatusResponse(&ent.Task{ID: id, Disabled: !disabled}, p, info, feedback).Render(ctx, &body))
			body.WriteString(`</template>`)
		}
	}
	body.WriteString(`</main></body></html>`)
	require.NotContains(t, body.String(), "!(MISSING:")
	if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "task-status-actions.html"), body.Bytes(), 0644))
	}
}
