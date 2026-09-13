package mdm_views

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/tasks_views"
	"github.com/stretchr/testify/require"
)

func TestTaskCreationForms(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for state, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}, "long": {TenantID: "1", SiteID: "2"}} {
		review := &inventory.TaskCreationReview{ProfileID: 17, ProfileName: "Owned <creation> profile"}
		if state == "long" {
			review.ProfileName = strings.Repeat("界", 512)
			review.NameTruncated = true
		}
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/_hyperscript.min.js" defer></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
		require.NoError(t, tasks_views.TaskCreationForm(review, info).Render(ctx, &body))
		body.WriteString(`<template id="owned-windows-types">`)
		require.NoError(t, partials.SelectTaskType(nil, "windows").Render(ctx, &body))
		body.WriteString(`</template><template id="owned-linux-types">`)
		require.NoError(t, partials.SelectTaskType(nil, "linux").Render(ctx, &body))
		body.WriteString(`</template><template id="owned-powershell-definition">`)
		require.NoError(t, partials.PowerShellComponent(nil).Render(ctx, &body))
		body.WriteString(`</template><template id="owned-registry-subtypes">`)
		require.NoError(t, partials.SelectRegistryTaskSubtype(nil).Render(ctx, &body))
		body.WriteString(`</template><template id="owned-any-types">`)
		require.NoError(t, partials.SelectTaskType(nil, "any").Render(ctx, &body))
		body.WriteString(`</template><template id="owned-netbird-subtypes">`)
		require.NoError(t, partials.SelectNetbirdTaskSubtype(nil).Render(ctx, &body))
		body.WriteString(`</template><template id="owned-netbird-definition">`)
		require.NoError(t, partials.NetbirdTaskComponent(&ent.Task{Type: task.TypeNetbirdRegister, NetbirdGroups: `"opaque-ID-1"`}, []nats.NetBirdGroups{{ID: "opaque-ID-1", Name: "Owned group-with-hyphens"}, {ID: "opaque-ID-2", Name: "Another owned group"}}).Render(ctx, &body))
		body.WriteString(`</template></main></body></html>`)
		require.NotContains(t, body.String(), "MISSING")
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "task-creation-"+state+".html"), body.Bytes(), 0644))
		}
	}
}
