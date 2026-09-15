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

func TestProfileMetadataFields(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for scope, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}} {
		for _, state := range []string{"none", "all", "tags", "all-with-tags"} {
			profile := &ent.Profile{ID: 17, Name: "Owned <metadata>\n第二行", ApplyToAll: state == "all" || state == "all-with-tags"}
			if state == "tags" || state == "all-with-tags" {
				profile.Edges.Tags = []*ent.Tag{{ID: 42, Tag: "Owned tag", Color: "blue"}}
			}
			var body bytes.Buffer
			body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js"></script><script src="/assets/js/_hyperscript.min.js"></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4"><div class="flex flex-col gap-4">`)
			require.NoError(t, profiles_views.ProfileNameField(profile).Render(ctx, &body))
			require.NoError(t, profiles_views.ProfileAssignmentField(profile).Render(ctx, &body))
			visibility := "hidden"
			if state == "tags" {
				visibility = "visible"
			}
			fmt.Fprintf(&body, `<div id="profile-tags" style="visibility:%s">Owned tag selection</div>`, visibility)
			require.NoError(t, profiles_views.ProfileMetadataSaveAction(profile, info).Render(ctx, &body))
			body.WriteString(`</div></main></body></html>`)
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("profile-metadata-%s-%s.html", scope, state)), body.Bytes(), 0644))
			}
		}
	}
}
