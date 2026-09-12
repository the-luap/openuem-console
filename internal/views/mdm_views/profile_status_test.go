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

func TestProfileStatusActions(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	var body bytes.Buffer
	body.WriteString(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js"></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
	p := partials.PaginationAndSort{CurrentPage: 2, PageSize: 25, SortBy: "name", SortOrder: "asc"}
	for i, info := range []*partials.CommonInfo{{TenantID: "-1", SiteID: "-1"}, {TenantID: "1", SiteID: "-1"}, {TenantID: "1", SiteID: "2"}} {
		for _, disabled := range []bool{true, false} {
			fmt.Fprintf(&body, `<section id="profile-status-%d-%t">`, i, disabled)
			require.NoError(t, profiles_views.ProfileStatusAction(&ent.Profile{ID: 17, Disabled: disabled}, p, info).Render(ctx, &body))
			body.WriteString(`</section>`)
		}
	}
	body.WriteString(`</main></body></html>`)
	if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "profile-status-actions.html"), body.Bytes(), 0644))
	}
}
