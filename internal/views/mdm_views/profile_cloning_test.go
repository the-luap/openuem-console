package mdm_views

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
	"github.com/stretchr/testify/require"
)

func TestProfileCloningForms(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for scope, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}} {
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js"></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
		require.NoError(t, profiles_views.ProfileCloneForm(&ent.Profile{ID: 17, Name: "Owned <clone>\n第二行"}, []*ent.Tenant{{ID: 1, Description: "Owned organization"}, {ID: 3, Description: "Other organization"}}, info).Render(ctx, &body))
		body.WriteString(`</main><template id="owned-sites-response">`)
		require.NoError(t, profiles_views.SitesSelect([]*ent.Site{{ID: 2, Description: "Owned destination site"}}).Render(ctx, &body))
		body.WriteString(`</template><template id="owned-empty-response">`)
		require.NoError(t, profiles_views.EmptySitesSelect().Render(ctx, &body))
		body.WriteString(`</template></body></html>`)
		require.NotContains(t, body.String(), "!(MISSING:")
		require.Contains(t, body.String(), "Destination organization")
		require.Contains(t, body.String(), "Destination site")
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "profile-cloning-"+scope+".html"), body.Bytes(), 0644))
		}
	}
}
