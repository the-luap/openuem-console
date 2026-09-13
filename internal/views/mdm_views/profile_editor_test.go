package mdm_views

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
	"github.com/stretchr/testify/require"
)

func TestProfileEditorNativeFormsAndPanels(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for scope, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}} {
		for _, kind := range []string{"normal", "long"} {
			c := echo.New().NewContext(httptest.NewRequest("GET", "/profiles/17", nil).WithContext(ctx), httptest.NewRecorder())
			c.Set("csrf", "owned-csrf")
			p := partials.PaginationAndSort{CurrentPage: 2, PageSize: 2, NItems: 3}
			tag := inventory.ProfileTagChoice{ID: 42, Name: "Owned <tag>", TenantID: 1, Organization: "Owned organization"}
			panel := &inventory.ProfileTagPanel{ProfileID: 17, ApplyToAll: true, Query: inventory.ProfileTagQuery{Page: 1}, Total: 51, Applied: []inventory.ProfileTagChoice{tag}, Available: []inventory.ProfileTagChoice{{ID: 43, Name: "Available & tag", TenantID: 1, Organization: "Owned organization"}}, HasMore: true}
			review := &inventory.ProfileEditorReview{Profile: &ent.Profile{ID: 17, Name: "Owned <profile>\n第二行", ApplyToAll: true}, Tags: panel, Tasks: &inventory.LegacyTaskPage{Page: 2, PageSize: 2, Total: 3, Tasks: []*ent.Task{{ID: 101, Order: 3, Name: "Owned task", Type: task.TypeUnixScript, AgentType: task.AgentTypeLinux, Version: 1}}}}
			if kind == "long" {
				review.NameNeedsReplacement = true
				review.Profile.Name = ""
				review.NamePreview = strings.Repeat("界", 512) + "…"
				panel.Applied[0].Name = strings.Repeat("W", 256) + "…"
			}
			var body bytes.Buffer
			body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/uikit.min.js" defer></script><script src="/assets/js/_hyperscript.min.js" defer></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
			require.NoError(t, profiles_views.ProfileEditorForm(c, p, review, 2, info).Render(ctx, &body))
			body.WriteString(`</main><template id="owned-tag-search-response">`)
			panel.Query = inventory.ProfileTagQuery{Page: 1, Search: "needle & <tag>"}
			panel.Available = []inventory.ProfileTagChoice{{ID: 44, Name: "Search result", TenantID: 1, Organization: "Owned organization"}}
			panel.HasMore = false
			require.NoError(t, profiles_views.ProfileTagPanelView(panel, info, "").Render(ctx, &body))
			body.WriteString(`</template><template id="owned-tag-add-response">`)
			panel.ApplyToAll = false
			panel.Total = 52
			panel.Applied = append(panel.Applied, panel.Available[0])
			panel.Available = nil
			require.NoError(t, profiles_views.ProfileTagMutation(panel, info, "Tag added").Render(ctx, &body))
			body.WriteString(`</template><template id="owned-tag-remove-response">`)
			panel.Total = 0
			panel.Applied = nil
			panel.Available = []inventory.ProfileTagChoice{tag}
			require.NoError(t, profiles_views.ProfileTagMutation(panel, info, "Tag removed").Render(ctx, &body))
			body.WriteString(`</template><template id="owned-tag-page-response">`)
			panel.Total = 51
			panel.Query.Page = 2
			panel.Applied = []inventory.ProfileTagChoice{tag}
			require.NoError(t, profiles_views.ProfileTagPanelView(panel, info, "").Render(ctx, &body))
			body.WriteString(`</template></body></html>`)
			require.NotContains(t, body.String(), "!(MISSING:")
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("profile-editor-%s-%s.html", scope, kind)), body.Bytes(), 0644))
			}
		}
	}
}
