package mdm_views

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
	"github.com/stretchr/testify/require"
)

func TestTaskOrderListsAndPartialResponses(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for scope, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}} {
		c := echo.New().NewContext(httptest.NewRequest("GET", "/profiles/17/tasks", nil).WithContext(ctx), httptest.NewRecorder())
		c.Set("csrf", "owned-csrf")
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/uikit.min.js" defer></script><script src="/assets/js/_hyperscript.min.js" defer></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4"><label for="owned-unsaved">Profile name</label><input id="owned-unsaved" class="uk-input" value="Owned original profile">`)
		p := partials.PaginationAndSort{CurrentPage: 1, PageSize: 2, NItems: 3, SortBy: "name", SortOrder: "asc"}
		rows := func(ids ...int) []*ent.Task {
			values := []*ent.Task{}
			for i, id := range ids {
				values = append(values, &ent.Task{ID: id, Order: i + 1, Name: fmt.Sprintf("Owned <task> %d", id), Type: task.TypeUnixScript, AgentType: task.AgentTypeLinux, Version: 7})
			}
			return values
		}
		require.NoError(t, profiles_views.ProfileTaskList(c, p, 17, rows(101, 102), 1, info).Render(ctx, &body))
		body.WriteString(`</main><template id="owned-order-response">`)
		require.NoError(t, profiles_views.ProfileTaskList(c, p, 17, rows(102, 101), 1, info).Render(ctx, &body))
		body.WriteString(`</template><template id="owned-follow-response">`)
		p.CurrentPage = 2
		last := rows(101)
		last[0].Order = 3
		require.NoError(t, profiles_views.ProfileTaskList(c, p, 17, last, 1, info).Render(ctx, &body))
		body.WriteString(`</template></body></html>`)
		require.NotContains(t, body.String(), "!(MISSING:")
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "task-order-"+scope+".html"), body.Bytes(), 0644))
		}
	}
}
