package mdm_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestOrganizationTagPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-tag-admin")
	for _, state := range []string{"list", "empty", "detail", "used", "viewer", "long", "list-viewer", "administrator"} {
		t.Run(state, func(t *testing.T) {
			role := access.TenantAdmin
			if strings.Contains(state, "viewer") {
				role = access.Viewer
			}
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-tag-admin", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "-1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			tag := inventory.OrganizationTag{ID: 42, Revision: "00000000-0000-4000-8000-000000000042", TagDefinition: inventory.TagDefinition{Name: "Owned <tag>", Description: "Shared organization definition", Color: "#123456"}, Used: state == "used"}
			info.IsAdmin = true
			if state == "administrator" {
				info.Principal.Grants = []access.Grant{{Role: access.Administrator}}
			}
			if state == "long" {
				tag.Name = strings.Repeat("x", 247) + "<script>"
				tag.Description = strings.Repeat("D", 2048)
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/admin/tags", nil).WithContext(ctx), httptest.NewRecorder())
			var component templ.Component
			if state == "list" || state == "empty" || state == "list-viewer" {
				tags := []inventory.OrganizationTag{tag}
				if state == "empty" {
					tags = nil
				}
				component = OrganizationTags(c, info, &inventory.TagPage{Tags: tags}, inventory.ReportFilter{Search: "Owned"}, DevicePagination{Next: "/tenant/1/admin/tags?q=Owned&after=42"})
			} else {
				component = OrganizationTag(c, info, &tag)
			}
			var body bytes.Buffer
			require.NoError(t, component.Render(ctx, &body))
			html := body.String()
			require.NotContains(t, html, "organization_tags.")
			require.NotContains(t, html, "@Navigation")
			require.NotContains(t, html, "@CSRF")
			require.Equal(t, state == "administrator", strings.Contains(html, `value="/admin"`))
			require.Equal(t, state == "administrator", strings.Contains(html, `href="/tenant/1/admin/settings"`))
			require.Equal(t, role == access.TenantAdmin, strings.Contains(html, `aria-label="Edit tag"`))
			require.Equal(t, state == "detail" || state == "long" || state == "administrator", strings.Contains(html, `aria-label="Delete tag"`))
			require.False(t, strings.Contains(html, tag.Name), "tag text was not escaped")
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "organization-tags-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
