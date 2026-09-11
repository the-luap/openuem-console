package mdm_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/preferences"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestManagementNavigationRetainsScopedRoleLinksAndCatalogFallback(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	for _, language := range preferences.Languages() {
		for _, role := range []access.Role{access.Viewer, access.Operator, access.TenantAdmin, access.Administrator} {
			ctx, err := ctxi18n.WithLocale(context.Background(), language.Code)
			if err != nil {
				t.Fatal(err)
			}
			sm := scs.New()
			ctx, err = sm.Load(ctx, "")
			if err != nil {
				t.Fatal(err)
			}
			sm.Put(ctx, "uid", "navigation-reader")
			scope := access.Scope{TenantID: 1, SiteID: 1}
			if role == access.TenantAdmin {
				scope.SiteID = 0
			}
			if role == access.Administrator {
				scope = access.Scope{}
			}
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "navigation-reader", Grants: []access.Grant{{Role: role, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/devices", nil).WithContext(ctx), httptest.NewRecorder())
			var body bytes.Buffer
			if err = Devices(c, info, nil, "", "", "", false).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			html := body.String()
			if !strings.Contains(html, "Management pages") || !strings.Contains(html, `aria-label="Management pages"`) || strings.Contains(html, "management_navigation.") {
				t.Fatal("navigation catalog fallback missing", language.Code, role)
			}
			if strings.Contains(html, `/tenant/1/site/1/deploy"`) != (role == access.Administrator) {
				t.Fatal("legacy deployment navigation authority changed", role)
			}
			if strings.Contains(html, `/tenant/1/site/1/ios/ade"`) != (role == access.TenantAdmin || role == access.Administrator) {
				t.Fatal("ADE navigation authority changed", role)
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" && language.Code == "en" {
				if err = os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "management-navigation-"+string(role)+".html"), body.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
