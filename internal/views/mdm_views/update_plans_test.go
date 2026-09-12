package mdm_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdatePlanPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	scope := access.Scope{TenantID: 1, SiteID: 1}

	for _, state := range []string{"list", "empty", "detail", "archived", "viewer", "long"} {
		t.Run(state, func(t *testing.T) {
			role := access.Operator
			if state == "viewer" {
				role = access.Viewer
			}
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: role, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			plan := apple.UpdatePlan{ID: "70000000-0000-0000-0000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, Revision: 3, Actor: "owned-operator", CreatedAt: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC), Definition: apple.UpdatePlanDefinition{Name: "Owned <pilot>", Description: "Reviewed pilot settings", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00", DetailsURL: "https://example.test/update", Archived: state == "archived"}}
			if state == "long" {
				plan.Definition.Name = strings.Repeat("N", 110) + "<script>"
				plan.Definition.Description = strings.Repeat("D", 1024)
				plan.Definition.DetailsURL = "https://example.test/" + strings.Repeat("U", 1900)
			}
			older := plan
			older.Revision = 2
			older.Definition.Name = "Previous <pilot>"
			older.Definition.TargetVersion = "18.7"
			older.Definition.TargetBuild = "22H90"
			path := "/tenant/1/site/1/ios/update-plans/" + plan.ID
			c := echo.New().NewContext(httptest.NewRequest("GET", path, nil).WithContext(ctx), httptest.NewRecorder())
			var component templ.Component
			if state == "list" || state == "empty" {
				plans := []apple.UpdatePlan{plan}
				if state == "empty" {
					plans = nil
				}
				component = AppleUpdatePlans(c, info, plans, DevicePagination{Next: "/tenant/1/site/1/ios/update-plans?after=" + plan.ID})
			} else {
				component = AppleUpdatePlan(c, info, plan, []apple.UpdatePlan{plan, older}, DevicePagination{Next: path + "?before=2"})
			}
			var body bytes.Buffer
			require.NoError(t, component.Render(ctx, &body))
			html := body.String()
			require.False(t, strings.Contains(html, plan.Definition.Name), "plan name was not escaped")
			require.NotContains(t, html, "@Timestamp")
			require.NotContains(t, html, "@CSRF")
			require.NotContains(t, html, "apple_update_plans.")
			require.Equal(t, state != "viewer", strings.Contains(html, `aria-label="Save Apple update plan"`))
			if state != "viewer" {
				revision := "3"
				if state == "list" || state == "empty" {
					revision = "0"
				}
				require.Contains(t, html, `name="expected_revision" value="`+revision+`"`)
				require.Contains(t, html, `name="csrf" value="owned-csrf"`)
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-plan-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
