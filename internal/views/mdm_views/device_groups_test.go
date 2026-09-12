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
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestDeviceGroupPages(t *testing.T) {
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
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			g := inventory.DeviceGroup{ID: "00000000-0000-0000-0000-000000000001", Scope: scope, Revision: 3, DeviceGroupDefinition: inventory.DeviceGroupDefinition{Name: "Owned <group>", Description: "Current group rule", Rule: inventory.DeviceGroupRule{Platform: "windows", Search: "Owned"}, Archived: state == "archived"}, Actor: "owned-operator", CreatedAt: now}
			if state == "long" {
				g.Name = strings.Repeat("x", 110) + "<script>"
				g.Description = strings.Repeat("D", 1024)
			}
			path := "/tenant/1/site/1/device-groups/" + g.ID
			paging := DevicePagination{Next: path + "?revision=3&after=owned-cursor"}
			history := DevicePagination{Next: path + "?revision=3&history=2"}
			rows := []DeviceRow{{Name: "Owned Windows", Platform: "Windows", OSVersion: "11", Status: "agent", URL: "/tenant/1/site/1/computers/owned-windows", LastSeen: &now}}
			if state == "archived" {
				rows = nil
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", path, nil).WithContext(ctx), httptest.NewRecorder())
			var component templ.Component
			if state == "list" || state == "empty" {
				groups := []inventory.DeviceGroup{g}
				if state == "empty" {
					groups = nil
				}
				component = DeviceGroups(c, info, &inventory.DeviceGroupPage{Groups: groups}, DevicePagination{Next: "/tenant/1/site/1/device-groups?after=" + g.ID})
			} else {
				component = DeviceGroup(c, info, &inventory.DeviceGroupInspection{Group: g, Members: &inventory.DevicePage{}, History: []inventory.DeviceGroup{g}}, rows, paging, history)
			}
			var body bytes.Buffer
			require.NoError(t, component.Render(ctx, &body))
			html := body.String()
			require.NotContains(t, html, "mdm.groups.")
			require.False(t, strings.Contains(html, g.Name), "group name was not escaped")
			require.NotContains(t, html, "@Navigation")
			require.NotContains(t, html, "@Timestamp")
			require.Equal(t, state != "viewer", strings.Contains(html, `aria-label="Edit group definition"`))
			if state != "viewer" {
				require.Contains(t, html, `name="csrf" value="owned-csrf"`)
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "device-groups-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
