package desktop_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestDeviceDetailsPreserveDraftAndEscapeSavedFields(t *testing.T) {
	require.NoError(t, locales.Load())
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "details-admin")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}, Principal: access.Principal{UserID: "details-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/details-device/details", nil).WithContext(ctx), httptest.NewRecorder())
	for _, state := range []string{"edit", "conflict", "empty", "long"} {
		data := &inventory.DeviceDetails{DeviceID: "details-device", Hostname: "finance-host", Revision: "350542db-5a9f-4a88-97cb-4b70d5f164d1", TenantID: 1, SiteID: 1, Values: inventory.DeviceDetailValues{Nickname: "Finance laptop", Description: "Current saved <script>window.detailsOwned=true</script>\nSecond line", EndpointType: "Laptop"}}
		draft, message := data.Values, ""
		if state == "conflict" || state == "long" {
			draft.Nickname = "Draft <script>window.draftOwned=true</script>"
			draft.Description = "Draft </textarea><script>window.draftOwned=true</script>\nPreserved second line"
			draft.EndpointType = "Server"
			message = "Your draft is preserved. Compare it with the currently saved values before saving again."
		}
		if state == "empty" {
			data.Values = inventory.DeviceDetailValues{EndpointType: "Other"}
			draft = data.Values
		}
		if state == "long" {
			data.Values.Nickname = strings.Repeat("n", 255)
			data.Values.Description = strings.Repeat("long", 1000)
			data.Hostname = strings.Repeat("host", 128)
		}
		var out bytes.Buffer
		require.NoError(t, Details(c, info, data, draft, message).Render(ctx, &out))
		html := out.String()
		require.NotContains(t, html, "<script>window.")
		require.Contains(t, html, `name="revision" value="`+data.Revision+`"`)
		require.Contains(t, html, `name="csrf"`)
		require.Contains(t, html, `hx-boost="false"`)
		if message != "" {
			require.Contains(t, html, "Draft &lt;/textarea&gt;")
			require.Contains(t, html, "Currently saved values")
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "device-details-"+state+".html"), out.Bytes(), 0600))
		}
	}
}
