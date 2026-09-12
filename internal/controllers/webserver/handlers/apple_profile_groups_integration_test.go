package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseAppleProfileGroups(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	invite, err := h.Apple.Invite(ctx, scope, "Owned Apple group target", "apple-console-admin")
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='iPhone16,1',os_version='18.6',certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID)
	require.NoError(t, err)
	payload, err := apple.BuildProfile("Owned group Wi-Fi", "com.example.owned.group.wifi", "wifi", map[string]any{"SSID_STR": "Owned group network", "EncryptionType": "WPA", "Password": "owned-group-password-not-for-html"})
	require.NoError(t, err)
	p, err := h.Apple.SaveProfile(ctx, tenant, "", 0, payload, "apple-console-admin")
	require.NoError(t, err)
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", access.Scope{TenantID: tenant, SiteID: site}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <Apple group>", Rule: inventory.DeviceGroupRule{Search: "Owned Apple group target"}})
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations/%s", tenant, site, p.ID)
	chooser := base + "/groups?revision=1&desired=installed"
	previewPath := base + "/groups/" + group.ID + "/preview?revision=1&group_revision=1&desired=installed"
	for _, path := range []string{chooser, previewPath, base + "/group-assignments"} {
		require.Equal(t, 403, request("scoped-viewer", "GET", path, nil).Code)
	}
	page := request("scoped-operator", "GET", chooser, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "/groups/"+group.ID+"/preview?")
	preview := request("scoped-operator", "GET", previewPath, nil)
	require.Equal(t, 200, preview.Code)
	require.Contains(t, preview.Body.String(), "Owned &lt;Apple group&gt;")
	require.Contains(t, preview.Body.String(), invite.DeviceID)
	require.Contains(t, preview.Body.String(), `name="confirmed"`)
	require.NotContains(t, preview.Body.String(), "owned-group-password-not-for-html")
	var count int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Zero(t, count)
	form := url.Values{"expected_revision": {"1"}, "group_id": {group.ID}, "group_revision": {"1"}, "request_key": {uuid.NewString()}, "devices": {invite.DeviceID}, "desired": {"installed"}}
	require.Equal(t, 400, request("scoped-operator", "POST", base+"/group-assignments", form).Code)
	form.Set("confirmed", "yes")
	saved := request("scoped-operator", "POST", base+"/group-assignments", form)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, base+"/group-assignments/"))
	history := request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, history.Code)
	require.Contains(t, history.Body.String(), "Original group assignment")
	require.Contains(t, history.Body.String(), "Owned &lt;Apple group&gt;")
	require.Contains(t, history.Body.String(), invite.DeviceID)
	require.Equal(t, 200, request("scoped-operator", "GET", base+"/group-assignments", nil).Code)
	definition := group.DeviceGroupDefinition
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", access.Scope{TenantID: tenant, SiteID: site}, group.ID, group.Revision, definition)
	require.NoError(t, err)
	replay := request("scoped-operator", "POST", base+"/group-assignments", form)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	form.Set("request_key", uuid.NewString())
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/group-assignments", form).Code)
	form.Add("group_revision", "1")
	require.Equal(t, 400, request("scoped-operator", "POST", base+"/group-assignments", form).Code)
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&count))
	require.Equal(t, 1, count)
}
