package handlers

import (
	"context"
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseAppleProfileOrganizationGroups(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	other, err := h.Model.Client.Site.Create().SetDescription("Owned other organization-group site").SetTenantID(tenant).Save(ctx)
	require.NoError(t, err)
	var ids []string
	for _, scope := range []apple.Scope{scope, {TenantID: tenant, SiteID: other.ID}} {
		invite, err := h.Apple.Invite(ctx, scope, "Owned organization profile target", "apple-console-admin")
		require.NoError(t, err)
		_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='iPhone16,1',os_version='18.6',certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID)
		require.NoError(t, err)
		ids = append(ids, invite.DeviceID)
	}
	payload, err := apple.BuildProfile("Owned organization-group Wi-Fi", "com.example.owned.organization.group.wifi", "wifi", map[string]any{"SSID_STR": "Owned organization network", "EncryptionType": "WPA", "Password": "owned-organization-secret"})
	require.NoError(t, err)
	p, err := h.Apple.SaveProfile(ctx, tenant, "", 0, payload, "apple-console-admin")
	require.NoError(t, err)
	definition := inventory.DeviceGroupDefinition{Name: "Owned <organization profile group>", Rule: inventory.DeviceGroupRule{Search: "Owned organization profile target"}}
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "organization-admin", access.Scope{TenantID: tenant}, "", 0, definition)
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations/%s", tenant, site, p.ID)
	chooser := base + "/groups?revision=1&source=organization"
	preview := base + "/groups/" + group.ID + "/preview?revision=1&group_revision=1&source=organization"
	for _, path := range []string{chooser, preview} {
		page := request("organization-admin", "GET", path, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
		require.Contains(t, page.Body.String(), "Owned &lt;organization profile group&gt;")
		require.NotContains(t, page.Body.String(), ids[1])
		require.Equal(t, 403, request("scoped-operator", "GET", path, nil).Code)
		require.Equal(t, 403, request("scoped-viewer", "GET", path, nil).Code)
	}
	page := request("organization-admin", "GET", preview, nil)
	require.Contains(t, page.Body.String(), ids[0])
	require.Contains(t, page.Body.String(), fmt.Sprintf("/tenant/%d/device-groups/%s", tenant, group.ID))
	require.NotContains(t, page.Body.String(), "owned-organization-secret")
	form := url.Values{}
	for _, field := range []string{"expected_revision", "group_id", "group_revision", "group_source", "request_key", "devices", "desired"} {
		m := regexp.MustCompile(`name="` + field + `" value="([^"]*)"`).FindStringSubmatch(page.Body.String())
		require.Len(t, m, 2)
		form.Set(field, html.UnescapeString(m[1]))
	}
	require.Equal(t, "organization", form.Get("group_source"))
	require.Equal(t, ids[0], form.Get("devices"))
	require.Equal(t, 400, request("organization-admin", "POST", base+"/group-assignments", form).Code)
	form.Set("confirmed", "yes")
	require.Equal(t, 403, request("scoped-operator", "POST", base+"/group-assignments", form).Code)
	// Source kind cannot be removed to turn this into a site-source admission.
	form.Del("group_source")
	require.Equal(t, 404, request("organization-admin", "POST", base+"/group-assignments", form).Code)
	form.Set("group_source", "organization")
	orgBase := fmt.Sprintf("/tenant/%d/ios/configurations/%s", tenant, p.ID)
	require.Equal(t, 400, request("organization-admin", "GET", orgBase+"/groups?revision=1&source=organization", nil).Code)
	require.Equal(t, 400, request("organization-admin", "POST", orgBase+"/group-assignments", form).Code)
	for _, path := range []string{chooser + "&source=site", base + "/groups?revision=1&source=other", preview + "&source=organization"} {
		require.Equal(t, 400, request("organization-admin", "GET", path, nil).Code)
	}
	form.Add("group_source", "site")
	require.Equal(t, 400, request("organization-admin", "POST", base+"/group-assignments", form).Code)
	form.Set("group_source", "organization")
	saved := request("organization-admin", "POST", base+"/group-assignments", form)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, base+"/group-assignments/"))
	page = request("organization-admin", "GET", location, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "Only the selected target site")
	require.NotContains(t, page.Body.String(), ids[1])
	require.Contains(t, page.Body.String(), fmt.Sprintf("/tenant/%d/device-groups/%s", tenant, group.ID))
	page = request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, page.Code)
	require.NotContains(t, page.Body.String(), "Open the current organization group and its history")
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "organization-admin", access.Scope{TenantID: tenant}, group.ID, 1, definition)
	require.NoError(t, err)
	require.NoError(t, h.Apple.AssignProfileWithAccess(ctx, scope, p.ID, p.Revision, []string{ids[0]}, "removed", "organization-admin", h.Access))
	replay := request("organization-admin", "POST", base+"/group-assignments", form)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	assignments, err := h.Apple.Assignments(ctx, scope, ids[0])
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	require.Equal(t, "removed", assignments[0].Desired)
	var commands int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1 AND device_id=$2`, p.ID, ids[1]).Scan(&commands))
	require.Zero(t, commands)
	form.Set("request_key", uuid.NewString())
	require.Equal(t, 409, request("organization-admin", "POST", base+"/group-assignments", form).Code)
	page = request("scoped-operator", "GET", base+"/group-assignments", nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "Source: organization group")
}
