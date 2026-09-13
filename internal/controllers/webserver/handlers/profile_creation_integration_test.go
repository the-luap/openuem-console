package handlers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"testing"

	"github.com/labstack/echo/v4"
	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseProfileCreationScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	name := "Owned profile creation audit"
	path := fmt.Sprintf("/tenant/%d/site/%d/profiles/new", tenant, site)
	require.Equal(t, 200, request("apple-console-admin", "POST", path, url.Values{"profile-description": {name}}, "console-test-token").Code)
	profile, err := h.Model.Client.Profile.Query().Where(entprofile.NameEQ(name)).Only(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
	var events int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.profiles.create' AND resource_id=$3", tenant, site, strconv.Itoa(profile.ID)).Scan(&events))
	require.Equal(t, 1, events)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		prefix := ""
		if scope.TenantID != 0 {
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			prefix += fmt.Sprintf("/site/%d", site)
		}
		path := prefix + "/profiles/new"
		name := fmt.Sprintf("Owned <creation> %d/%d\n第二行", scope.TenantID, scope.SiteID)
		form := url.Values{"profile-description": {name}}
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", path+"?profile-description=Other", form, "console-test-token").Code)
		for _, invalid := range []url.Values{nil, {"profile-description": {" \t"}}, {"profile-description": {name, name}}, {"profile-description": {name}, "profile-assignment": {"applyToAll"}}, {"profile-description": {name}, "profile": {"17"}}, {"profile-description": {name}, "tenant-id": {"1"}}} {
			require.Equal(t, 400, request("apple-console-admin", "POST", path, invalid, "console-test-token").Code)
		}
		require.Equal(t, 200, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
		created, err := h.Model.Client.Profile.Query().Where(entprofile.NameEQ(name)).WithTasks().WithTags().WithTenant().WithSite().Only(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(created.ID).Exec(ctx)
		require.False(t, created.ApplyToAll)
		require.False(t, created.Disabled)
		require.Empty(t, created.Edges.Tasks)
		require.Empty(t, created.Edges.Tags)
		require.Equal(t, entprofile.TypeWinget, created.Type)
		if scope.TenantID == 0 {
			require.Empty(t, created.Edges.Tenant)
		} else {
			require.Len(t, created.Edges.Tenant, 1)
			require.Equal(t, tenant, created.Edges.Tenant[0].ID)
		}
		if scope.SiteID == 0 {
			require.Empty(t, created.Edges.Site)
		} else {
			require.Len(t, created.Edges.Site, 1)
			require.Equal(t, site, created.Edges.Site[0].ID)
		}
		var count int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.profiles.create' AND resource_id=$3", scope.TenantID, scope.SiteID, strconv.Itoa(created.ID)).Scan(&count))
		require.Equal(t, 1, count)
	}
}
