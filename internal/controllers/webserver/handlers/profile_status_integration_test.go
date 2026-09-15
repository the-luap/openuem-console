package handlers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseProfileStatusScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant int) {
	t.Helper()
	profile, err := h.Model.Client.Profile.Create().SetName("Other organization status target").SetDisabled(true).AddTenantIDs(otherTenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
	request := ownedTagHTTPRequest(t, h, e, ctx)
	w := request("apple-console-admin", "POST", fmt.Sprintf("/tenant/%d/profiles/%d/enable", tenant, profile.ID), nil, "console-test-token")
	require.Equal(t, 404, w.Code)
	unchanged, err := h.Model.Client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.True(t, unchanged.Disabled)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		q := h.Model.Client.Profile.Create().SetName("Owned profile status").SetDisabled(true).SetApplyToAll(true)
		prefix := ""
		if scope.TenantID != 0 {
			q.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			q.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		owned, err := q.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(owned.ID).Exec(ctx)
		base := fmt.Sprintf("%s/profiles/%d", prefix, owned.ID)
		form := url.Values{"page": {"1"}, "pageSize": {"5"}, "sortBy": {"name"}, "sortOrder": {"asc"}}
		for _, action := range []string{"enable", "disable"} {
			path := base + "/" + action
			for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
				require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
			}
			require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
			require.Equal(t, 400, request("apple-console-admin", "POST", path+"?profile=1", form, "console-test-token").Code)
			require.Equal(t, 400, request("apple-console-admin", "POST", path, url.Values{"enabled": {"true"}}, "console-test-token").Code)
			require.Equal(t, 400, request("apple-console-admin", "POST", path, url.Values{"page": {"1", "2"}}, "console-test-token").Code)
			require.Equal(t, 200, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
			current, err := h.Model.Client.Profile.Get(ctx, owned.ID)
			require.NoError(t, err)
			require.Equal(t, action == "disable", current.Disabled)
			require.True(t, current.ApplyToAll)
			require.Equal(t, owned.Name, current.Name)
		}
		var count int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action IN ('inventory.profiles.enable','inventory.profiles.disable') AND tenant_id=$1 AND site_id=$2 AND resource_id=$3`, scope.TenantID, scope.SiteID, strconv.Itoa(owned.ID)).Scan(&count))
		require.Equal(t, 2, count)
	}
}
