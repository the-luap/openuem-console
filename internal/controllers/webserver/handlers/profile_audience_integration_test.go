package handlers

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseProfileAudienceScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	for _, action := range []string{"setglobal", "settenant"} {
		t.Run("foreign audience "+action, func(t *testing.T) {
			profile, err := h.Model.Client.Profile.Create().SetName("Other organization audience target").AddTenantIDs(otherTenant).Save(ctx)
			require.NoError(t, err)
			defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
			path := fmt.Sprintf("/tenant/%d/site/%d/profiles/%d/%s", tenant, site, profile.ID, action)
			require.Equal(t, 404, request("apple-console-admin", "POST", path, nil, "console-test-token").Code)
		})
	}
	for _, tc := range []struct {
		scope  access.Scope
		action string
	}{{access.Scope{TenantID: tenant}, "setglobal"}, {access.Scope{TenantID: tenant, SiteID: site}, "setglobal"}, {access.Scope{TenantID: tenant, SiteID: site}, "settenant"}} {
		t.Run(fmt.Sprintf("%s from site %d", tc.action, tc.scope.SiteID), func(t *testing.T) {
			q := h.Model.Client.Profile.Create().SetName("Owned audience move").SetDisabled(true).SetApplyToAll(true).AddTenantIDs(tenant)
			prefix := fmt.Sprintf("/tenant/%d", tenant)
			if tc.scope.SiteID != 0 {
				q.AddSiteIDs(site)
				prefix += fmt.Sprintf("/site/%d", site)
			}
			profile, err := q.Save(ctx)
			require.NoError(t, err)
			defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
			path := fmt.Sprintf("%s/profiles/%d/%s", prefix, profile.ID, tc.action)
			form := url.Values{"page": {"1"}, "pageSize": {"5"}, "sortBy": {"name"}, "sortOrder": {"asc"}}
			for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
				require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
			}
			require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
			for _, body := range []url.Values{{"tenant-id": {"1"}}, {"global": {"true"}}, {"page": {"1", "2"}}} {
				require.Equal(t, 400, request("apple-console-admin", "POST", path, body, "console-test-token").Code)
			}
			require.Equal(t, 400, request("apple-console-admin", "POST", path+"?page=2", form, "console-test-token").Code)
			require.Equal(t, 200, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
			require.Equal(t, 404, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
			current, err := h.Model.Client.Profile.Get(ctx, profile.ID)
			require.NoError(t, err)
			require.True(t, current.Disabled)
			require.True(t, current.ApplyToAll)
			require.Equal(t, profile.Name, current.Name)
			sites, err := current.QuerySite().All(ctx)
			require.NoError(t, err)
			require.Empty(t, sites)
			tenants, err := current.QueryTenant().All(ctx)
			require.NoError(t, err)
			destination, action := tenant, "inventory.profiles.move_organization"
			if tc.action == "setglobal" {
				require.Empty(t, tenants)
				destination = 0
				action = "inventory.profiles.move_global"
			} else {
				require.Len(t, tenants, 1)
				require.Equal(t, tenant, tenants[0].ID)
			}
			var count int
			resource := fmt.Sprintf("%d/from/%d/%d/to/%d/0", profile.ID, tenant, tc.scope.SiteID, destination)
			require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action=$1 AND resource_id=$2`, action, resource).Scan(&count))
			require.Equal(t, 2, count)
		})
	}
	global, err := h.Model.Client.Profile.Create().SetName("Already global").Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(global.ID).Exec(ctx)
	for _, action := range []string{"setglobal", "settenant"} {
		require.Equal(t, 400, request("apple-console-admin", "POST", fmt.Sprintf("/profiles/%d/%s", global.ID, action), nil, "console-test-token").Code)
	}
}
