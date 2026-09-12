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

func exerciseProfileMetadataScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	profile, err := h.Model.Client.Profile.Create().SetName("Other organization metadata target").SetApplyToAll(true).AddTenantIDs(otherTenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
	form := url.Values{"profile-description": {"Foreign profile changed"}, "profile-assignment": {"dontApplyToAll"}}
	require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/tenant/%d/profiles/%d", tenant, profile.ID), form, "console-test-token").Code)
	unchanged, err := h.Model.Client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.Equal(t, profile.Name, unchanged.Name)
	require.True(t, unchanged.ApplyToAll)
	tag, err := h.Model.Client.Tag.Create().SetTag("Metadata route tag").SetColor("blue").SetTenantID(tenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Tag.DeleteOneID(tag.ID).Exec(ctx)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		q := h.Model.Client.Profile.Create().SetName("Owned metadata").SetApplyToAll(true).SetDisabled(true)
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
		path := fmt.Sprintf("%s/profiles/%d", prefix, owned.ID)
		for _, mode := range []string{"useTags", "applyToAll", "dontApplyToAll"} {
			require.NoError(t, h.Model.Client.Profile.UpdateOneID(owned.ID).AddTagIDs(tag.ID).SetApplyToAll(true).Exec(ctx))
			body := url.Values{"profile-description": {"Saved <metadata>\n第二行"}, "profile-assignment": {mode}}
			for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
				require.Equal(t, 403, request(actor, "POST", path, body, "console-test-token").Code)
			}
			require.Equal(t, 403, request("apple-console-admin", "POST", path, body, "wrong").Code)
			require.Equal(t, 400, request("apple-console-admin", "POST", path+"?profile-assignment=applyToAll", body, "console-test-token").Code)
			for _, invalid := range []url.Values{{"profile-description": {"Owned"}}, {"profile-description": {"Owned"}, "profile-assignment": {"unknown"}}, {"profile-description": {"Owned", "Other"}, "profile-assignment": {"useTags"}}, {"profile-description": {"Owned"}, "profile-assignment": {"useTags"}, "profile": {"1"}}} {
				require.Equal(t, 400, request("apple-console-admin", "POST", path, invalid, "console-test-token").Code)
			}
			require.Equal(t, 200, request("apple-console-admin", "POST", path, body, "console-test-token").Code)
			current, err := h.Model.Client.Profile.Get(ctx, owned.ID)
			require.NoError(t, err)
			require.Equal(t, body.Get("profile-description"), current.Name)
			require.Equal(t, mode == "applyToAll", current.ApplyToAll)
			require.True(t, current.Disabled)
			count, err := current.QueryTags().Count(ctx)
			require.NoError(t, err)
			if mode == "useTags" {
				require.Equal(t, 1, count)
			} else {
				require.Zero(t, count)
			}
			var events int
			require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.profiles.update' AND resource_id=$3`, scope.TenantID, scope.SiteID, fmt.Sprintf("%d/assignment/%s", owned.ID, mode)).Scan(&events))
			require.Equal(t, 1, events)
		}
	}
}
