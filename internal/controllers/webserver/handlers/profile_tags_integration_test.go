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

func exerciseProfileTagAssignments(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	tag, err := h.Model.Client.Tag.Create().SetTag("Owned profile route tag").SetColor("blue").SetTenantID(tenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Tag.DeleteOneID(tag.ID).Exec(ctx)
	foreign, err := h.Model.Client.Tag.Create().SetTag("Private profile route tag").SetColor("red").SetTenantID(otherTenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Tag.DeleteOneID(foreign.ID).Exec(ctx)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		q := h.Model.Client.Profile.Create().SetName("Owned tag route profile").SetApplyToAll(true)
		prefix := ""
		if scope.TenantID != 0 {
			q.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			q.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		profile, err := q.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
		path := fmt.Sprintf("%s/profiles/%d/tags", prefix, profile.ID)
		form := url.Values{"agentId": {strconv.Itoa(profile.ID)}, "tagId": {strconv.Itoa(tag.ID)}, "page": {"1"}, "pageSize": {"5"}}
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
			require.Equal(t, 403, request(actor, "DELETE", path+"?"+form.Encode(), nil, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
		require.Equal(t, 403, request("apple-console-admin", "DELETE", path+"?"+form.Encode(), nil, "wrong").Code)
		duplicate := url.Values{"agentId": {strconv.Itoa(profile.ID)}, "tagId": {strconv.Itoa(tag.ID), strconv.Itoa(foreign.ID)}}
		require.Equal(t, 400, request("apple-console-admin", "POST", path, duplicate, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "DELETE", path+"?"+duplicate.Encode(), nil, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", path+"?tagId=1", form, "console-test-token").Code)
		mismatch := url.Values{"agentId": {"0"}, "tagId": {strconv.Itoa(tag.ID)}}
		require.Equal(t, 400, request("apple-console-admin", "POST", path, mismatch, "console-test-token").Code)
		if scope.TenantID != 0 {
			require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/profiles/%d/tags", profile.ID), form, "console-test-token").Code)
			other := url.Values{"agentId": {strconv.Itoa(profile.ID)}, "tagId": {strconv.Itoa(foreign.ID)}}
			w := request("apple-console-admin", "POST", path, other, "console-test-token")
			require.Equal(t, 404, w.Code)
			require.NotContains(t, w.Body.String(), foreign.Tag)
		} else {
			require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/tenant/%d/profiles/%d/tags", tenant, profile.ID), form, "console-test-token").Code)
		}
		require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
		current, err := h.Model.Client.Profile.Get(ctx, profile.ID)
		require.NoError(t, err)
		require.False(t, current.ApplyToAll)
		require.Equal(t, 204, request("apple-console-admin", "DELETE", path+"?"+form.Encode(), nil, "console-test-token").Code)
		var count int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM profile_tags WHERE profile_id=$1`, profile.ID).Scan(&count))
		require.Zero(t, count)
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action IN ('inventory.profile_tags.assign','inventory.profile_tags.unassign') AND tenant_id=$1 AND site_id=$2 AND resource_id LIKE $3`, scope.TenantID, scope.SiteID, strconv.Itoa(profile.ID)+"/%").Scan(&count))
		require.Equal(t, 2, count)
	}
}
