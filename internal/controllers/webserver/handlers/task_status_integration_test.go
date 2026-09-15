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

func exerciseTaskStatusScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	p, err := h.Model.Client.Profile.Create().SetName("Owned task status source").AddTenantIDs(tenant).AddSiteIDs(site).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
	task, err := h.Model.Client.Task.Create().SetName("Owned task status").SetType("powershell_script").SetProfileID(p.ID).Save(ctx)
	require.NoError(t, err)
	require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/tasks/%d/disable", task.ID), nil, "console-test-token").Code)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		prefix := ""
		create := h.Model.Client.Profile.Create().SetName("Owned task status parent").SetApplyToAll(true)
		if scope.TenantID != 0 {
			prefix = fmt.Sprintf("/tenant/%d", tenant)
			create.AddTenantIDs(tenant)
		}
		if scope.SiteID != 0 {
			prefix += fmt.Sprintf("/site/%d", site)
			create.AddSiteIDs(site)
		}
		p, err := create.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
		task, err := h.Model.Client.Task.Create().SetName("Owned untouched task label").SetType("unix_script").SetVersion(7).SetOrder(0).SetProfileID(p.ID).Save(ctx)
		require.NoError(t, err)
		base := fmt.Sprintf("%s/tasks/%d/", prefix, task.ID)
		form := url.Values{"page": {"2"}, "pageSize": {"50"}, "sortBy": {"name"}, "sortOrder": {"asc"}}
		for _, action := range []string{"disable", "enable"} {
			path := base + action
			for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
				require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
			}
			require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
			require.Equal(t, 400, request("apple-console-admin", "POST", path+"?page=2", form, "console-test-token").Code)
			for _, invalid := range []url.Values{{"disabled": {"true"}}, {"profile-id": {strconv.Itoa(p.ID)}}, {"page": {"1", "2"}}} {
				require.Equal(t, 400, request("apple-console-admin", "POST", path, invalid, "console-test-token").Code)
			}
			response := request("apple-console-admin", "POST", path, form, "console-test-token")
			require.Equal(t, 200, response.Code)
			require.NotContains(t, response.Body.String(), "!(MISSING:")
			require.Contains(t, response.Body.String(), `hx-target="closest form"`)
			require.Contains(t, response.Body.String(), `name="pageSize" value="50"`)
			require.Contains(t, response.Body.String(), `role="img" aria-label="Task `)
			require.Contains(t, response.Body.String(), `hx-swap-oob="outerHTML"`)
			require.Contains(t, response.Body.String(), fmt.Sprintf(`id="task-status-state-%d"`, task.ID))
			require.NotContains(t, response.Body.String(), `id="profile-description"`)
			require.NotContains(t, response.Body.String(), task.Name)
			current, err := h.Model.Client.Task.Get(ctx, task.ID)
			require.NoError(t, err)
			require.Equal(t, action == "disable", current.Disabled)
			require.Equal(t, 7, current.Version)
			require.Zero(t, current.Order, "status response invoked legacy GET order initialization")
			var count int
			require.NoError(t, h.Model.DB.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action=$3 AND resource_id=$4", scope.TenantID, scope.SiteID, "inventory.tasks."+action, fmt.Sprintf("%d/profile/%d", task.ID, p.ID)).Scan(&count))
			require.Equal(t, 1, count)
		}
	}
}
