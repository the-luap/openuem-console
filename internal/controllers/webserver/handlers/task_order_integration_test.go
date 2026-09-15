package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseTaskOrderScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	p, err := h.Model.Client.Profile.Create().SetName("Owned task order source").AddTenantIDs(tenant).AddSiteIDs(site).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
	_, err = h.Model.Client.Task.Create().SetName("Owned first order task").SetType("unix_script").SetOrder(1).SetProfileID(p.ID).Save(ctx)
	require.NoError(t, err)
	second, err := h.Model.Client.Task.Create().SetName("Owned second order task").SetType("unix_script").SetOrder(2).SetProfileID(p.ID).Save(ctx)
	require.NoError(t, err)
	require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/tasks/%d/moveup/2", second.ID), nil, "console-test-token").Code)
	require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/profiles/%d/tasks", p.ID), nil, "").Code)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		prefix := ""
		create := h.Model.Client.Profile.Create().SetName("Owned scoped task order")
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
		ids := []int{}
		for i := range 3 {
			row, err := h.Model.Client.Task.Create().SetName(fmt.Sprintf("Owned order label %d", i)).SetType("unix_script").SetScript("Owned hidden task script").SetLocalUserPassword("Owned hidden task credential").SetOrder(0).SetProfileID(p.ID).Save(ctx)
			require.NoError(t, err)
			ids = append(ids, row.ID)
		}
		// Initial editor reads must also stop initializing order values.
		require.Equal(t, 200, request("apple-console-admin", "GET", fmt.Sprintf("%s/profiles/%d", prefix, p.ID), nil, "").Code)
		for _, id := range ids {
			row, err := h.Model.Client.Task.Get(ctx, id)
			require.NoError(t, err)
			require.Zero(t, row.Order)
		}
		path := fmt.Sprintf("%s/profiles/%d/tasks", prefix, p.ID)
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "GET", path, nil, "").Code)
		}
		for _, query := range []string{"?page=0", "?page=1&page=2", "?pageSize=1001", "?profile=1", "?page=01"} {
			require.Equal(t, 400, request("apple-console-admin", "GET", path+query, nil, "").Code)
		}
		page := request("apple-console-admin", "GET", path+"?page=1&pageSize=2", nil, "")
		require.Equal(t, 200, page.Code)
		require.Contains(t, page.Body.String(), `id="profile-task-list"`)
		require.NotContains(t, page.Body.String(), `id="profile-description"`)
		require.NotContains(t, page.Body.String(), "Owned hidden")
		require.NotContains(t, page.Body.String(), "!(MISSING:")
		form := url.Values{"page": {"1"}, "pageSize": {"2"}, "sortBy": {"name"}, "sortOrder": {"asc"}}
		up := fmt.Sprintf("%s/tasks/%d/moveup/2", prefix, ids[1])
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "POST", up, form, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "POST", up, form, "wrong").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", up+"?from=1", form, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", up, url.Values{"from": {"2"}}, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", up, url.Values{"pageSize": {"02"}}, "console-test-token").Code)
		for _, move := range []struct {
			suffix string
			page   int
		}{{"moveup/2", 1}, {"movedown/1", 1}, {"movefrom/2/to/3", 2}} {
			response := request("apple-console-admin", "POST", fmt.Sprintf("%s/tasks/%d/%s", prefix, ids[1], move.suffix), form, "console-test-token")
			require.Equal(t, 204, response.Code)
			var event map[string]struct {
				ProfileID string `json:"profileId"`
				TaskID    string `json:"taskId"`
				Page      int    `json:"page"`
			}
			require.NoError(t, json.Unmarshal([]byte(response.Header().Get("HX-Trigger")), &event))
			require.Equal(t, fmt.Sprint(p.ID), event["profileTaskOrderSaved"].ProfileID)
			require.Equal(t, move.page, event["profileTaskOrderSaved"].Page)
		}
		require.Equal(t, 409, request("apple-console-admin", "POST", up, form, "console-test-token").Code)
		fresh := request("apple-console-admin", "GET", path+"?page=2&pageSize=2", nil, "")
		require.Equal(t, 200, fresh.Code)
		require.Contains(t, fresh.Body.String(), fmt.Sprintf(`id="task-name-%d"`, ids[1]))
		require.Equal(t, 1, strings.Count(fresh.Body.String(), `class="profile-task-row"`))
		var count int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.tasks.reorder' AND resource_id LIKE $3", scope.TenantID, scope.SiteID, fmt.Sprintf("%%/profile/%d/%%", p.ID)).Scan(&count))
		require.Equal(t, 3, count)
	}
}
