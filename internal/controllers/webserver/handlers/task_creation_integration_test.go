package handlers

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseTaskCreationScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	form := url.Values{"task-agent-type": {"windows"}, "task-type": {"powershell_type"}, "task-description": {"Owned <created> task"}, "powershell-script": {"Write-Output 'owned'"}, "powershell-run": {"always"}}
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		prefix := ""
		create := h.Model.Client.Profile.Create().SetName("Owned <creation> parent")
		if scope.TenantID != 0 {
			create.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			create.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		p, err := create.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
		existing, err := h.Model.Client.Task.Create().SetName("Retained creation sibling").SetType("unix_script").SetOrder(9).SetProfileID(p.ID).Save(ctx)
		require.NoError(t, err)
		path := fmt.Sprintf("%s/tasks/%d/new", prefix, p.ID)
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "GET", path, nil, "").Code)
			require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"?profile=1", nil, "").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", path+"?profile=1", form, "console-test-token").Code)
		for _, change := range []func(url.Values){func(v url.Values) { v["profile"] = []string{"1"} }, func(v url.Values) { v["task-description"] = []string{"one", "two"} }, func(v url.Values) { v.Set("task-agent-type", "linux") }, func(v url.Values) { v.Set("task-description", "") }, func(v url.Values) { v.Set("powershell-script", strings.Repeat("x", (128<<10)+1)) }} {
			bad := url.Values{}
			for k, v := range form {
				bad[k] = append([]string{}, v...)
			}
			change(bad)
			require.Equal(t, 400, request("apple-console-admin", "POST", path, bad, "console-test-token").Code)
		}
		w := request("apple-console-admin", "GET", path, nil, "")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "Owned &lt;creation&gt; parent")
		require.Contains(t, w.Body.String(), fmt.Sprintf("Destination profile ID: %d", p.ID))
		require.NotContains(t, w.Body.String(), "MISSING")
		require.Equal(t, 1, strings.Count(w.Body.String(), `id="main"`))
		sibling, err := h.Model.Client.Task.Get(ctx, existing.ID)
		require.NoError(t, err)
		require.Equal(t, 9, sibling.Order)
		w = request("apple-console-admin", "POST", path, form, "console-test-token")
		require.Equal(t, 204, w.Code)
		require.Equal(t, fmt.Sprintf("%s/profiles/%d", prefix, p.ID), w.Header().Get("HX-Redirect"))
		var id, version, order int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT id,version,"order" FROM tasks WHERE profile_tasks=$1 AND name=$2`, p.ID, "Owned <created> task").Scan(&id, &version, &order))
		require.Equal(t, 1, version)
		require.Equal(t, 2, order)
		var events int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.tasks.create' AND resource_id=$3`, scope.TenantID, scope.SiteID, fmt.Sprintf("%d/profile/%d/position/2", id, p.ID)).Scan(&events))
		require.Equal(t, 1, events)
		registration := url.Values{"task-agent-type": {"any"}, "task-type": {"netbird_type"}, "task-subtype": {"netbird_register"}, "task-description": {"Owned network registration"}, "netbird-group-id": {"opaque-ID-1", "opaque-ID-2"}}
		if scope.TenantID == 0 {
			require.Equal(t, 409, request("apple-console-admin", "POST", path, registration, "console-test-token").Code)
		} else {
			require.Equal(t, 204, request("apple-console-admin", "POST", path, registration, "console-test-token").Code)
			var configured, position int
			var groups string
			require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT tenant,"order",netbird_groups FROM tasks WHERE profile_tasks=$1 AND name='Owned network registration'`, p.ID).Scan(&configured, &position, &groups))
			require.Equal(t, tenant, configured)
			require.Equal(t, 3, position)
			require.Equal(t, `"opaque-ID-1","opaque-ID-2"`, groups)
			registration["netbird-group-id"] = []string{"same", "same"}
			require.Equal(t, 400, request("apple-console-admin", "POST", path, registration, "console-test-token").Code)
		}
		if scope.SiteID != 0 {
			require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/tasks/%d/new", p.ID), nil, "").Code)
			require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/tasks/%d/new", p.ID), form, "console-test-token").Code)
		}
	}
}
