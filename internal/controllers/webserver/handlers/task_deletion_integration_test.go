package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseTaskDeletionScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) {
		if r.Method == http.MethodDelete {
			r.Header.Del("Content-Type")
		}
	})
	foreign, err := h.Model.Client.Profile.Create().SetName("Owned foreign deletion profile").AddTenantIDs(tenant).AddSiteIDs(site).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(foreign.ID).Exec(ctx)
	target, err := h.Model.Client.Task.Create().SetName("Owned foreign task").SetType("unix_script").SetOrder(99).SetProfileID(foreign.ID).Save(ctx)
	require.NoError(t, err)
	require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/tasks/%d/confirm-delete/%d", foreign.ID, target.ID), nil, "").Code)
	require.Equal(t, 404, request("apple-console-admin", "DELETE", fmt.Sprintf("/tasks/%d?profile=%d", target.ID, foreign.ID), nil, "console-test-token").Code)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		create := h.Model.Client.Profile.Create().SetName("Owned delete task parent")
		prefix := ""
		if scope.TenantID != 0 {
			create.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			create.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		profile, err := create.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
		task, err := h.Model.Client.Task.Create().SetName("Owned <task> deletion").SetType("unix_script").SetScript("Owned secret script").SetLocalUserPassword("Owned secret password").SetProfileID(profile.ID).Save(ctx)
		require.NoError(t, err)
		sibling, err := h.Model.Client.Task.Create().SetName("Owned remaining task").SetType("unix_script").SetOrder(8).SetProfileID(profile.ID).Save(ctx)
		require.NoError(t, err)
		var report int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `INSERT INTO task_reports(task_reports,std_output) VALUES($1,'Owned deleted result') RETURNING id`, task.ID).Scan(&report))
		path := fmt.Sprintf("%s/tasks/%d", prefix, task.ID)
		deletion := fmt.Sprintf("%s?profile=%d", path, profile.ID)
		review := fmt.Sprintf("%s/tasks/%d/confirm-delete/%d", prefix, profile.ID, task.ID)
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "DELETE", deletion, nil, "console-test-token").Code)
			require.Equal(t, 403, request(actor, "GET", review, nil, "").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "DELETE", deletion, nil, "wrong").Code)
		for _, query := range []string{"", "?profile=0", fmt.Sprintf("?profile=%d&profile=%d", profile.ID, profile.ID), fmt.Sprintf("?profile=0%d", profile.ID), fmt.Sprintf("?profile=%d&task=1", profile.ID), "?profile=%zz", "?profile=" + strings.Repeat("1", 129)} {
			require.Equal(t, 400, request("apple-console-admin", "DELETE", path+query, nil, "console-test-token").Code)
		}
		require.Equal(t, 400, request("apple-console-admin", "DELETE", deletion, url.Values{"profile": {"1"}}, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", review+"?profile=1", nil, "").Code)
		require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("%s/tasks/%d/confirm-delete/%d", prefix, foreign.ID, task.ID), nil, "").Code)
		require.Equal(t, 404, request("apple-console-admin", "DELETE", fmt.Sprintf("%s?profile=%d", path, foreign.ID), nil, "console-test-token").Code)
		w := request("apple-console-admin", "GET", review, nil, "")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "Owned &lt;task&gt; deletion")
		require.Contains(t, w.Body.String(), "stored results")
		require.NotContains(t, w.Body.String(), "Owned secret")
		require.NotContains(t, w.Body.String(), "MISSING")
		require.Equal(t, 1, strings.Count(w.Body.String(), `id="main"`))
		w = request("apple-console-admin", "DELETE", deletion, nil, "console-test-token")
		require.Equal(t, 204, w.Code)
		require.Equal(t, fmt.Sprintf("%s/profiles/%d", prefix, profile.ID), w.Header().Get("HX-Redirect"))
		require.Empty(t, w.Body.String())
		require.Equal(t, 404, request("apple-console-admin", "DELETE", deletion, nil, "console-test-token").Code)
		require.Equal(t, 404, request("apple-console-admin", "GET", review, nil, "").Code)
		current, err := h.Model.Client.Task.Get(ctx, sibling.ID)
		require.NoError(t, err)
		require.Equal(t, 1, current.Order)
		current, err = h.Model.Client.Task.Get(ctx, target.ID)
		require.NoError(t, err)
		require.Equal(t, 99, current.Order)
		var n int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM tasks WHERE id=$1)+(SELECT count(*) FROM task_reports WHERE id=$2)`, task.ID, report).Scan(&n))
		require.Zero(t, n)
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.tasks.delete' AND resource_id=$3`, scope.TenantID, scope.SiteID, fmt.Sprintf("%d/profile/%d/remaining/1", task.ID, profile.ID)).Scan(&n))
		require.Equal(t, 1, n)
	}
}
