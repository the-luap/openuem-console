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

func exerciseProfileDeletionScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) {
		if r.Method == http.MethodDelete {
			r.Header.Del("Content-Type")
		}
	})
	profile, err := h.Model.Client.Profile.Create().SetName("Other organization deletion target").AddTenantIDs(otherTenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(profile.ID).Exec(ctx)
	task, err := h.Model.Client.Task.Create().SetName("Foreign deletion task").SetType("powershell_script").SetProfileID(profile.ID).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Task.DeleteOneID(task.ID).Exec(ctx)
	require.Equal(t, 404, request("apple-console-admin", "DELETE", fmt.Sprintf("/tenant/%d/profiles/%d", tenant, profile.ID), nil, "console-test-token").Code)
	require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/tenant/%d/profiles/%d/confirm-delete", tenant, profile.ID), nil, "console-test-token").Code)
	_, err = h.Model.Client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	_, err = h.Model.Client.Task.Get(ctx, task.ID)
	require.NoError(t, err)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		q := h.Model.Client.Profile.Create().SetName("Owned <deletion> target")
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
		ownedTask, err := h.Model.Client.Task.Create().SetName("Owned deleted task").SetType("powershell_script").SetProfileID(owned.ID).Save(ctx)
		require.NoError(t, err)
		var report int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `INSERT INTO task_reports(task_reports,std_output) VALUES($1,'Owned deleted result') RETURNING id`, ownedTask.ID).Scan(&report))
		path := fmt.Sprintf("%s/profiles/%d", prefix, owned.ID)
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "DELETE", path, nil, "console-test-token").Code)
			require.Equal(t, 403, request(actor, "GET", path+"/confirm-delete", nil, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "DELETE", path, nil, "wrong").Code)
		require.Equal(t, 400, request("apple-console-admin", "DELETE", path+"?profile=1", nil, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "DELETE", path, url.Values{"profile": {"1"}}, "console-test-token").Code)
		w := request("apple-console-admin", "GET", path+"/confirm-delete", nil, "console-test-token")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "Owned &lt;deletion&gt; target")
		require.Contains(t, w.Body.String(), "stored results")
		require.Equal(t, 1, strings.Count(w.Body.String(), `id="main"`))
		_, err = h.Model.Client.Task.Get(ctx, ownedTask.ID)
		require.NoError(t, err)
		require.Equal(t, 200, request("apple-console-admin", "DELETE", path, nil, "console-test-token").Code)
		require.Equal(t, 404, request("apple-console-admin", "DELETE", path, nil, "console-test-token").Code)
		require.Equal(t, 404, request("apple-console-admin", "GET", path+"/confirm-delete", nil, "console-test-token").Code)
		var remaining int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM profiles WHERE id=$1)+(SELECT count(*) FROM tasks WHERE id=$2)+(SELECT count(*) FROM task_reports WHERE id=$3)`, owned.ID, ownedTask.ID, report).Scan(&remaining))
		require.Zero(t, remaining)
		var events int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.profiles.delete' AND resource_id=$3`, scope.TenantID, scope.SiteID, fmt.Sprintf("%d/tasks/1", owned.ID)).Scan(&events))
		require.Equal(t, 1, events)
	}
}
