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

func exerciseTaskCloningScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	scopes := []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}}
	targets := []int{}
	for _, scope := range scopes {
		q := h.Model.Client.Profile.Create().SetName("Owned clone destination")
		if scope.TenantID != 0 {
			q.AddTenantIDs(tenant)
		}
		if scope.SiteID != 0 {
			q.AddSiteIDs(site)
		}
		p, err := q.Save(ctx)
		require.NoError(t, err)
		targets = append(targets, p.ID)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
	}
	for i, source := range scopes {
		prefix := ""
		q := h.Model.Client.Profile.Create().SetName("Owned task clone source")
		if source.TenantID != 0 {
			q.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if source.SiteID != 0 {
			q.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		p, err := q.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
		task, err := h.Model.Client.Task.Create().SetName("Owned <task> source").SetType("apt_install").SetAptName("owned-package").SetScript("Owned private script").SetLocalUserPassword("Owned private value").SetProfileID(p.ID).Save(ctx)
		require.NoError(t, err)
		index := (i + 1) % 3
		destination := scopes[index]
		targetID := targets[index]
		token := fmt.Sprintf("%d:%d:%d", targetID, destination.TenantID, destination.SiteID)
		path := fmt.Sprintf("%s/tasks/%d/clone", prefix, task.ID)
		form := url.Values{"source-profile": {fmt.Sprint(p.ID)}, "target": {token}, "task-description": {"Owned <copied> task"}}
		search := fmt.Sprintf("%s/targets?source-profile=%d&q=%d", path, p.ID, targetID)
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "GET", path, nil, "").Code)
			require.Equal(t, 403, request(actor, "GET", search, nil, "").Code)
			require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
		for _, bad := range []url.Values{{"task-description": {"Only name"}}, {"source-profile": {fmt.Sprint(p.ID)}, "target": {token, token}, "task-description": {"Duplicate"}}, {"source-profile": {fmt.Sprint(p.ID)}, "target": {token}, "task-description": {""}}, {"source-profile": {fmt.Sprint(p.ID)}, "target": {token}, "task-description": {"Invalid"}, "profile": {"1"}}} {
			require.Equal(t, 400, request("apple-console-admin", "POST", path, bad, "console-test-token").Code)
		}
		require.Equal(t, 400, request("apple-console-admin", "POST", path+"?target=1", form, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"?profile=1", nil, "").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"/targets?source-profile=1&q="+strings.Repeat("a", 257), nil, "").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", search+"&target=1", nil, "").Code)
		stale := url.Values{"source-profile": {fmt.Sprint(targetID)}, "target": {token}, "task-description": {"Stale source"}}
		require.Equal(t, 404, request("apple-console-admin", "POST", path, stale, "console-test-token").Code)
		w := request("apple-console-admin", "GET", path, nil, "")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "Owned &lt;task&gt; source")
		require.Contains(t, w.Body.String(), "Destination profile")
		require.NotContains(t, w.Body.String(), "Owned private")
		require.NotContains(t, w.Body.String(), "MISSING")
		require.Equal(t, 1, strings.Count(w.Body.String(), `id="main"`))
		w = request("apple-console-admin", "GET", search, nil, "")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), `value="`+token+`"`)
		require.NotContains(t, w.Body.String(), "Owned private")
		w = request("apple-console-admin", "POST", path, form, "console-test-token")
		require.Equal(t, 204, w.Code)
		expected := fmt.Sprintf("/profiles/%d", targetID)
		if destination.SiteID != 0 {
			expected = fmt.Sprintf("/site/%d", site) + expected
		}
		if destination.TenantID != 0 {
			expected = fmt.Sprintf("/tenant/%d", tenant) + expected
		}
		require.Equal(t, expected, w.Header().Get("HX-Redirect"))
		var id, version, order int
		var aptName string
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT id,version,"order",apt_name FROM tasks WHERE profile_tasks=$1 AND name=$2`, targetID, "Owned <copied> task").Scan(&id, &version, &order, &aptName))
		require.Equal(t, 1, version)
		require.Equal(t, 1, order)
		require.Equal(t, "owned-package", aptName)
		var events int
		resource := fmt.Sprintf("%d/from/%d/%d/%d/%d/to/%d/%d/%d/position/1", id, task.ID, p.ID, source.TenantID, source.SiteID, targetID, destination.TenantID, destination.SiteID)
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.clone' AND resource_id=$1`, resource).Scan(&events))
		require.Equal(t, 2, events)
		if source.SiteID != 0 {
			require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/tasks/%d/clone", task.ID), nil, "").Code)
		}
	}
}
