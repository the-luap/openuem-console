package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseProfileIssueHistory(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	request := ownedTagHTTPRequest(t, h, e, ctx)
	orphan, err := h.Model.Client.ProfileIssue.Create().SetError("Unrelated orphan must remain").Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.ProfileIssue.DeleteOneID(orphan.ID).Exec(ctx)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		q := h.Model.Client.Profile.Create().SetName("Owned history <profile>")
		prefix := ""
		if scope.TenantID != 0 {
			q.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			q.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		p, err := q.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
		task, err := h.Model.Client.Task.Create().SetName("Owned disabled history task").SetType("unix_script").SetProfileID(p.ID).SetDisabled(true).SetScript("private-history-route-script").SetLocalUserPassword("private-history-route-password").Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Task.DeleteOneID(task.ID).Exec(ctx)
		issue, err := h.Model.Client.ProfileIssue.Create().SetProfileID(p.ID).SetError("Owned history error").Save(ctx)
		require.NoError(t, err)
		_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO task_reports(profile_issue_tasksreports,task_reports,std_output,std_error,failed,"end") VALUES($1,$2,'Owned <stdout>','Owned <stderr>',true,'invalid owned timestamp')`, issue.ID, task.ID)
		require.NoError(t, err)
		path := fmt.Sprintf("%s/profiles/%d/issues", prefix, p.ID)
		detail := fmt.Sprintf("%s/%d", path, issue.ID)
		for _, target := range []string{path, detail} {
			for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
				require.Equal(t, 403, request(actor, "GET", target, nil, "console-test-token").Code)
			}
			for _, query := range []string{"page=0", "page=01", "page=1&page=2", "unknown=x", "page=1000001"} {
				require.Equal(t, 400, request("apple-console-admin", "GET", target+"?"+query, nil, "console-test-token").Code)
			}
			w := request("apple-console-admin", "GET", target, nil, "console-test-token")
			require.Equal(t, 200, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Contains(t, w.Body.String(), "Endpoint no longer available")
			require.NotContains(t, w.Body.String(), "private-history-route-")
		}
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"?pageSize=101", nil, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", detail+"?pageSize=25", nil, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", detail+"?issuePageSize=101", nil, "console-test-token").Code)
		compressed := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") })
		require.Equal(t, 400, compressed("apple-console-admin", "GET", path, nil, "console-test-token").Code)
		wrong := fmt.Sprintf("/profiles/%d/issues", p.ID)
		if prefix == "" {
			wrong = fmt.Sprintf("/tenant/%d/profiles/%d/issues", tenant, p.ID)
		}
		require.Equal(t, 404, request("apple-console-admin", "GET", wrong, nil, "console-test-token").Code)
		require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("%s/%d", wrong, issue.ID), nil, "console-test-token").Code)
		require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("%s/%d", path, orphan.ID), nil, "console-test-token").Code)
		list := request("apple-console-admin", "GET", path+"?page=99&pageSize=5", nil, "console-test-token").Body.String()
		require.NotContains(t, list, "Owned &lt;stdout&gt;")
		require.NotContains(t, list, "Owned disabled history task")
		require.Contains(t, list, "1 failed task reports")
		reports := request("apple-console-admin", "GET", detail+"?page=99&issuePage=2&issuePageSize=5", nil, "console-test-token").Body.String()
		require.Contains(t, reports, "Owned &lt;stdout&gt;")
		require.Contains(t, reports, "Owned &lt;stderr&gt;")
		require.Contains(t, reports, "Task is currently disabled.")
		require.Contains(t, reports, "invalid owned timestamp")
		require.Contains(t, reports, "page=2&amp;pageSize=5")
		_, err = h.Model.DB.ExecContext(ctx, `CREATE FUNCTION reject_owned_history_route() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('inventory.profile_issues.list','inventory.profile_issues.read') THEN RAISE EXCEPTION 'private history route audit'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_history_route BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_history_route()`)
		require.NoError(t, err)
		for _, target := range []string{path, detail} {
			w := request("apple-console-admin", "GET", target, nil, "console-test-token")
			require.Equal(t, 503, w.Code)
			require.NotContains(t, w.Body.String(), "private history route audit")
			require.NotContains(t, w.Body.String(), "Owned history")
		}
		_, err = h.Model.DB.ExecContext(ctx, `DROP TRIGGER reject_owned_history_route ON uem_inventory_audit; DROP FUNCTION reject_owned_history_route()`)
		require.NoError(t, err)
		for _, id := range []int{orphan.ID, issue.ID} {
			found, err := h.Model.Client.ProfileIssue.Get(ctx, id)
			require.NoError(t, err)
			require.False(t, strings.Contains(found.Error, "deleted"))
		}
	}
}
