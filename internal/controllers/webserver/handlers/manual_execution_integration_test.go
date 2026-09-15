package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

func exerciseManualExecutionRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	previous := h.ManualExecution
	defer func() { h.ManualExecution = previous }()
	calls := 0
	store, err := inventory.NewManualExecutionStore(h.Model.DB, h.Access, false, strings.Repeat("k", 32), func(context.Context, string, string, *taskexecution.Payload) error { calls++; return nil })
	require.NoError(t, err)
	require.NoError(t, inventory.Migrate(ctx, h.Model.DB))
	h.ManualExecution = store
	request := ownedTagHTTPRequest(t, h, e, ctx)
	id := uuid.NewString()
	require.NoError(t, h.Model.Client.Agent.Create().SetID(id).SetHostname("Owned <manual endpoint>").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	defer h.Model.Client.Agent.DeleteOneID(id).Exec(ctx)
	p, err := h.Model.Client.Profile.Create().SetName("Owned <manual profile>").AddTenantIDs(tenant).AddSiteIDs(site).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
	source, err := h.Model.Client.Task.Create().SetName("Owned <manual task>").SetProfileID(p.ID).SetType(task.TypePowershellScript).SetAgentType(task.AgentTypeWindows).SetScript("owned-private-manual-script").SetVersion(3).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Task.DeleteOneID(source.ID).Exec(ctx)
	path := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/execution", tenant, site, id)
	reviewPath := path + fmt.Sprintf("/review?kind=task&source_id=%d&q=Owned", source.ID)
	for _, target := range []string{path, reviewPath} {
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "GET", target, nil, "console-test-token").Code)
		}
		response := request("apple-console-admin", "GET", target, nil, "console-test-token")
		require.Equal(t, 200, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.NotContains(t, response.Body.String(), "owned-private-manual-script")
		require.Contains(t, response.Body.String(), "Owned &lt;manual")
	}
	for _, query := range []string{"kind=unknown", "kind=task&kind=profile", "q=" + strings.Repeat("x", 257), "q=%00", "unknown=value", "q=%zz"} {
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"?"+query, nil, "console-test-token").Code)
	}
	for _, sourceID := range []string{"0", "01", "-1", "unknown"} {
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"/review?source_id="+sourceID, nil, "console-test-token").Code)
	}
	scope := access.Scope{TenantID: tenant, SiteID: site}
	review, err := store.Review(ctx, "apple-console-admin", scope, id, "task", int64(source.ID))
	require.NoError(t, err)
	form := url.Values{"csrf": {"console-test-token"}, "kind": {"task"}, "source_id": {fmt.Sprint(source.ID)}, "revision": {review.Source.Revision}, "request_id": {uuid.NewString()}, "confirmed": {"yes"}}
	for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
		require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
	}
	for _, alter := range []func(url.Values){
		func(v url.Values) { v.Del("confirmed") },
		func(v url.Values) { v["confirmed"] = []string{"no"} },
		func(v url.Values) { v.Add("confirmed", "yes") },
		func(v url.Values) { v.Set("request_id", "invalid") },
		func(v url.Values) { v.Set("revision", strings.Repeat("a", 63)) },
		func(v url.Values) { v.Set("secret", "unexpected") },
		func(v url.Values) { v.Set("source_id", "01") },
	} {
		invalid := url.Values{}
		for key, value := range form {
			invalid[key] = append([]string(nil), value...)
		}
		alter(invalid)
		require.Equal(t, 400, request("apple-console-admin", "POST", path, invalid, "console-test-token").Code)
	}
	require.Equal(t, 400, request("apple-console-admin", "POST", path+"?confirmed=yes", form, "console-test-token").Code)
	badToken := url.Values{}
	for key, value := range form {
		badToken[key] = value
	}
	badToken.Set("csrf", "wrong")
	require.Equal(t, 403, request("apple-console-admin", "POST", path, badToken, "console-test-token").Code)
	compressed := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") })
	require.Equal(t, 400, compressed("apple-console-admin", "POST", path, form, "console-test-token").Code)
	oversized := url.Values{"csrf": {"console-test-token"}, "confirmed": {strings.Repeat("x", 8193)}}
	require.Equal(t, 413, request("apple-console-admin", "POST", path, oversized, "console-test-token").Code)
	require.Zero(t, calls)
	admitted := request("apple-console-admin", "POST", path, form, "console-test-token")
	require.Equal(t, 204, admitted.Code)
	receiptPath := path + "/" + form.Get("request_id")
	require.Equal(t, receiptPath, admitted.Header().Get("HX-Redirect"))
	require.Zero(t, calls, "HTTP admission must not publish")
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	queued := request("apple-console-admin", "GET", receiptPath, nil, "console-test-token")
	require.Equal(t, 200, queued.Code)
	require.Contains(t, queued.Body.String(), "Queued for a single delivery attempt")
	worked, err := store.DispatchOne(ctx)
	require.NoError(t, err)
	require.True(t, worked)
	require.Equal(t, 1, calls)
	accepted := request("apple-console-admin", "GET", receiptPath, nil, "console-test-token")
	require.Equal(t, 200, accepted.Code)
	require.Contains(t, accepted.Body.String(), "Accepted by the agent")
	require.Contains(t, accepted.Body.String(), "It does not confirm execution or success")
	require.NotContains(t, accepted.Body.String(), "owned-private")
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	require.Equal(t, 1, calls)
	// Both former execution URLs now require the reviewed envelope.
	for _, route := range []string{"/runtask", "/runprofile"} {
		legacy := strings.TrimSuffix(path, "/execution") + route
		bad := url.Values{"csrf": {"console-test-token"}, "task": {fmt.Sprint(source.ID)}, "profile": {fmt.Sprint(p.ID)}}
		require.Equal(t, 400, request("apple-console-admin", "POST", legacy, bad, "console-test-token").Code)
	}
	profileReview, err := store.Review(ctx, "apple-console-admin", scope, id, "profile", int64(p.ID))
	require.NoError(t, err)
	nativeForm := url.Values{"csrf": {"console-test-token"}, "kind": {"profile"}, "source_id": {fmt.Sprint(p.ID)}, "revision": {profileReview.Source.Revision}, "request_id": {uuid.NewString()}, "confirmed": {"yes"}}
	nativeForm.Set("csrf", strings.Repeat("t", 32))
	native := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) {
		r.Header.Del("HX-Request")
		r.Header.Del("X-CSRF-Token")
	})
	nativeResponse := native("apple-console-admin", "POST", strings.TrimSuffix(path, "/execution")+"/runprofile", nativeForm, "console-test-token")
	require.Equal(t, 303, nativeResponse.Code)
	require.Equal(t, path+"/"+nativeForm.Get("request_id"), nativeResponse.Header().Get("Location"))
	_, err = store.DispatchOne(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, calls)

	issue, err := h.Model.Client.ProfileIssue.Create().SetProfileID(p.ID).SetAgentsID(id).Save(ctx)
	require.NoError(t, err)
	_, err = h.Model.Client.TaskReport.Create().SetProfileissueID(issue.ID).SetTaskID(source.ID).SetStdOutput("Owned <manual report>").SetFailed(true).SetEnd("invalid owned completion").Save(ctx)
	require.NoError(t, err)
	historyPath := strings.TrimSuffix(path, "/execution") + "/tasks"
	history := request("apple-console-admin", "GET", historyPath+"?page=99&pageSize=5", nil, "console-test-token")
	require.Equal(t, 200, history.Code)
	require.Contains(t, history.Body.String(), "Owned &lt;manual report&gt;")
	require.Contains(t, history.Body.String(), "invalid owned completion")
	require.NotContains(t, history.Body.String(), "owned-private-manual-script")
	require.Contains(t, history.Body.String(), fmt.Sprintf("source_id=%d", source.ID))
	for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
		require.Equal(t, 403, request(actor, "GET", historyPath, nil, "console-test-token").Code)
	}
	for _, query := range []string{"page=0", "page=01", "pageSize=101", "page=1&page=2", "sortBy=name", "unknown=value"} {
		require.Equal(t, 400, request("apple-console-admin", "GET", historyPath+"?"+query, nil, "console-test-token").Code)
	}
	require.NoError(t, h.Model.Client.Agent.DeleteOneID(id).Exec(ctx))
	require.Equal(t, 200, request("apple-console-admin", "GET", receiptPath, nil, "console-test-token").Code)
	for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
		require.Equal(t, 403, request(actor, "GET", receiptPath, nil, "console-test-token").Code)
	}
}
