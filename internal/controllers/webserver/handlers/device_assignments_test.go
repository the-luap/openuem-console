package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/open-uem/ent/agent"
	"github.com/stretchr/testify/require"
)

func exerciseDeviceAssignmentRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling, foreignSite int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	const device = "assignment-route-fixture"
	t.Cleanup(func() { require.NoError(t, h.Model.Client.Agent.DeleteOneID(device).Exec(ctx)) })
	require.NoError(t, h.Model.Client.Agent.Create().SetID(device).SetHostname("Assignment route device").SetDescription("Original description").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	base := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/assignment", tenant, site, device)
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
			for _, method := range []string{"GET", "POST"} {
				w := request(actor, method, prefix+"/computers/"+device+"/assignment", url.Values{"destination_site": {strconv.Itoa(sibling)}})
				require.Equal(t, 403, w.Code)
			}
		}
	}
	for _, actor := range []string{"organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
			path := prefix + "/computers/" + device + "/assignment"
			w := request(actor, "GET", path, nil)
			require.Equal(t, 200, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Contains(t, w.Body.String(), "Choose a destination site")
			w = request(actor, "POST", path, url.Values{"destination_site": {strconv.Itoa(sibling)}})
			require.Equal(t, 303, w.Code)
			receipt := w.Header().Get("Location")
			w = request(actor, "GET", receipt, nil)
			require.Equal(t, 200, w.Code)
			require.Contains(t, w.Body.String(), "Moving within the same organization keeps")
			require.Contains(t, w.Body.String(), `name="confirm"`)
		}
	}
	for _, test := range []string{"csrf", "duplicate", "missing", "mixed", "query", "oversized"} {
		form := url.Values{"destination_site": {strconv.Itoa(sibling)}}
		path, want := base, 400
		switch test {
		case "csrf":
			form.Set("csrf", "wrong")
			want = 403
		case "duplicate":
			form.Add("destination_site", strconv.Itoa(sibling))
		case "missing":
			form.Del("destination_site")
		case "mixed":
			form.Set("tenant", "999999")
		case "query":
			path += "?destination_site=1"
		case "oversized":
			form.Set("destination_site", strings.Repeat("1", 9000))
			want = 413
		}
		require.Equal(t, want, request("organization-admin", "POST", path, form).Code, test)
	}
	for _, query := range []string{"q=%", "q=first&q=second", "after=-1", "unknown=value", "q=" + strings.Repeat("a", 17<<10)} {
		require.Equal(t, 400, request("organization-admin", "GET", base+"?"+query, nil).Code)
	}
	require.Equal(t, 403, request("organization-admin", "POST", base, url.Values{"destination_site": {strconv.Itoa(foreignSite)}}).Code)
	for _, target := range []string{"inventory-foreign", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		w := request("organization-admin", "GET", strings.Replace(base, device, target, 1), nil)
		require.Equal(t, 404, w.Code, target)
	}
	// Old overview submissions only open the reviewed workflow. They cannot
	// change the description first and then partially perform an invalid move.
	for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
		w := request("apple-console-admin", "POST", prefix+"/computers/"+device+"/overview", url.Values{"tenant": {"999999"}, "site": {strconv.Itoa(foreignSite)}, "endpoint-description": {"Must not be saved"}})
		require.Equal(t, 303, w.Code)
		require.True(t, strings.HasSuffix(w.Header().Get("Location"), "/assignment"))
	}
	stored, err := h.Model.Client.Agent.Get(ctx, device)
	require.NoError(t, err)
	require.Equal(t, "Original description", stored.Description)
	w := request("organization-admin", "POST", base, url.Values{"destination_site": {strconv.Itoa(sibling)}})
	require.Equal(t, 303, w.Code)
	receipt := w.Header().Get("Location")
	require.Equal(t, 400, request("organization-admin", "POST", receipt, url.Values{}).Code)
	require.Equal(t, 403, request("organization-admin", "POST", receipt, url.Values{"confirm": {"yes"}, "csrf": {"wrong"}}).Code)
	require.Equal(t, 400, request("organization-admin", "POST", receipt, url.Values{"confirm": {"yes"}, "destination_site": {strconv.Itoa(foreignSite)}}).Code)
	require.NoError(t, h.Model.Client.Agent.UpdateOneID(device).SetNotes("Changed private notes").Exec(ctx))
	w = request("organization-admin", "POST", receipt, url.Values{"confirm": {"yes"}})
	require.Equal(t, 409, w.Code)
	require.Contains(t, w.Body.String(), "Nothing was moved by this request")
	require.NotContains(t, w.Body.String(), "Changed private notes")
	w = request("organization-admin", "POST", base, url.Values{"destination_site": {strconv.Itoa(sibling)}})
	require.Equal(t, 303, w.Code)
	receipt = w.Header().Get("Location")
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT route_assignment_failure CHECK(action<>'inventory.assignment.arrive') NOT VALID`)
	require.NoError(t, err)
	w = request("organization-admin", "POST", receipt, url.Values{"confirm": {"yes"}})
	require.Equal(t, 503, w.Code)
	require.NotContains(t, w.Body.String(), "route_assignment_failure")
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT route_assignment_failure`)
	require.NoError(t, err)
	w = request("organization-admin", "POST", receipt, url.Values{"confirm": {"yes"}})
	require.Equal(t, 303, w.Code)
	w = request("organization-admin", "GET", w.Header().Get("Location"), nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Device moved")
	require.NotContains(t, w.Body.String(), `name="confirm"`)
	for range 2 {
		require.Equal(t, 303, request("organization-admin", "POST", receipt, url.Values{"confirm": {"yes"}}).Code)
	}
	var actual int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT site_id FROM site_agents WHERE agent_id=$1`, device).Scan(&actual))
	require.Equal(t, sibling, actual)
}
