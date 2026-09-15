package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/open-uem/ent/agent"
	"github.com/stretchr/testify/require"
)

func exerciseDeviceDetailsRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	const device = "details-route-fixture"
	require.NoError(t, h.Model.Client.Agent.Create().SetID(device).SetHostname("Reported route hostname").SetNickname("Original name").SetDescription("Original description").SetOs("windows").SetEndpointType(agent.EndpointTypeOther).SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	t.Cleanup(func() { require.NoError(t, h.Model.Client.Agent.DeleteOneID(device).Exec(ctx)) })
	base := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/details", tenant, site, device)
	form := func(revision string) url.Values {
		return url.Values{"revision": {revision}, "nickname": {"Updated display name"}, "description": {"Updated description\nsecond line"}, "endpoint_type": {"Laptop"}}
	}
	revision := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		require.Equal(t, 200, w.Code)
		parts := regexp.MustCompile(`name="revision" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		require.Len(t, parts, 2)
		return parts[1]
	}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
			for _, method := range []string{"GET", "POST"} {
				require.Equal(t, 403, request(actor, method, prefix+"/computers/"+device+"/details", form("bad")).Code)
			}
		}
	}
	for _, actor := range []string{"organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
			path := prefix + "/computers/" + device + "/details"
			w := request(actor, "GET", path, nil)
			r := revision(w)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Contains(t, w.Body.String(), "Reported route hostname")
			w = request(actor, "POST", path, form(r))
			require.Equal(t, 303, w.Code)
			require.True(t, strings.HasSuffix(w.Header().Get("Location"), "/details"))
		}
	}
	r := revision(request("organization-admin", "GET", base, nil))
	for _, kind := range []string{"csrf", "missing", "duplicate", "unknown", "revision", "type", "nickname-limit", "description-limit", "query", "wire-limit"} {
		values := form(r)
		path, want := base, 400
		switch kind {
		case "csrf":
			values.Set("csrf", "wrong")
			want = 403
		case "missing":
			values.Del("nickname")
		case "duplicate":
			values.Add("description", "Duplicate")
		case "unknown":
			values.Set("tenant", "9999")
		case "revision":
			values.Set("revision", "missing")
		case "type":
			values.Set("endpoint_type", "Unknown")
		case "nickname-limit":
			values.Set("nickname", strings.Repeat("é", 128))
		case "description-limit":
			values.Set("description", strings.Repeat("d", 4097))
		case "query":
			path += "?nickname=Override"
		case "wire-limit":
			values.Set("description", strings.Repeat("x", 33<<10))
			want = 413
		}
		require.Equal(t, want, request("organization-admin", "POST", path, values).Code, kind)
	}
	require.Equal(t, 400, request("organization-admin", "GET", base+"?extra=1", nil).Code)
	for _, id := range []string{"inventory-foreign", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		for _, method := range []string{"GET", "POST"} {
			require.Equal(t, 404, request("organization-admin", method, strings.Replace(base, device, id, 1), form(r)).Code, id)
		}
	}
	// Old forms have no displayed revision and must not write any of the fields.
	for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
		for _, suffix := range []string{"/overview", "/nickname"} {
			w := request("apple-console-admin", "POST", prefix+"/computers/"+device+suffix, url.Values{"nickname": {"Unreviewed name"}, "endpoint-description": {"Unreviewed description"}, "endpoint-type": {"Server"}})
			require.Equal(t, 303, w.Code)
			require.True(t, strings.HasSuffix(w.Header().Get("Location"), "/details"))
		}
	}
	stored, err := h.Model.Client.Agent.Get(ctx, device)
	require.NoError(t, err)
	require.Equal(t, "Updated display name", stored.Nickname)
	require.Equal(t, agent.EndpointTypeLaptop, stored.EndpointType)
	require.NoError(t, h.Model.Client.Agent.UpdateOneID(device).SetDescription("Concurrent saved description").Exec(ctx))
	values := form(r)
	values.Set("nickname", `Draft <script>window.detailsOwned=true</script>`)
	w := request("organization-admin", "POST", base, values)
	require.Equal(t, 409, w.Code)
	require.Contains(t, w.Body.String(), "Draft &lt;script&gt;")
	require.NotContains(t, w.Body.String(), "<script>window.detailsOwned")
	require.Contains(t, w.Body.String(), "Concurrent saved description")
	require.Contains(t, w.Body.String(), "Your draft is preserved")
	r = revision(request("organization-admin", "GET", base, nil))
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT route_details_failure CHECK(action<>'inventory.details.update') NOT VALID`)
	require.NoError(t, err)
	w = request("organization-admin", "POST", base, form(r))
	require.Equal(t, 503, w.Code)
	require.NotContains(t, w.Body.String(), "route_details_failure")
	stored, err = h.Model.Client.Agent.Get(ctx, device)
	require.NoError(t, err)
	require.Equal(t, "Concurrent saved description", stored.Description)
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT route_details_failure`)
	require.NoError(t, err)
	values = form(r)
	values.Set("nickname", "")
	values.Set("description", "")
	w = request("organization-admin", "POST", base, values)
	require.Equal(t, 303, w.Code)
	w = request("organization-admin", "GET", w.Header().Get("Location"), nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Reported route hostname")
	stored, err = h.Model.Client.Agent.Get(ctx, device)
	require.NoError(t, err)
	require.Empty(t, stored.Nickname)
	require.Empty(t, stored.Description)
}
