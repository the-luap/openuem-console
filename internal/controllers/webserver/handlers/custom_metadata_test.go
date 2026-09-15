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

func exerciseCustomMetadataRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, foreign int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	const device = "metadata-route-fixture"
	require.NoError(t, h.Model.Client.Agent.Create().SetID(device).SetHostname("Metadata route device").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	t.Cleanup(func() { require.NoError(t, h.Model.Client.Agent.DeleteOneID(device).Exec(ctx)) })
	catalog := fmt.Sprintf("/tenant/%d/admin/metadata", tenant)
	form := url.Values{"revision": {""}, "name": {"Route field <script>window.metadataOwned=true</script>"}, "description": {"Help text\nSecond line"}}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		for _, path := range []string{catalog, catalog + "/new"} {
			require.Equal(t, 403, request(actor, "GET", path, nil).Code)
			require.Equal(t, 403, request(actor, "POST", path, form).Code)
		}
	}
	w := request("organization-admin", "POST", catalog+"/new", form)
	require.Equal(t, 303, w.Code)
	fieldPath := w.Header().Get("Location")
	field := fieldPath[strings.LastIndex(fieldPath, "/")+1:]
	hidden := func(w *httptest.ResponseRecorder, key string) string {
		t.Helper()
		matches := regexp.MustCompile(`name="` + key + `" value="([^"]*)"`).FindStringSubmatch(w.Body.String())
		require.Len(t, matches, 2)
		return matches[1]
	}
	w = request("organization-admin", "GET", fieldPath, nil)
	require.Equal(t, 200, w.Code)
	require.NotContains(t, w.Body.String(), "<script>window.metadataOwned")
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	fieldRevision := hidden(w, "revision")
	require.Equal(t, 403, request("organization-admin", "GET", strings.Replace(fieldPath, fmt.Sprintf("/tenant/%d/", tenant), fmt.Sprintf("/tenant/%d/", foreign), 1), nil).Code)
	require.Equal(t, 409, request("organization-admin", "POST", catalog+"/new", form).Code)
	form.Set("revision", fieldRevision)
	form.Set("description", "Changed meaning")
	require.Equal(t, 303, request("organization-admin", "POST", fieldPath, form).Code)
	form.Set("name", "Draft </textarea><script>window.draftOwned=true</script>")
	w = request("organization-admin", "POST", fieldPath, form)
	require.Equal(t, 409, w.Code)
	require.Contains(t, w.Body.String(), "Currently saved definition")
	require.Contains(t, w.Body.String(), "Draft &lt;/textarea&gt;")
	require.NotContains(t, w.Body.String(), "<script>window.draftOwned")
	valuePath := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/metadata/%s", tenant, site, device, field)
	valueForm := func(w *httptest.ResponseRecorder) url.Values {
		return url.Values{"field_revision": {hidden(w, "field_revision")}, "revision": {hidden(w, "revision")}, "value": {"Private route value\nSecond line"}}
	}
	for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
		base := prefix + "/computers/" + device + "/metadata"
		for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
			require.Equal(t, 403, request(actor, "GET", base, nil).Code)
			require.Equal(t, 403, request(actor, "GET", base+"/"+field, nil).Code)
			require.Equal(t, 403, request(actor, "POST", base+"/"+field, url.Values{}).Code)
		}
		w = request("organization-admin", "GET", base, nil)
		require.Equal(t, 200, w.Code)
		require.NotContains(t, w.Body.String(), "Private route value")
		w = request("organization-admin", "GET", base+"/"+field, nil)
		require.Equal(t, 200, w.Code)
		require.Equal(t, 303, request("organization-admin", "POST", base+"/"+field, valueForm(w)).Code)
		for _, method := range []string{"POST", "DELETE"} {
			require.Equal(t, 405, request("apple-console-admin", method, base, url.Values{"orgMetadataId": {field}, "value": {"Unreviewed"}}).Code)
		}
	}
	values := valueForm(request("organization-admin", "GET", valuePath, nil))
	for _, kind := range []string{"csrf", "missing", "duplicate", "unknown", "revision", "limit", "query", "wire-limit"} {
		f := url.Values{}
		for k, v := range values {
			f[k] = append([]string{}, v...)
		}
		path, want := valuePath, 400
		switch kind {
		case "csrf":
			f.Set("csrf", "wrong")
			want = 403
		case "missing":
			f.Del("value")
		case "duplicate":
			f.Add("revision", f.Get("revision"))
		case "unknown":
			f.Set("tenant", "9999")
		case "revision":
			f.Set("revision", "bad")
		case "limit":
			f.Set("value", strings.Repeat("x", 16385))
		case "query":
			path += "?value=Override"
		case "wire-limit":
			f.Set("value", strings.Repeat("x", 65<<10))
			want = 413
		}
		require.Equal(t, want, request("organization-admin", "POST", path, f).Code, kind)
	}
	for _, id := range []string{"inventory-foreign", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		for _, method := range []string{"GET", "POST"} {
			require.Equal(t, 404, request("organization-admin", method, strings.Replace(valuePath, device, id, 1), values).Code, id)
		}
	}
	_, err := h.Model.DB.ExecContext(ctx, `UPDATE metadata SET value='Concurrent saved value' WHERE agent_metadata=$1`, device)
	require.NoError(t, err)
	values.Set("value", "Draft </textarea><script>window.draftOwned=true</script>")
	w = request("organization-admin", "POST", valuePath, values)
	require.Equal(t, 409, w.Code)
	require.Contains(t, w.Body.String(), "Concurrent saved value")
	require.Contains(t, w.Body.String(), "Draft &lt;/textarea&gt;")
	require.NotContains(t, w.Body.String(), "<script>window.draftOwned")
	values = valueForm(request("organization-admin", "GET", valuePath, nil))
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT route_metadata_failure CHECK(action NOT LIKE 'inventory.metadata.%') NOT VALID`)
	require.NoError(t, err)
	w = request("organization-admin", "POST", valuePath, values)
	require.Equal(t, 503, w.Code)
	require.NotContains(t, w.Body.String(), "route_metadata_failure")
	require.Equal(t, 503, request("organization-admin", "GET", valuePath, nil).Code)
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT route_metadata_failure`)
	require.NoError(t, err)
	clear := url.Values{"field_revision": values["field_revision"], "revision": values["revision"], "confirm": {"clear"}}
	require.Equal(t, 303, request("organization-admin", "POST", valuePath+"/clear", clear).Code)
	w = request("organization-admin", "GET", valuePath, nil)
	require.Contains(t, w.Body.String(), "No value is configured")
	require.Equal(t, 303, request("organization-admin", "POST", valuePath, valueForm(w)).Code)
	fieldRevision = hidden(request("organization-admin", "GET", fieldPath, nil), "revision")
	w = request("organization-admin", "POST", fieldPath+"/deletion", url.Values{"revision": {fieldRevision}})
	require.Equal(t, 303, w.Code)
	receiptPath := w.Header().Get("Location")
	w = request("organization-admin", "GET", receiptPath, nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Devices with a configured value")
	require.Equal(t, 400, request("organization-admin", "POST", receiptPath, url.Values{}).Code)
	require.Equal(t, 404, request("apple-console-admin", "POST", receiptPath, url.Values{"confirm": {"delete"}}).Code)
	require.Equal(t, 303, request("organization-admin", "POST", receiptPath, url.Values{"confirm": {"delete"}}).Code)
	require.Equal(t, 303, request("organization-admin", "POST", receiptPath, url.Values{"confirm": {"delete"}}).Code)
	w = request("organization-admin", "GET", receiptPath, nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Field and values deleted")
	require.NotContains(t, w.Body.String(), `name="confirm"`)
	require.Equal(t, 404, request("organization-admin", "GET", valuePath, nil).Code)
	for _, method := range []string{"POST", "DELETE"} {
		require.Equal(t, 405, request("apple-console-admin", method, catalog, url.Values{"orgMetadataId": {field}, "name": {"Unreviewed"}}).Code)
	}
}
