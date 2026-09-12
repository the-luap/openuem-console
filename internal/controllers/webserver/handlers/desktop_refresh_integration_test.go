package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
)

func exerciseDesktopRefreshRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	previous := h.InventoryRefresh
	defer func() { h.InventoryRefresh = previous }()
	var calls int
	store, err := inventory.NewRefreshStore(h.Model.DB, h.Access, false, func(context.Context, string, string) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h.InventoryRefresh = store
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		rec := request(user, "GET", base+"/computers/windows-fixture/inventory", nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "Request fresh inventory") != (user != "scoped-viewer") {
			t.Fatal("refresh control does not follow capabilities", user, rec.Code, rec.Body.String())
		}
	}
	for _, form := range []url.Values{
		{"request_id": {uuid.NewString()}, "csrf": {"wrong"}},
		{"request_id": {uuid.NewString(), uuid.NewString()}},
		{"request_id": {uuid.NewString()}, "site": {fmt.Sprint(sibling)}},
		{"request_id": {uuid.NewString()}, "tenant": {fmt.Sprint(tenant)}},
		{"request_id": {uuid.NewString()}, "unexpected": {strings.Repeat("x", 9000)}},
		{"request_id": {"not-a-request"}},
		{},
	} {
		rec := request("scoped-operator", "POST", base+"/computers/windows-fixture/refresh", form)
		if rec.Code != 400 && rec.Code != 403 {
			t.Fatal("ambiguous refresh form accepted", rec.Code)
		}
	}
	for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
		for _, route := range []string{"/computers/windows-fixture/refresh", "/agents/windows-fixture/forcereport"} {
			if rec := request("scoped-viewer", "POST", prefix+route, url.Values{"request_id": {uuid.NewString()}}); rec.Code != 403 {
				t.Fatal("viewer queued inventory", rec.Code)
			}
		}
	}
	if rec := request("scoped-operator", "POST", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/refresh", tenant, sibling), url.Values{"request_id": {uuid.NewString()}}); rec.Code != 404 {
		t.Fatal("foreign URL scope accepted", rec.Code)
	}
	if rec := request("scoped-operator", "POST", base+"/computers/inventory-ambiguous/refresh", url.Values{"request_id": {uuid.NewString()}}); rec.Code != 404 {
		t.Fatal("ambiguous object accepted", rec.Code)
	}
	var count int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_refresh`).Scan(&count); err != nil || count != 0 || calls != 0 {
		t.Fatal("rejected form created work", count, calls, err)
	}
	for _, user := range []string{"scoped-operator", "organization-admin", "apple-console-admin"} {
		id, nonce := uuid.NewString(), uuid.NewString()
		if err = h.Model.Client.Agent.Create().SetID(id).SetHostname("Refresh route fixture").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			for _, route := range []string{"/computers/" + id + "/refresh", "/agents/" + id + "/forcereport"} {
				rec := request(user, "POST", prefix+route, url.Values{"request_id": {nonce}})
				if rec.Code != 303 || !strings.HasSuffix(rec.Header().Get("Location"), "/computers/"+id+"/inventory") {
					t.Fatal("authorized refresh failed", user, route, rec.Code, rec.Body.String())
				}
			}
		}
		rec := request(user, "GET", base+"/computers/"+id+"/inventory", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Waiting to send") || strings.Contains(rec.Body.String(), "Request fresh inventory") {
			t.Fatal("pending state or duplicate control incorrect", rec.Code, rec.Body.String())
		}
		if found, err := store.DispatchOne(ctx); !found || err != nil {
			t.Fatal("retained refresh not dispatched", found, err)
		}
		rec = request(user, "GET", base+"/computers/"+id+"/inventory", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Accepted for delivery") || !strings.Contains(rec.Body.String(), "The device must still collect") {
			t.Fatal("broker acceptance misrepresented", rec.Code, rec.Body.String())
		}
		if rec = request(user, "POST", base+"/computers/"+id+"/refresh", url.Values{"request_id": {uuid.NewString()}}); rec.Code != 429 {
			t.Fatal("refresh cooldown bypassed", rec.Code)
		}
	}
	if calls != 3 {
		t.Fatal("route retries published duplicate requests", calls)
	}
}
