package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func exerciseDesktopNetworkRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	for i := 0; i < 27; i++ {
		if err := h.Model.Client.NetworkAdapter.Create().SetName(fmt.Sprintf("Scoped adapter %02d", i)).SetMACAddress("AA:BB:CC:DD:EE:FF").SetAddresses("192.0.2.1").SetSpeed("1 Gbps").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Model.Client.NetworkAdapter.Create().SetName("Foreign network must stay hidden").SetMACAddress("00:11:22:33:44:55").SetAddresses("192.0.2.2").SetSpeed("1 Gbps").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			routes := []string{"/inventory/network"}
			if user != "apple-console-admin" {
				routes = append(routes, "/network-adapters")
			}
			for _, suffix := range routes {
				rec := request(user, "GET", prefix+"/computers/windows-fixture"+suffix, nil)
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Network inventory") || !strings.Contains(rec.Body.String(), "Scoped adapter 00") || strings.Contains(rec.Body.String(), "Scoped adapter 26") || !strings.Contains(rec.Body.String(), "Next page") {
					t.Fatal("scoped network page failed", user, prefix, suffix, rec.Code, rec.Body.String())
				}
				for _, hidden := range []string{"private-inventory-", "Foreign network", "Confirm deletion", "Uninstall", "method=\"post\""} {
					if strings.Contains(rec.Body.String(), hidden) {
						t.Fatal("network read exposed data or mutations", hidden)
					}
				}
			}
		}
	}
	for _, target := range []string{"inventory-foreign", "inventory-sibling", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		if rec := request("scoped-viewer", "GET", base+"/computers/"+target+"/inventory/network?after=1", nil); rec.Code != 404 {
			t.Fatal("foreign network object visible", target, rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/inventory/network", tenant, sibling), nil); rec.Code != 404 {
		t.Fatal("foreign network URL scope accepted", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/network?q=adapter+26", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scoped adapter 26") || strings.Contains(rec.Body.String(), "Scoped adapter 00") {
		t.Fatal("network search did not filter", rec.Code, rec.Body.String())
	}
	for _, raw := range []string{"q=a&q=b", "after=-1", "after=01", "tenant=1", "q=" + strings.Repeat("x", 257)} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/network?"+raw, nil); rec.Code != 400 {
			t.Fatal("bad network query accepted", rec.Code)
		}
	}
	if _, err := h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT network_test_audit_failure CHECK(action<>'inventory.network.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT network_test_audit_failure`)
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/network", nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Scoped adapter") || strings.Contains(rec.Body.String(), "network_test_audit_failure") {
		t.Fatal("network audit failure leaked data", rec.Code, rec.Body.String())
	}
}
