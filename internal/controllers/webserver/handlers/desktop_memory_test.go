package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func exerciseDesktopMemoryRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	for i := 0; i < 27; i++ {
		if err := h.Model.Client.MemorySlot.Create().SetSlot(fmt.Sprintf("Scoped module %02d", i)).SetManufacturer("Example Modules").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Model.Client.MemorySlot.Create().SetSlot("Foreign memory must stay hidden").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			routes := []string{"/inventory/memory"}
			for _, suffix := range routes {
				rec := request(user, "GET", prefix+"/computers/windows-fixture"+suffix, nil)
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Memory module inventory") || !strings.Contains(rec.Body.String(), "Scoped module 00") || strings.Contains(rec.Body.String(), "Scoped module 26") || !strings.Contains(rec.Body.String(), "Next page") {
					t.Fatal("scoped memory page failed", user, prefix, suffix, rec.Code, rec.Body.String())
				}
				next := request(user, "GET", inventoryNextURL(t, rec.Body.String()), nil)
				if next.Code != 200 || !strings.Contains(next.Body.String(), "Scoped module 26") || strings.Contains(next.Body.String(), "Scoped module 00") {
					t.Fatal("memory continuation failed", next.Code)
				}
				for _, hidden := range []string{"private-inventory-", "Foreign memory", "Confirm deletion", "Uninstall", "method=\"post\""} {
					if strings.Contains(rec.Body.String(), hidden) {
						t.Fatal("memory read exposed data or mutations", hidden)
					}
				}
			}
		}
	}
	for _, target := range []string{"inventory-foreign", "inventory-sibling", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		if rec := request("scoped-viewer", "GET", base+"/computers/"+target+"/inventory/memory?after=1", nil); rec.Code != 404 {
			t.Fatal("foreign memory object visible", target, rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/inventory/memory", tenant, sibling), nil); rec.Code != 404 {
		t.Fatal("foreign memory URL scope accepted", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/memory?q=module+26", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scoped module 26") || strings.Contains(rec.Body.String(), "Scoped module 00") {
		t.Fatal("memory search did not filter", rec.Code, rec.Body.String())
	}
	for _, raw := range []string{"q=a&q=b", "after=-1", "after=01", "tenant=1", "q=" + strings.Repeat("x", 257)} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/memory?"+raw, nil); rec.Code != 400 {
			t.Fatal("bad memory query accepted", rec.Code)
		}
	}
	if _, err := h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT memory_test_audit_failure CHECK(action<>'inventory.memory.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT memory_test_audit_failure`)
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/memory", nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Scoped module") || strings.Contains(rec.Body.String(), "memory_test_audit_failure") {
		t.Fatal("memory audit failure leaked data", rec.Code, rec.Body.String())
	}
}
