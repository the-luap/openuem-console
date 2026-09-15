package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func exerciseDesktopSecurityRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	for i := 0; i < 27; i++ {
		if err := h.Model.Client.Update.Create().SetTitle(fmt.Sprintf("Scoped update %02d", i)).SetDate(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)).SetSupportURL("https://support.invalid/update").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Model.Client.Update.Create().SetTitle("Foreign security must stay hidden").SetDate(time.Time{}).SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			routes := []string{"/computers/windows-fixture/inventory/security"}
			if user != "apple-console-admin" {
				routes = append(routes, "/security/windows-fixture/updates")
			}
			for _, suffix := range routes {
				rec := request(user, "GET", prefix+suffix, nil)
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Security report inventory") || !strings.Contains(rec.Body.String(), "Scoped update 00") || strings.Contains(rec.Body.String(), "Scoped update 26") || !strings.Contains(rec.Body.String(), "Next page") {
					t.Fatal("scoped security page failed", user, prefix, suffix, rec.Code, rec.Body.String())
				}
				next := request(user, "GET", inventoryNextURL(t, rec.Body.String()), nil)
				if next.Code != 200 || !strings.Contains(next.Body.String(), "Scoped update 26") || strings.Contains(next.Body.String(), "Scoped update 00") {
					t.Fatal("security continuation failed", next.Code)
				}
				for _, hidden := range []string{"private-inventory-", "Foreign security", "Confirm deletion", "Uninstall", "method=\"post\""} {
					if strings.Contains(rec.Body.String(), hidden) {
						t.Fatal("security read exposed data or mutations", hidden)
					}
				}
			}
		}
	}
	for _, target := range []string{"inventory-foreign", "inventory-sibling", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		for _, suffix := range []string{"/computers/" + target + "/inventory/security", "/security/" + target + "/updates"} {
			if rec := request("scoped-viewer", "GET", base+suffix+"?after=1", nil); rec.Code != 404 {
				t.Fatal("foreign update object visible", target, suffix, rec.Code)
			}
		}
	}
	if rec := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/inventory/security", tenant, sibling), nil); rec.Code != 404 {
		t.Fatal("foreign security URL scope accepted", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/security?q=update+26", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scoped update 26") || strings.Contains(rec.Body.String(), "Scoped update 00") {
		t.Fatal("security search did not filter", rec.Code, rec.Body.String())
	}
	for _, raw := range []string{"q=a&q=b", "after=-1", "after=01", "tenant=1", "q=" + strings.Repeat("x", 257)} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/security?"+raw, nil); rec.Code != 400 {
			t.Fatal("bad security query accepted", rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", base+"/security/windows-fixture/updates?delete=true", nil); rec.Code != 400 {
		t.Fatal("legacy update deletion query accepted", rec.Code)
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			if rec := request(user, "POST", prefix+"/security/windows-fixture/updates", url.Values{"q": {"update"}}); rec.Code != 403 {
				t.Fatal("legacy update POST permission changed", user, prefix, rec.Code)
			}
		}
	}

	if _, err := h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT security_test_audit_failure CHECK(action<>'inventory.security.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT security_test_audit_failure`)
	for _, suffix := range []string{"/computers/windows-fixture/inventory/security", "/security/windows-fixture/updates"} {
		if rec := request("scoped-viewer", "GET", base+suffix, nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Scoped update") || strings.Contains(rec.Body.String(), "security_test_audit_failure") {
			t.Fatal("security audit failure leaked data", suffix, rec.Code, rec.Body.String())
		}
	}
}
