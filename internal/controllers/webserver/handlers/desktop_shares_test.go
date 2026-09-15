package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func exerciseDesktopSharesRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	for i := 0; i < 27; i++ {
		if err := h.Model.Client.Share.Create().SetName(fmt.Sprintf("Scoped share %02d", i)).SetDescription("Example shared files").SetPath(`\\server\share`).SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Model.Client.Share.Create().SetName("Foreign shares must stay hidden").SetDescription("Hidden report").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			routes := []string{"/inventory/shares"}
			if user != "apple-console-admin" {
				routes = append(routes, "/shares")
			}
			for _, suffix := range routes {
				rec := request(user, "GET", prefix+"/computers/windows-fixture"+suffix, nil)
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Share inventory") || !strings.Contains(rec.Body.String(), "Scoped share 00") || strings.Contains(rec.Body.String(), "Scoped share 26") || !strings.Contains(rec.Body.String(), "Next page") {
					t.Fatal("scoped shares page failed", user, prefix, suffix, rec.Code, rec.Body.String())
				}
				next := request(user, "GET", inventoryNextURL(t, rec.Body.String()), nil)
				if next.Code != 200 || !strings.Contains(next.Body.String(), "Scoped share 26") || strings.Contains(next.Body.String(), "Scoped share 00") {
					t.Fatal("shares continuation failed", next.Code)
				}
				for _, hidden := range []string{"private-inventory-", "Foreign shares", "Confirm deletion", "Uninstall", "method=\"post\""} {
					if strings.Contains(rec.Body.String(), hidden) {
						t.Fatal("shares read exposed data or mutations", hidden)
					}
				}
			}
		}
	}
	for _, target := range []string{"inventory-foreign", "inventory-sibling", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		for _, suffix := range []string{"/inventory/shares", "/shares"} {
			if rec := request("scoped-viewer", "GET", base+"/computers/"+target+suffix+"?after=1", nil); rec.Code != 404 {
				t.Fatal("foreign share object visible", target, suffix, rec.Code)
			}
		}
	}
	if rec := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/inventory/shares", tenant, sibling), nil); rec.Code != 404 {
		t.Fatal("foreign shares URL scope accepted", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/shares?q=share+26", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scoped share 26") || strings.Contains(rec.Body.String(), "Scoped share 00") {
		t.Fatal("shares search did not filter", rec.Code, rec.Body.String())
	}
	for _, raw := range []string{"q=a&q=b", "after=-1", "after=01", "tenant=1", "q=" + strings.Repeat("x", 257)} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/shares?"+raw, nil); rec.Code != 400 {
			t.Fatal("bad shares query accepted", rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/shares?delete=true", nil); rec.Code != 400 {
		t.Fatal("legacy share deletion query accepted", rec.Code)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT shares_test_audit_failure CHECK(action<>'inventory.shares.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT shares_test_audit_failure`)
	for _, suffix := range []string{"/inventory/shares", "/shares"} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture"+suffix, nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Scoped share") || strings.Contains(rec.Body.String(), "shares_test_audit_failure") {
			t.Fatal("share audit failure leaked data", suffix, rec.Code, rec.Body.String())
		}
	}
}
