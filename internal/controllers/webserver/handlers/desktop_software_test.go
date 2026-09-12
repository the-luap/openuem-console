package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDesktopReportFilterRejectsAmbiguousQuery(t *testing.T) {
	for _, raw := range []string{"q=a&q=b", "q=%ff", "q=%00", "q=%zz", "q=" + strings.Repeat("x", 257), "q=" + strings.Repeat("%20", 1500), "after=", "after=0", "after=-1", "after=01", "after=+1", "after=1&after=2", "after=9223372036854775808", "tenant=1", "q=a;after=2"} {
		if _, err := desktopReportFilter(raw); err == nil {
			t.Error("ambiguous report filter accepted", raw)
		}
	}
	if got, err := desktopReportFilter("q=%25_%26&after=42"); err != nil || got.Search != "%_&" || got.After != 42 {
		t.Fatal("literal search or cursor changed", got, err)
	}
}

func exerciseDesktopSoftwareRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	for i := 0; i < 27; i++ {
		if err := h.Model.Client.App.Create().SetName(fmt.Sprintf("Scoped application %02d", i)).SetVersion("1.0").SetPublisher("Example publisher").SetInstallDate("20260911").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Model.Client.App.Create().SetName("Foreign software must stay hidden").SetVersion("1").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			routes := []string{"/inventory/software"}
			if user != "apple-console-admin" {
				routes = append(routes, "/software")
			}
			for _, suffix := range routes {
				rec := request(user, "GET", prefix+"/computers/windows-fixture"+suffix, nil)
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Software inventory") || !strings.Contains(rec.Body.String(), "Scoped application 00") || strings.Contains(rec.Body.String(), "Scoped application 26") || !strings.Contains(rec.Body.String(), "Next page") {
					t.Fatal("scoped software page failed", user, prefix, suffix, rec.Code, rec.Body.String())
				}
				for _, hidden := range []string{"private-inventory-", "Foreign software", "Confirm deletion", "Uninstall", "method=\"post\""} {
					if strings.Contains(rec.Body.String(), hidden) {
						t.Fatal("software read exposed data or mutations", hidden)
					}
				}
			}
		}
	}
	for _, target := range []string{"inventory-foreign", "inventory-sibling", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		if rec := request("scoped-viewer", "GET", base+"/computers/"+target+"/inventory/software?after=1", nil); rec.Code != 404 {
			t.Fatal("foreign software object visible", target, rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/inventory/software", tenant, sibling), nil); rec.Code != 404 {
		t.Fatal("foreign software URL scope accepted", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/software?q=application+26", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scoped application 26") || strings.Contains(rec.Body.String(), "Scoped application 00") {
		t.Fatal("software search did not filter", rec.Code, rec.Body.String())
	}
	for _, raw := range []string{"q=a&q=b", "after=-1", "after=01", "tenant=1", "q=" + strings.Repeat("x", 257)} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/software?"+raw, nil); rec.Code != 400 {
			t.Fatal("bad software query accepted", rec.Code)
		}
	}
	if _, err := h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT software_test_audit_failure CHECK(action<>'inventory.software.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT software_test_audit_failure`)
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/software", nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Scoped application") || strings.Contains(rec.Body.String(), "software_test_audit_failure") {
		t.Fatal("software audit failure leaked data", rec.Code, rec.Body.String())
	}
}
