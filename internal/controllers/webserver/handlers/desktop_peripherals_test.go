package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
)

func TestDesktopPeripheralsFilterRejectsAmbiguousQueries(t *testing.T) {
	for _, raw := range []string{"kind=", "kind=MONITORS", "kind=monitors&kind=monitors", "kind=printers&kind=monitors", "q=a&q=b", "after=0", "after=01", "after=+1", "after=", "after=-1", "after=9223372036854775808", "site=1", "q=%ff", "q=%00", "q=%", "q=" + strings.Repeat("x", 257), "kind=" + strings.Repeat("%70", 1400), "q=x;y"} {
		if _, err := desktopPeripheralsFilter(raw, ""); err == nil {
			t.Fatal("invalid peripherals query accepted", raw)
		}
	}
	for _, raw := range []string{"", "kind=monitors", "kind=printers", "kind=printers&q=%25_&after=9223372036854775807"} {
		if _, err := desktopPeripheralsFilter(raw, ""); err != nil {
			t.Fatal("valid peripherals query rejected", raw, err)
		}
	}
	for _, kind := range []inventory.PeripheralsKind{inventory.MonitorReports, inventory.PrinterReports} {
		for _, raw := range []string{"", "kind=" + string(kind)} {
			if got, err := desktopPeripheralsFilter(raw, kind); err != nil || got.Kind != kind {
				t.Fatal("legacy alias lost kind", got, err)
			}
		}
	}
	if _, err := desktopPeripheralsFilter("kind=monitors", inventory.PrinterReports); err == nil {
		t.Fatal("conflicting legacy report kind accepted")
	}
	if _, err := desktopPeripheralsFilter("kind=printers", inventory.MonitorReports); err == nil {
		t.Fatal("conflicting legacy report kind accepted")
	}
}

func exerciseDesktopPeripheralsRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	for i := 0; i < 27; i++ {
		if err := h.Model.Client.Monitor.Create().SetModel(fmt.Sprintf("Scoped monitors %02d", i)).SetManufacturer("Example Displays").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Model.Client.Printer.Create().SetName(fmt.Sprintf("Scoped printers %02d", i)).SetPort("IP_192.0.2.15").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Model.Client.Monitor.Create().SetModel("Foreign peripherals must stay hidden").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Model.Client.Printer.Create().SetName("Foreign peripherals must stay hidden").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, kind := range []string{"monitors", "printers"} {
		for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
			for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
				routes := []string{"/inventory/peripherals?kind=" + kind}
				if user != "apple-console-admin" {
					routes = append(routes, "/"+kind)
				}
				for _, suffix := range routes {
					rec := request(user, "GET", prefix+"/computers/windows-fixture"+suffix, nil)
					body := rec.Body.String()
					if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(body, "Peripheral inventory") || !strings.Contains(body, "Scoped "+kind+" 00") || strings.Contains(body, "Scoped "+kind+" 26") || !strings.Contains(body, "Next page") {
						t.Fatal("scoped peripherals page failed", user, prefix, suffix, rec.Code, body)
					}
					for _, hidden := range []string{"private-inventory-", "Foreign peripherals", "Confirm deletion", "Browse files", "method=\"post\""} {
						if strings.Contains(body, hidden) {
							t.Fatal("peripherals read exposed data or mutations", hidden)
						}
					}
					// Follow the actual server-generated continuation, preserving kind
					// and scope rather than assuming either table's sequence values.
					nextURL := inventoryNextURL(t, body)
					next := request(user, "GET", nextURL, nil)
					if next.Code != 200 || !strings.Contains(next.Body.String(), "Scoped "+kind+" 26") || strings.Contains(next.Body.String(), "Scoped "+kind+" 00") {
						t.Fatal("peripherals continuation failed", nextURL, next.Code)
					}
				}
			}
		}
		for _, target := range []string{"inventory-foreign", "inventory-sibling", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
			if rec := request("scoped-viewer", "GET", base+"/computers/"+target+"/inventory/peripherals?kind="+kind+"&after=1", nil); rec.Code != 404 {
				t.Fatal("foreign peripherals object visible", target, rec.Code)
			}
		}
		if rec := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/inventory/peripherals?kind=%s", tenant, sibling, kind), nil); rec.Code != 404 {
			t.Fatal("foreign peripherals URL scope accepted", rec.Code)
		}
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/peripherals?kind="+kind+"&q=26", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scoped "+kind+" 26") || strings.Contains(rec.Body.String(), "Scoped "+kind+" 00") {
			t.Fatal("peripherals search did not filter", rec.Code)
		}
	}
	for _, raw := range []string{"kind=", "kind=printers&kind=monitors", "kind=bogus", "q=a&q=b", "after=-1", "after=01", "tenant=1", "q=" + strings.Repeat("x", 257)} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/peripherals?"+raw, nil); rec.Code != 400 {
			t.Fatal("bad peripherals query accepted", raw, rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/printers?kind=monitors", nil); rec.Code != 400 {
		t.Fatal("conflicting legacy peripherals query accepted", rec.Code)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT peripherals_test_audit_failure CHECK(action<>'inventory.peripherals.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT peripherals_test_audit_failure`)
	for _, kind := range []string{"monitors", "printers"} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/peripherals?kind="+kind, nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Scoped "+kind) || strings.Contains(rec.Body.String(), "peripherals_test_audit_failure") {
			t.Fatal("peripherals audit failure leaked data", rec.Code, rec.Body.String())
		}
	}
}
