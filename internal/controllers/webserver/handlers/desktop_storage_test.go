package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
	"golang.org/x/net/html"
)

func TestDesktopStorageFilterRejectsAmbiguousQueries(t *testing.T) {
	for _, raw := range []string{"kind=", "kind=PHYSICAL", "kind=physical&kind=physical", "kind=logical&kind=physical", "q=a&q=b", "after=0", "after=01", "after=+1", "after=", "after=-1", "after=9223372036854775808", "site=1", "q=%ff", "q=%00", "q=%", "q=" + strings.Repeat("x", 257), "kind=" + strings.Repeat("%70", 1400), "q=x;y"} {
		if _, err := desktopStorageFilter(raw, ""); err == nil {
			t.Fatal("invalid storage query accepted", raw)
		}
	}
	for _, raw := range []string{"", "kind=physical", "kind=logical", "kind=logical&q=%25_&after=9223372036854775807"} {
		if _, err := desktopStorageFilter(raw, ""); err != nil {
			t.Fatal("valid storage query rejected", raw, err)
		}
	}
	for _, kind := range []inventory.StorageKind{inventory.PhysicalStorage, inventory.LogicalStorage} {
		for _, raw := range []string{"", "kind=" + string(kind)} {
			if got, err := desktopStorageFilter(raw, kind); err != nil || got.Kind != kind {
				t.Fatal("legacy alias lost kind", got, err)
			}
		}
	}
	if _, err := desktopStorageFilter("kind=physical", inventory.LogicalStorage); err == nil {
		t.Fatal("conflicting legacy report kind accepted")
	}
	if _, err := desktopStorageFilter("kind=logical", inventory.PhysicalStorage); err == nil {
		t.Fatal("conflicting legacy report kind accepted")
	}
}

func exerciseDesktopStorageRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	for i := 0; i < 27; i++ {
		if err := h.Model.Client.PhysicalDisk.Create().SetDeviceID(fmt.Sprintf("Scoped physical %02d", i)).SetModel("Physical model").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := h.Model.Client.LogicalDisk.Create().SetLabel(fmt.Sprintf("Scoped logical %02d", i)).SetFilesystem("NTFS").SetOwnerID("windows-fixture").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Model.Client.PhysicalDisk.Create().SetDeviceID("Foreign storage must stay hidden").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Model.Client.LogicalDisk.Create().SetLabel("Foreign storage must stay hidden").SetOwnerID("inventory-foreign").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, kind := range []string{"physical", "logical"} {
		for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
			for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
				routes := []string{"/inventory/storage?kind=" + kind}
				if user != "apple-console-admin" {
					routes = append(routes, "/"+kind+"-disks")
				}
				for _, suffix := range routes {
					rec := request(user, "GET", prefix+"/computers/windows-fixture"+suffix, nil)
					body := rec.Body.String()
					if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(body, "Storage inventory") || !strings.Contains(body, "Scoped "+kind+" 00") || strings.Contains(body, "Scoped "+kind+" 26") || !strings.Contains(body, "Next page") {
						t.Fatal("scoped storage page failed", user, prefix, suffix, rec.Code, body)
					}
					for _, hidden := range []string{"private-inventory-", "Foreign storage", "Confirm deletion", "Browse files", "method=\"post\""} {
						if strings.Contains(body, hidden) {
							t.Fatal("storage read exposed data or mutations", hidden)
						}
					}
					// Follow the actual server-generated continuation, preserving kind
					// and scope rather than assuming either table's sequence values.
					nextURL := storageNextURL(t, body)
					next := request(user, "GET", nextURL, nil)
					if next.Code != 200 || !strings.Contains(next.Body.String(), "Scoped "+kind+" 26") || strings.Contains(next.Body.String(), "Scoped "+kind+" 00") {
						t.Fatal("storage continuation failed", nextURL, next.Code)
					}
				}
			}
		}
		for _, target := range []string{"inventory-foreign", "inventory-sibling", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
			if rec := request("scoped-viewer", "GET", base+"/computers/"+target+"/inventory/storage?kind="+kind+"&after=1", nil); rec.Code != 404 {
				t.Fatal("foreign storage object visible", target, rec.Code)
			}
		}
		if rec := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/inventory/storage?kind=%s", tenant, sibling, kind), nil); rec.Code != 404 {
			t.Fatal("foreign storage URL scope accepted", rec.Code)
		}
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/storage?kind="+kind+"&q=26", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scoped "+kind+" 26") || strings.Contains(rec.Body.String(), "Scoped "+kind+" 00") {
			t.Fatal("storage search did not filter", rec.Code)
		}
	}
	for _, raw := range []string{"kind=", "kind=logical&kind=physical", "kind=bogus", "q=a&q=b", "after=-1", "after=01", "tenant=1", "q=" + strings.Repeat("x", 257)} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/storage?"+raw, nil); rec.Code != 400 {
			t.Fatal("bad storage query accepted", raw, rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/logical-disks?kind=physical", nil); rec.Code != 400 {
		t.Fatal("conflicting legacy storage query accepted", rec.Code)
	}
	if _, err := h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT storage_test_audit_failure CHECK(action<>'inventory.storage.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT storage_test_audit_failure`)
	for _, kind := range []string{"physical", "logical"} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture/inventory/storage?kind="+kind, nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Scoped "+kind) || strings.Contains(rec.Body.String(), "storage_test_audit_failure") {
			t.Fatal("storage audit failure leaked data", rec.Code, rec.Body.String())
		}
	}
}

func storageNextURL(t *testing.T, body string) string {
	t.Helper()
	tokens := html.NewTokenizer(strings.NewReader(body))
	for tokens.Next() != html.ErrorToken {
		token := tokens.Token()
		if token.Type != html.StartTagToken || token.Data != "a" {
			continue
		}
		var href, rel string
		for _, attribute := range token.Attr {
			if attribute.Key == "href" {
				href = attribute.Val
			}
			if attribute.Key == "rel" {
				rel = attribute.Val
			}
		}
		if rel == "next" && href != "" {
			return href
		}
	}
	t.Fatal("storage continuation missing")
	return ""
}
