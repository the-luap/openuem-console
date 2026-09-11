package desktop_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestPeripheralsViewsPreserveReportsAndReadOnlySearch(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, "uid", "peripherals-reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/desktop-report/inventory/peripherals", nil).WithContext(ctx), httptest.NewRecorder())
	for _, kind := range []inventory.PeripheralsKind{inventory.MonitorReports, inventory.PrinterReports} {
		for _, role := range []access.Role{access.Viewer, access.Operator} {
			info.Principal = access.Principal{UserID: "peripherals-reader", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}
			for _, state := range []string{"first", "next", "empty", "long"} {
				marker := `<img src="data:," onerror="window.__ownedPeripheralsMarkup=true">`
				page := &inventory.PeripheralsPage{DeviceID: "desktop-report", DeviceName: "Finance Windows", Organization: "Example organization", Site: "Berlin", Next: 25, Entries: []inventory.PeripheralsEntry{{ID: 1, Name: marker, Manufacturer: "Example & Partners Displays", Serial: marker, Week: "07", Year: "2024", Port: marker, Default: new(true), Network: new(false)}}}
				filter := inventory.PeripheralsFilter{Kind: kind, ReportFilter: inventory.ReportFilter{Search: "%_& Example"}}
				if state == "next" {
					filter.After = 25
					page.Next = 50
				}
				if state == "long" {
					page.Entries[0].Name += strings.Repeat("PeripheralsReport", 50)
					page.Entries[0].Serial += strings.Repeat("SerialReport", 50)
					page.Entries[0].Port += strings.Repeat("PortReport", 50)
				}
				page.Entries = append(page.Entries, inventory.PeripheralsEntry{ID: 2})
				if kind == inventory.PrinterReports {
					page.Entries = append(page.Entries, inventory.PeripheralsEntry{ID: 3, Name: "Reported flags", Default: new(false), Network: new(true), Shared: new(false)})
				}
				if state == "empty" {
					filter.After = 50
					page.Next = 0
					page.Entries = nil
				}
				var body bytes.Buffer
				if err = Peripherals(c, info, page, filter).Render(ctx, &body); err != nil {
					t.Fatal(err)
				}
				html := body.String()
				if strings.Contains(html, `<img src=`) || strings.Contains(html, `method="post"`) || strings.Contains(html, "Browse files") {
					t.Fatal("peripherals report injected markup or exposed mutation", kind, state, role)
				}
				if !strings.Contains(html, `method="get"`) || !strings.Contains(html, `id="peripherals-search"`) || !strings.Contains(html, `aria-current="page">Reported peripherals`) || !strings.Contains(html, "They do not verify that a display or printer") {
					t.Fatal("read-only form or report meaning missing", kind, state, role)
				}
				if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
					if err = os.MkdirAll(dir, 0755); err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(filepath.Join(dir, "desktop-peripherals-"+string(kind)+"-"+state+"-"+string(role)+".html"), body.Bytes(), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}
