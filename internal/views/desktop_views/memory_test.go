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
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestMemoryViewsPreserveLiteralReportsAndReadOnlySearch(t *testing.T) {
	if err := locales.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, err := locales.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, "uid", "memory-reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/desktop-report/inventory/memory", nil).WithContext(ctx), httptest.NewRecorder())
	for _, role := range []access.Role{access.Viewer, access.Operator} {
		info.Principal = access.Principal{UserID: "memory-reader", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}
		for _, state := range []string{"first", "next", "empty", "long"} {
			marker := `<img src="data:," onerror="window.__ownedMemoryMarkup=true">`
			page := &inventory.MemoryPage{DeviceID: "desktop-report", DeviceName: "Finance Windows", Organization: "Example organization", Site: "Berlin", Next: 25, Entries: []inventory.MemoryEntry{{ID: 1, Name: marker, Size: "16 GB", Type: "DDR5", Serial: marker, PartNumber: "Part & Module", Speed: "4800 MT/s", Manufacturer: "Example & Partners"}, {ID: 2}}}
			filter := inventory.MemoryFilter{Search: "%_& Example"}
			if state == "next" {
				filter.After = 25
				page.Next = 50
			}
			if state == "empty" {
				filter.After = 50
				page.Next = 0
				page.Entries = nil
			}
			if state == "long" {
				page.Entries[0].Name += strings.Repeat("MemoryReport", 50)
				page.Entries[0].Serial += strings.Repeat("SerialReport", 50)
				page.Entries[0].PartNumber = strings.Repeat("LongPart", 50)
			}
			var body bytes.Buffer
			if err = Memory(c, info, page, filter).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			html := body.String()
			if strings.Contains(html, `<img src=`) || strings.Contains(html, `method="post"`) || strings.Contains(html, "Uninstall") {
				t.Fatal("memory report injected markup or exposed a mutation", state, role)
			}
			if !strings.Contains(html, `method="get"`) || !strings.Contains(html, `id="memory-search"`) || !strings.Contains(html, `aria-current="page">Reported memory modules`) || !strings.Contains(html, "They do not verify current capacity") {
				t.Fatal("read-only form, navigation or report meaning missing", state, role)
			}
			if state != "empty" && (!strings.Contains(html, "Not reported") || !strings.Contains(html, "4800 MT/s")) {
				t.Fatal("literal report or missing flag label lost")
			}
			if state == "empty" && !strings.Contains(html, "does not prove that the device has no memory modules") {
				t.Fatal("empty report was misrepresented")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				if err = os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "desktop-memory-"+state+"-"+string(role)+".html"), body.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
