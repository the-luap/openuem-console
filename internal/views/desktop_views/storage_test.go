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

func TestStorageViewsPreserveReportsAndReadOnlySearch(t *testing.T) {
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
	sm.Put(ctx, "uid", "storage-reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/desktop-report/inventory/storage", nil).WithContext(ctx), httptest.NewRecorder())
	for _, kind := range []inventory.StorageKind{inventory.PhysicalStorage, inventory.LogicalStorage} {
		for _, role := range []access.Role{access.Viewer, access.Operator} {
			info.Principal = access.Principal{UserID: "storage-reader", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}
			for _, state := range []string{"first", "next", "empty", "long"} {
				marker := `<img src="data:," onerror="window.__ownedStorageMarkup=true">`
				page := &inventory.StoragePage{DeviceID: "desktop-report", DeviceName: "Finance Windows", Organization: "Example organization", Site: "Berlin", Next: 25, Entries: []inventory.StorageEntry{{ID: 1, Name: marker, Model: "Example & Partners SSD", Serial: marker, Size: "1 TB", Filesystem: "NTFS", Usage: new(int64(37)), Remaining: "630 GB", Volume: "Data & Archives", BitLocker: marker}}}
				filter := inventory.StorageFilter{Kind: kind, ReportFilter: inventory.ReportFilter{Search: "%_& Example"}}
				if state == "next" {
					filter.After = 25
					page.Next = 50
				}
				if state == "long" {
					page.Entries[0].Name += strings.Repeat("StorageReport", 50)
					page.Entries[0].Serial += strings.Repeat("SerialReport", 50)
					page.Entries[0].BitLocker += strings.Repeat("EncryptionReport", 50)
				}
				if kind == inventory.LogicalStorage {
					page.Entries = append(page.Entries, inventory.StorageEntry{ID: 2, Name: "Missing report"}, inventory.StorageEntry{ID: 3, Name: "Stored zero", Usage: new(int64(0))}, inventory.StorageEntry{ID: 4, Name: "Invalid negative", Usage: new(int64(-1))}, inventory.StorageEntry{ID: 5, Name: "Invalid high", Usage: new(int64(127))})
				}
				if state == "empty" {
					filter.After = 50
					page.Next = 0
					page.Entries = nil
				}
				var body bytes.Buffer
				if err = Storage(c, info, page, filter).Render(ctx, &body); err != nil {
					t.Fatal(err)
				}
				html := body.String()
				if strings.Contains(html, `<img src=`) || strings.Contains(html, `method="post"`) || strings.Contains(html, "Browse files") {
					t.Fatal("storage report injected markup or exposed mutation", kind, state, role)
				}
				if !strings.Contains(html, `method="get"`) || !strings.Contains(html, `id="storage-search"`) || !strings.Contains(html, `aria-current="page">Reported storage`) || !strings.Contains(html, "They do not verify current capacity") {
					t.Fatal("read-only form or report meaning missing", kind, state, role)
				}
				if kind == inventory.LogicalStorage && !strings.Contains(html, "Encryption is not verified or enforced here") {
					t.Fatal("encryption report misrepresented")
				}
				if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
					if err = os.MkdirAll(dir, 0755); err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(filepath.Join(dir, "desktop-storage-"+string(kind)+"-"+state+"-"+string(role)+".html"), body.Bytes(), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}
