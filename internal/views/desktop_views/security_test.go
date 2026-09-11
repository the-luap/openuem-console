package desktop_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestSecurityViewsPreserveLiteralReportsAndReadOnlySearch(t *testing.T) {
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
	sm.Put(ctx, "uid", "security-reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/desktop-report/inventory/security", nil).WithContext(ctx), httptest.NewRecorder())
	for _, role := range []access.Role{access.Viewer, access.Operator} {
		info.Principal = access.Principal{UserID: "security-reader", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}
		for _, state := range []string{"first", "next", "empty", "long", "missing", "negative"} {
			marker := `<img src="data:," onerror="window.__ownedSecurityMarkup=true">`
			yes, no := true, false
			instant := time.Date(2026, 9, 1, 12, 34, 56, 123456000, time.FixedZone("report", 3600))
			zero := time.Time{}
			page := &inventory.SecurityPage{DeviceID: "desktop-report", DeviceName: "Finance Windows", Organization: "Example organization", Site: "Berlin", Next: 25,
				AntivirusName: "Example & product", AntivirusActive: &yes, AntivirusUpdated: &no,
				UpdateStatus: "Unknown & reported", PendingUpdates: &yes, LastInstall: &instant, LastSearch: &zero,
				Entries: []inventory.SecurityUpdateEntry{{ID: 1, Title: marker, Date: &instant, SupportURL: "https://support.invalid/update?a=1&b=2"}, {ID: 2}, {ID: 3, Title: "Reported support text", SupportURL: "javascript:window.__ownedSecurityPath=true"}}}

			filter := inventory.SecurityFilter{Search: "%_& Example"}
			if state == "next" {
				filter.After = 25
				page.Next = 50
			}
			if state == "empty" || state == "missing" {
				filter.After = 50
				page.Next = 0
				page.Entries = nil
			}
			if state == "long" {
				page.Entries[0].Title += strings.Repeat("SecurityReport", 50)
				page.AntivirusName += strings.Repeat("ProductReport", 50)
				page.Entries[0].SupportURL += strings.Repeat("LongPath", 50)
			}
			if state == "missing" {
				page.AntivirusName, page.UpdateStatus = "", ""
				page.AntivirusActive, page.AntivirusUpdated, page.PendingUpdates = nil, nil, nil
				page.LastInstall, page.LastSearch = nil, nil
			}
			if state == "negative" {
				page.AntivirusActive, page.AntivirusUpdated, page.PendingUpdates = &no, &yes, &no
				page.LastInstall, page.LastSearch = &zero, &instant
				page.Entries[0].Date = &zero
			}

			var body bytes.Buffer
			if err = Security(c, info, page, filter).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			html := body.String()
			if strings.Contains(html, `<img src=`) || strings.Contains(html, `method="post"`) || strings.Contains(html, "Uninstall") {
				t.Fatal("security report injected markup or exposed a mutation", state, role)
			}
			if !strings.Contains(html, `method="get"`) || !strings.Contains(html, `id="security-search"`) || !strings.Contains(html, `aria-current="page">Reported security`) || !strings.Contains(html, "They do not verify current protection") {
				t.Fatal("read-only form, navigation or report meaning missing", state, role)
			}
			if state != "empty" && state != "missing" && (!strings.Contains(html, "Not reported") || !strings.Contains(html, "javascript:window.__ownedSecurityPath=true")) {
				t.Fatal("literal report or missing flag label lost")
			}
			if state == "empty" && !strings.Contains(html, "does not prove that the device has no installed updates") {
				t.Fatal("empty report was misrepresented")
			}
			if strings.Contains(html, "0001-01-01") {
				t.Fatal("collector zero time was shown as an observed date", state)
			}
			if state != "missing" && !strings.Contains(html, `datetime="2026-09-01T11:34:56.123456Z"`) {
				t.Fatal("reported instant lost timezone or precision", state)
			}

			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				if err = os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "desktop-security-"+state+"-"+string(role)+".html"), body.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
