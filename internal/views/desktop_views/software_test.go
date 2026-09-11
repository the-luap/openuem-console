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

func TestSoftwareViewsPreserveLiteralReportsAndReadOnlySearch(t *testing.T) {
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
	sm.Put(ctx, "uid", "software-reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/desktop-report/inventory/software", nil).WithContext(ctx), httptest.NewRecorder())
	for _, role := range []access.Role{access.Viewer, access.Operator} {
		info.Principal = access.Principal{UserID: "software-reader", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}
		for _, state := range []string{"first", "next", "empty", "long"} {
			page := &inventory.SoftwarePage{DeviceID: "desktop-report", DeviceName: "Finance Windows", Organization: "Example organization", Site: "Berlin", Next: 25, Entries: []inventory.SoftwareEntry{{ID: 1, Name: `<img src=x onerror=alert(1)>`, Version: "1.2", Publisher: "Example & Partners", InstallDate: "20260911"}}}
			filter := inventory.SoftwareFilter{Search: "%_& Example"}
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
				page.Entries[0].Name += strings.Repeat("SoftwareReport", 50)
				page.Entries[0].Version = strings.Repeat("LongVersion", 20)
			}
			var body bytes.Buffer
			if err = Software(c, info, page, filter).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			html := body.String()
			if strings.Contains(html, `<img src=x`) || strings.Contains(html, `method="post"`) || strings.Contains(html, "Uninstall") {
				t.Fatal("software report injected markup or exposed a mutation", state, role)
			}
			if !strings.Contains(html, `method="get"`) || !strings.Contains(html, `id="software-search"`) || !strings.Contains(html, `aria-current="page">Reported software`) || !strings.Contains(html, "They do not verify a software deployment") {
				t.Fatal("read-only form, navigation or report meaning missing", state, role)
			}
			if state == "empty" && !strings.Contains(html, "does not prove that no software is installed") {
				t.Fatal("empty report was misrepresented")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				if err = os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "desktop-software-"+state+"-"+string(role)+".html"), body.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
