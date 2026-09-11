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
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestDesktopInventoryEscapesReportsAndOmitsMutationForms(t *testing.T) {
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
	sm.Put(ctx, "uid", "inventory-reader")
	sm.Put(ctx, "username", "Inventory reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/desktop-report", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	device := inventory.Desktop{ID: "desktop-report", Name: strings.Repeat("Long-device-name-", 12), Hostname: `<img src=x onerror=alert(1)>`, Platform: "windows", Status: "Enabled", EndpointType: "Laptop", Organization: "Example organization", Site: "Berlin", LastContact: &now, Hardware: &inventory.Hardware{Model: "Example laptop", Serial: strings.Repeat("ABCD", 40), Memory: new(uint64(16 << 30)), Cores: new(int64(8))}, OperatingSystem: &inventory.OperatingSystem{Version: "Windows 11", Edition: "Enterprise", Architecture: "amd64"}}
	for _, role := range []access.Role{access.Viewer, access.Operator, access.TenantAdmin} {
		info.Principal = access.Principal{UserID: "inventory-reader", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1}}}}
		for _, state := range []string{"complete", "partial", "missing-numbers", "zero-numbers"} {
			partial := state == "partial"
			d := device
			name := "desktop-inventory"
			if partial {
				d.Hardware, d.OperatingSystem, d.LastContact = nil, nil, nil
				name += "-partial"
			}
			if state == "missing-numbers" {
				d.Hardware = &inventory.Hardware{Model: "Incomplete report"}
				name += "-missing-numbers"
			}
			if state == "zero-numbers" {
				d.Hardware = &inventory.Hardware{Model: "Reported zero", Memory: new(uint64(0)), Cores: new(int64(0))}
				name += "-zero-numbers"
			}
			var body bytes.Buffer
			if err = Inventory(c, info, &d).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			html := body.String()
			if strings.Contains(html, d.Hostname) || !strings.Contains(html, "&lt;img src=x onerror=alert(1)&gt;") {
				t.Fatal("device-controlled inventory was not escaped")
			}
			_, main, _ := strings.Cut(html, "<main")
			main, _, _ = strings.Cut(main, "</main>")
			if main == "" || strings.Contains(main, "<form") || strings.Contains(main, "hx-post") || strings.Contains(main, "hx-delete") || strings.Contains(main, "remote-assistance") {
				t.Fatal("inventory contains a legacy mutation or remote action")
			}
			if partial && (!strings.Contains(main, "No hardware report received yet.") || !strings.Contains(main, "No operating system report received yet.")) {
				t.Fatal("missing reports are not explained")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" && role == access.Viewer {
				if err = os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name+".html"), body.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
