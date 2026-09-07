package mdm_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestManagementPagesRenderSafeFormsAndInventory(t *testing.T) {
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
	sm.Put(ctx, "uid", "preview-admin")
	sm.Put(ctx, "username", "Preview administrator")
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "preview-admin", Grants: []access.Grant{{Role: access.Administrator}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "-1", ProfileSiteID: "1", CSRFToken: "test-csrf-token", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	req := httptest.NewRequest("GET", "/tenant/1/devices", nil).WithContext(ctx)
	c := echo.New().NewContext(req, httptest.NewRecorder())
	now := time.Now().UTC()
	d := &apple.Device{ID: "10000000-0000-0000-0000-000000000001", Name: "Sales iPhone", Model: "iPhone16,1", OSVersion: "18.6.2", BuildVersion: "22G100", SerialNumber: "EXAMPLE123", Supervised: true, Status: "enrolled", InventoryAt: &now, LastSeen: &now, AppsAt: &now, ProfilesAt: &now, CertificateExpiresAt: now.AddDate(1, 0, 0), PushStatus: "accepted", Apps: []apple.Application{{Identifier: "com.example.app", Name: "Example app", Version: "42", ShortVersion: "1.2"}}}
	p := apple.Profile{ID: "20000000-0000-0000-0000-000000000001", Name: "Company Wi-Fi", Identifier: "eu.example.wifi", Revision: 2, PayloadTypes: []string{"com.apple.wifi.managed"}}
	policy := &apple.UpdatePolicy{TargetVersion: "18.7.1", Deadline: "2026-10-01T18:00:00", Status: "waiting"}
	detail := Detail{Device: d, Profiles: []apple.Profile{p}, Assignments: []apple.Assignment{{ProfileID: p.ID, Name: p.Name, Revision: 2, Desired: "installed", Status: "verified"}}, Policy: policy, Compliance: "update_required", CatalogAt: &now, Releases: []apple.OSRelease{{Version: "18.7.1", Build: "22H100"}, {Version: "18.7.1", Build: "22H6100"}}}
	cases := []struct {
		name      string
		component templ.Component
		required  []string
	}{
		{"devices", Devices(c, info, []DeviceRow{{ID: "windows-1", Name: "Finance Windows", Platform: "windows", OSVersion: "Windows 11", Status: "agent", LastSeen: &now, URL: "/tenant/1/computers/windows-1"}, {ID: d.ID, Name: d.Name, Platform: "iOS", OSVersion: d.OSVersion, Serial: d.SerialNumber, Status: d.Status, LastSeen: d.LastSeen, URL: "/tenant/1/ios/" + d.ID}}, "", "", ""), []string{"Finance Windows", "Sales iPhone", "Windows software deployment", "iOS profiles"}},
		{"device", DeviceDetails(c, info, detail), []string{"Installed apps", "Example app", "18.6.2", "22G100", "Enforce update policy", "test-csrf-token", `value="18.7.1/22H100"`, `value="18.7.1/22H6100"`}},
		{"profiles", Profiles(c, info, []apple.Profile{p}, []apple.Device{*d}), []string{"Create a Wi-Fi profile", "Save and deploy revision", "Company Wi-Fi", "test-csrf-token"}},
		{"setup", Setup(c, info, &apple.Settings{Organization: "Example organization", PublicURL: "https://mdm.example.test", Topic: "com.apple.mgmt.example", PushExpiresAt: now.AddDate(1, 0, 0)}, "", "", true), []string{"Create enrollment invitation", "push_certificate", "push_key", "test-csrf-token"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := tc.component.Render(ctx, &b); err != nil {
				t.Fatal(err)
			}
			html := b.String()
			for _, required := range tc.required {
				if !strings.Contains(html, required) {
					t.Errorf("missing %q", required)
				}
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, tc.name+".html"), b.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	malicious := *d
	malicious.Name = `<script>alert("xss")</script>`
	detail.Device = &malicious
	var b bytes.Buffer
	if err = DeviceDetails(c, info, detail).Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), malicious.Name) {
		t.Fatal("device-supplied name was emitted as executable HTML")
	}
}
