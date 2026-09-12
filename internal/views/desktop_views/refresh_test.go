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

func TestInventoryRefreshFormsAndDeliveryStates(t *testing.T) {
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
	sm.Put(ctx, "uid", "refresh-reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CSRFToken: "refresh-test-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/desktop-report/inventory", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	device := &inventory.Desktop{ID: "desktop-report", Name: "Finance Windows", Hostname: "finance-pc", Platform: "windows", Status: "Enabled", Organization: "Example organization", Site: "Berlin", LastContact: &now}
	for _, role := range []access.Role{access.Viewer, access.Operator} {
		info.Principal = access.Principal{UserID: "refresh-reader", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}
		for _, state := range []string{"new", "queued", "pending", "accepted", "stopped", "unconfirmed"} {
			data := RefreshData{Available: true, NewID: "10000000-0000-4000-8000-000000000001"}
			if state != "new" {
				data.Request = &inventory.RefreshRequest{ID: "20000000-0000-4000-8000-000000000001", DeviceID: device.ID, Status: state, RequestedAt: now}
			}
			if state == "pending" {
				data.Request.Status = "queued"
				data.Request.Attempts = 1
			}
			if state == "accepted" {
				data.Request.FinishedAt = &now
			}
			var body bytes.Buffer
			if err = InventoryWithRefresh(c, info, device, data).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			html := body.String()
			wantForm := role == access.Operator && state != "queued" && state != "pending"
			if strings.Contains(html, "Request fresh inventory") != wantForm {
				t.Fatal("refresh mutation does not follow authority or pending state", role, state)
			}
			if wantForm && (!strings.Contains(html, `action="/tenant/1/site/1/computers/desktop-report/refresh"`) || !strings.Contains(html, `name="request_id" value="`+data.NewID+`"`) || !strings.Contains(html, `name="csrf" value="refresh-test-csrf"`)) {
				t.Fatal("request binding or CSRF missing", role, state)
			}
			if data.Request != nil && !strings.Contains(html, refreshState(data.Request)) {
				t.Fatal("request state omitted", state)
			}
			if !strings.Contains(html, "The device must still collect") || strings.Contains(html, "Report completed") {
				t.Fatal("delivery was presented as report completion")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				if err = os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "desktop-refresh-"+state+"-"+string(role)+".html"), body.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
