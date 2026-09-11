package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// This runs on the complete real console router and the real Ent/Apple schemas,
// rather than a route mock or a test-only authorization schema.
func exerciseConsolePermissions(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenantID, siteID int, profileID string) {
	t.Helper()
	adminID := "apple-console-admin"
	sm := h.SessionManager.Manager
	defer sm.Put(ctx, "uid", adminID)
	otherTenant, err := h.Model.Client.Tenant.Create().SetDescription("Private organization").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Model.CloneGlobalSettings(otherTenant.ID); err != nil {
		t.Fatal(err)
	}
	otherSite, err := h.Model.Client.Site.Create().SetDescription("Private site").SetTenantID(otherTenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := h.Model.Client.Site.Create().SetDescription("Restricted sibling site").SetTenantID(tenantID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "unassigned-user", "openuem"} {
		if _, err = h.Model.Client.User.Create().SetID(id).SetName(id).SetEmail(id + "@example.test").SetUse2fa(false).Save(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []struct {
		user  string
		grant access.Grant
	}{{"scoped-viewer", access.Grant{Role: access.Viewer, Scope: access.Scope{TenantID: tenantID, SiteID: siteID}}}, {"scoped-operator", access.Grant{Role: access.Operator, Scope: access.Scope{TenantID: tenantID, SiteID: siteID}}}, {"organization-admin", access.Grant{Role: access.TenantAdmin, Scope: access.Scope{TenantID: tenantID}}}} {
		if err = h.Access.ReplaceGrants(ctx, adminID, entry.user, 0, []access.Grant{entry.grant}); err != nil {
			t.Fatal(err)
		}
	}
	settings, err := h.Apple.Settings(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	otherSettings := *settings
	otherSettings.TenantID = otherTenant.ID
	otherSettings.Organization = "Private organization"
	seedExistingAppleSettings(t, h.Model.DB, otherSettings)
	devices := []*apple.Invitation{}
	for _, entry := range []struct {
		tenant, site int
		name         string
	}{{tenantID, siteID, "Visible phone"}, {tenantID, sibling.ID, "Restricted sibling phone"}, {otherTenant.ID, otherSite.ID, "Private organization phone"}} {
		invite, err := h.Apple.Invite(ctx, apple.Scope{TenantID: entry.tenant, SiteID: entry.site}, entry.name, adminID)
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, invite)
		if _, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='iPhone16,1',os_version='18.6' WHERE id=$1`, invite.DeviceID); err != nil {
			t.Fatal(err)
		}
	}
	request := func(user, method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		sm.Put(ctx, "uid", user)
		if form == nil {
			form = url.Values{}
		}
		if method != http.MethodGet && form.Get("csrf") == "" {
			form.Set("csrf", "console-test-token")
		}
		req := httptest.NewRequest(method, path, bytes.NewBufferString(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenantID, siteID)
	t.Run("scoped desktop inventory", func(t *testing.T) {
		exerciseDesktopInventoryPermissions(t, h, ctx, tenantID, siteID, sibling.ID, otherTenant.ID, otherSite.ID, request)
	})
	t.Run("scoped desktop refresh", func(t *testing.T) {
		exerciseDesktopRefreshRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("scoped desktop software", func(t *testing.T) {
		exerciseDesktopSoftwareRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("scoped desktop network", func(t *testing.T) {
		exerciseDesktopNetworkRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("account language with real session and CSRF middleware", func(t *testing.T) { exerciseAccountLanguageRoutes(t, h) })
	t.Run("scoped desktop storage", func(t *testing.T) {
		exerciseDesktopStorageRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("scoped desktop peripherals", func(t *testing.T) {
		exerciseDesktopPeripheralsRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("scoped desktop memory", func(t *testing.T) {
		exerciseDesktopMemoryRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("scoped desktop shares", func(t *testing.T) {
		exerciseDesktopSharesRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("scoped desktop security", func(t *testing.T) {
		exerciseDesktopSecurityRoutes(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	t.Run("Mac invitation rights require explicit security permission", func(t *testing.T) {
		exerciseAppleEnrollmentOptions(t, h, ctx, tenantID, siteID, sibling.ID, request)
	})
	exercisePushRequestRoutes(t, h, e, ctx, tenantID, siteID, otherTenant.ID, otherSite.ID)
	exerciseADERoutes(t, h, e, ctx, tenantID, siteID, otherTenant.ID, otherSite.ID)
	t.Run("readers see only permitted scope and no mutation controls", func(t *testing.T) {
		for _, path := range []string{"/devices", fmt.Sprintf("/tenant/%d/devices", tenantID), base + "/devices"} {
			rec := request("scoped-viewer", "GET", path, nil)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Visible phone") {
				t.Fatal("scoped inventory failed", rec.Code, rec.Body.String())
			}
			for _, secret := range []string{"Restricted sibling phone", "Private organization phone", "Private organization", "Restricted sibling site", "Windows software deployment", "href=\"/admin\""} {
				if strings.Contains(rec.Body.String(), secret) {
					t.Error("out-of-scope inventory/navigation visible", secret)
				}
			}
		}
		rec := request("scoped-viewer", "GET", base+"/ios/setup", nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "push_key") || strings.Contains(rec.Body.String(), "Create enrollment invitation") {
			t.Fatal("reader sees mutation forms", rec.Code, rec.Body.String())
		}
		rec = request("scoped-viewer", "GET", base+"/ios/configurations", nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "Download current profile") || strings.Contains(rec.Body.String(), "Create or upload a profile") || strings.Contains(rec.Body.String(), "Apply profile") {
			t.Fatal("reader sees privileged profile controls", rec.Code)
		}
		rec = request("scoped-viewer", "GET", base+"/ios/"+devices[0].DeviceID, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "Refresh device, apps") || strings.Contains(rec.Body.String(), "Enforce update policy") {
			t.Fatal("reader sees device mutation controls", rec.Code)
		}
	})
	t.Run("every native mutation denies a viewer including aliases", func(t *testing.T) {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenantID), base} {
			for _, suffix := range []string{"/ios/setup", "/ios/setup/requests", "/ios/setup/requests/10000000-0000-0000-0000-000000000001/revoke", "/ios/setup/requests/10000000-0000-0000-0000-000000000001/certificate", "/ios/setup/requests/10000000-0000-0000-0000-000000000001/vendor", "/ios/enroll", "/ios/configurations", "/ios/configurations/" + profileID + "/assign", "/ios/configurations/" + profileID + "/delete", "/ios/" + devices[0].DeviceID + "/refresh", "/ios/" + devices[0].DeviceID + "/revoke", "/ios/" + devices[0].DeviceID + "/update", "/ios/" + devices[0].DeviceID + "/commands/10000000-0000-0000-0000-000000000001/retry"} {
				rec := request("scoped-viewer", "POST", prefix+suffix, nil)
				if rec.Code != 403 {
					t.Errorf("reader reached %s: %d %s", prefix+suffix, rec.Code, rec.Body.String())
				}
			}
			rec := request("scoped-viewer", "GET", prefix+"/ios/configurations/"+profileID+"/download", nil)
			if rec.Code != 403 {
				t.Fatal("reader downloaded profile secrets", rec.Code)
			}
		}
	})
	t.Run("server administration is denied for every registered admin route", func(t *testing.T) {
		count := 0
		for _, route := range e.Routes() {
			if !strings.HasPrefix(route.Path, "/admin") {
				continue
			}
			count++
			parts := strings.Split(route.Path, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, ":") {
					parts[i] = "1"
				}
			}
			rec := request("scoped-viewer", route.Method, strings.Join(parts, "/"), nil)
			if rec.Code != 403 {
				t.Errorf("admin route escaped role enforcement: %s %s: %d", route.Method, route.Path, rec.Code)
			}
		}
		if count < 25 {
			t.Fatal("did not exercise the real administrator route surface", count)
		}
	})
	t.Run("foreign URLs and object IDs cannot widen scope", func(t *testing.T) {
		for _, path := range []string{fmt.Sprintf("/tenant/%d/devices", otherTenant.ID), fmt.Sprintf("/tenant/%d/site/%d/devices", tenantID, sibling.ID), base + "/ios/" + devices[1].DeviceID, base + "/ios/" + devices[2].DeviceID} {
			rec := request("scoped-viewer", "GET", path, nil)
			if rec.Code != 404 {
				t.Errorf("foreign resource accepted %s: %d", path, rec.Code)
			}
		}
		rec := request("scoped-operator", "POST", base+"/ios/enroll", url.Values{"site_id": {strconv.Itoa(sibling.ID)}, "name": {"Cross-site attempt"}})
		if rec.Code != 403 {
			t.Fatal("body site overrode URL scope", rec.Code)
		}
		rec = request("scoped-operator", "POST", fmt.Sprintf("/tenant/%d/ios/enroll", tenantID), url.Values{"site_id": {strconv.Itoa(sibling.ID)}, "name": {"Cross-site attempt"}})
		if rec.Code != 403 {
			t.Fatal("organization alias escaped site grant", rec.Code)
		}
		rec = request("scoped-operator", "POST", base+"/ios/configurations/"+profileID+"/assign", url.Values{"device_id": {devices[0].DeviceID, devices[1].DeviceID}, "desired": {"installed"}})
		if rec.Code != 404 {
			t.Fatal("mixed-scope assignment accepted", rec.Code, rec.Body.String())
		}
		var assignments int
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_profile_assignments WHERE device_id=$1`, devices[0].DeviceID).Scan(&assignments); err != nil {
			t.Fatal(err)
		}
		if assignments != 0 {
			t.Fatal("failed batch partly changed authorized device")
		}
	})
	t.Run("operators can perform authorized work but not global configuration", func(t *testing.T) {
		rec := request("scoped-operator", "POST", base+"/ios/"+devices[0].DeviceID+"/refresh", nil)
		if rec.Code != 303 {
			t.Fatal("operator refresh denied", rec.Code, rec.Body.String())
		}
		rec = request("scoped-operator", "POST", base+"/ios/configurations/"+profileID+"/assign", url.Values{"device_id": {devices[0].DeviceID}, "desired": {"installed"}})
		if rec.Code != 303 {
			t.Fatal("operator profile assignment denied", rec.Code, rec.Body.String())
		}
		for _, path := range []string{base + "/ios/setup", base + "/ios/configurations", base + "/ios/" + devices[0].DeviceID + "/revoke"} {
			if rec = request("scoped-operator", "POST", path, nil); rec.Code != 403 {
				t.Error("operator modified configuration outside its capability", path, rec.Code)
			}
		}
		rec = request("organization-admin", "GET", base+"/ios/configurations/"+profileID+"/download", nil)
		if rec.Code != 200 {
			t.Fatal("organization admin cannot retrieve its profile", rec.Code)
		}
		rec = request("organization-admin", "GET", "/admin/access", nil)
		if rec.Code != 403 {
			t.Fatal("organization admin reached global access settings")
		}
	})
	t.Run("permission UI enforces confirmation CSRF version and last administrator", func(t *testing.T) {
		rec := request(adminID, "GET", "/admin/access?user_id=scoped-viewer", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Add or replace a permission") {
			t.Fatal("permissions UI missing", rec.Code, rec.Body.String())
		}
		if dir := os.Getenv("OPENUEM_ACCESS_UI_ARTIFACTS"); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "permissions.html"), rec.Body.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
		form := url.Values{"user_id": {"unassigned-user"}, "revision": {"0"}, "role": {"viewer"}, "tenant_id": {strconv.Itoa(tenantID)}, "site_id": {strconv.Itoa(siteID)}, "action": {"grant"}, "confirm": {"yes"}}
		form.Set("csrf", "wrong")
		rec = request(adminID, "POST", "/admin/access", form)
		if rec.Code != 403 {
			t.Fatal("permission update accepted wrong CSRF")
		}
		form.Set("csrf", "console-test-token")
		form.Del("confirm")
		rec = request(adminID, "POST", "/admin/access", form)
		if rec.Code != 400 {
			t.Fatal("permission update accepted without confirmation")
		}
		form.Set("confirm", "yes")
		rec = request(adminID, "POST", "/admin/access", form)
		if rec.Code != 303 {
			t.Fatal("permission UI did not save", rec.Code, rec.Body.String())
		}
		rec = request(adminID, "POST", "/admin/access", form)
		if rec.Code != 409 {
			t.Fatal("stale permission editor accepted")
		}
		rec = request("unassigned-user", "GET", base+"/devices", nil)
		if rec.Code != 200 {
			t.Fatal("permission grant not active on next request", rec.Code)
		}
		form.Set("revision", "1")
		form.Set("action", "revoke")
		rec = request(adminID, "POST", "/admin/access", form)
		if rec.Code != 303 {
			t.Fatal(rec.Code, rec.Body.String())
		}
		rec = request("unassigned-user", "GET", base+"/devices", nil)
		if rec.Code != 403 {
			t.Fatal("revocation did not apply to existing session", rec.Code)
		}
		rec = request(adminID, "POST", "/admin/access", url.Values{"user_id": {adminID}, "revision": {"1"}, "tenant_id": {"0"}, "site_id": {"0"}, "action": {"revoke"}, "confirm": {"yes"}})
		if rec.Code != 409 {
			t.Fatal("UI removed last administrator", rec.Code)
		}
		rec = request(adminID, "GET", "/admin/access/audit", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "permissions.replace") {
			t.Fatal("permission history missing", rec.Code)
		}
	})
	t.Run("inventory and profile reads are audited without contents", func(t *testing.T) {
		var inventory, downloads int
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_audit WHERE actor='scoped-viewer' AND action='inventory.read' AND resource_id=$1`, devices[0].DeviceID).Scan(&inventory); err != nil {
			t.Fatal(err)
		}
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_audit WHERE actor='organization-admin' AND action='profile.download' AND resource_id=$1`, profileID).Scan(&downloads); err != nil {
			t.Fatal(err)
		}
		if inventory == 0 || downloads == 0 {
			t.Fatal("sensitive read was not audited")
		}
	})
	t.Run("account reset retains permission identity and revokes old credentials", func(t *testing.T) {
		if err = h.Access.ReplaceGrants(ctx, adminID, "openuem", 0, []access.Grant{{Role: access.Administrator}}); err != nil {
			t.Fatal(err)
		}
		if err = h.Model.Client.User.UpdateOneID("openuem").SetUse2fa(true).SetTotpSecret("obsolete-secret").SetTotpSecretConfirmed(true).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err = h.Model.Client.Sessions.Create().SetID("reset-session").SetData([]byte("old-session")).SetExpiry(time.Now().Add(time.Hour)).SetOwnerID("openuem").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err = h.Model.Client.RecoveryCode.Create().SetUserID("openuem").SetCode("obsolete-code").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err = h.Model.CreateDefaultAdminPassword(true); err != nil {
			t.Fatal(err)
		}
		principal, err := h.Access.Principal(ctx, "openuem")
		if err != nil || !principal.IsAdministrator() {
			t.Fatal("account reset lost administrator permissions", err)
		}
		account, err := h.Model.GetUserById("openuem")
		if err != nil || account.Use2fa || account.TotpSecret != "" {
			t.Fatal("account reset retained old factor", err)
		}
		var sessions, codes int
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE token='reset-session'`).Scan(&sessions); err != nil {
			t.Fatal(err)
		}
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes WHERE code='obsolete-code'`).Scan(&codes); err != nil {
			t.Fatal(err)
		}
		if sessions != 0 || codes != 0 {
			t.Fatal("account reset left stale sessions or recovery codes")
		}
	})
}
