package handlers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestADEExactRoutesAndSafeFailures(t *testing.T) {
	for route, method := range map[string]string{"/ios/ade": "GET", "/ios/ade/servers": "POST", "/ios/ade/servers/:id/certificate": "GET", "/ios/ade/servers/:id/token": "POST", "/ios/ade/servers/:id/action": "POST", "/ios/ade/servers/:id/profiles": "POST", "/ios/ade/servers/:id/profiles/:profile/action": "POST", "/ios/ade/servers/:id/targets": "POST", "/ios/ade/servers/:id/targets/:serial/rearm": "POST"} {
		for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
			for _, m := range []string{"GET", "POST", "HEAD", "DELETE", "PUT"} {
				cap, ok := appleCapability(m, prefix+route)
				if ok != (method == m) || (ok && cap != access.ManageCertificates) {
					t.Fatal("unexpected ADE route authority", m, route)
				}
			}
		}
	}
	err := adeFailure(errors.New("synthetic private token and database connection details"))
	if strings.Contains(err.Error(), "synthetic private") {
		t.Fatal("private error details escaped")
	}
}

func exerciseADERoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant, otherSite int) {
	t.Helper()
	t.Run("ADE connection routes enforce organization scope and safe token import", func(t *testing.T) {
		defer stampOwnedConsoleSession(t, h, ctx, "apple-console-admin")
		request := func(user, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
			t.Helper()
			stampOwnedConsoleSession(t, h, ctx, user)
			req := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			return rec
		}
		base := fmt.Sprintf("/tenant/%d/site/%d/ios/ade", tenant, site)
		post := func(user, path string, f url.Values) *httptest.ResponseRecorder {
			return request(user, "POST", path, "application/x-www-form-urlencoded", []byte(f.Encode()))
		}
		form := url.Values{"csrf": {"console-test-token"}, "name": {"Connection <script>synthetic-name</script>"}}
		for _, user := range []string{"scoped-viewer", "scoped-operator"} {
			if rec := request(user, "GET", base, "", nil); rec.Code != 403 {
				t.Fatal("ADE inventory permission bypass", rec.Code)
			}
			if rec := post(user, base+"/servers", form); rec.Code != 403 {
				t.Fatal("ADE create permission bypass", rec.Code)
			}
		}
		form.Set("csrf", "bad")
		if rec := post("organization-admin", base+"/servers", form); rec.Code != 403 {
			t.Fatal("ADE CSRF bypass", rec.Code)
		}
		form.Set("csrf", "console-test-token")
		form.Add("name", "duplicate")
		if rec := post("organization-admin", base+"/servers", form); rec.Code != 400 {
			t.Fatal("duplicate connection name accepted", rec.Code)
		}
		form["name"] = form["name"][:1]
		if rec := post("organization-admin", base+"/servers?name=query", form); rec.Code != 400 {
			t.Fatal("query fallback accepted", rec.Code)
		}
		if rec := post("organization-admin", base+"/servers", form); rec.Code != 303 {
			t.Fatal("ADE create failed", rec.Code, rec.Body.String())
		}
		servers, err := h.Apple.ADEServers(ctx, tenant)
		if err != nil || len(servers) != 1 {
			t.Fatal("missing ADE connection", err)
		}
		id := servers[0].ID
		path := base + "/servers/" + id
		rec := request("organization-admin", "GET", base, "", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), id) || strings.Contains(rec.Body.String(), "<script>synthetic-name</script>") || !strings.Contains(rec.Body.String(), "&lt;script&gt;") {
			t.Fatal("unsafe ADE rendering", rec.Code)
		}
		for _, user := range []string{"scoped-viewer", "scoped-operator"} {
			for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
				p := prefix + "/ios/ade/servers/" + id
				if rec := request(user, "GET", p+"/certificate", "", nil); rec.Code != 403 {
					t.Fatal("public certificate downloaded without organization authority", rec.Code)
				}
				for _, suffix := range []string{"/token", "/action", "/profiles", "/profiles/00000000-0000-4000-8000-000000000001/action", "/targets", "/targets/SYNTHETIC1/rearm"} {
					if rec := post(user, p+suffix, form); rec.Code != 403 {
						t.Fatal("ADE mutation permission bypass", suffix, rec.Code)
					}
				}
			}
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/ios/ade", otherTenant, otherSite)
		if rec := request("apple-console-admin", "GET", foreign+"?server="+id, "", nil); rec.Code != 404 {
			t.Fatal("cross-tenant ADE inventory", rec.Code)
		}
		if rec := request("apple-console-admin", "GET", foreign+"/servers/"+id+"/certificate", "", nil); rec.Code != 404 {
			t.Fatal("cross-tenant ADE certificate", rec.Code)
		}
		rec = request("organization-admin", "GET", path+"/certificate", "", nil)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Header().Get("Content-Disposition"), id+".pem") {
			t.Fatal("certificate download protection", rec.Code)
		}
		block, rest := pem.Decode(rec.Body.Bytes())
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || bytes.Contains(rec.Body.Bytes(), []byte("PRIVATE KEY")) {
			t.Fatal("not a public certificate")
		}
		if _, err = x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatal(err)
		}
		upload := func(mode string) ([]byte, string) {
			var b bytes.Buffer
			w := multipart.NewWriter(&b)
			csrf := "console-test-token"
			if mode == "csrf" {
				csrf = "invalid"
			}
			if err := w.WriteField("csrf", csrf); err != nil {
				t.Fatal(err)
			}
			if mode != "confirmation" {
				if err := w.WriteField("confirmed", "yes"); err != nil {
					t.Fatal(err)
				}
			}
			count := 1
			if mode == "duplicate" {
				count = 2
			}
			for i := 0; i < count; i++ {
				p, err := w.CreateFormFile("token", "synthetic.p7m")
				if err != nil {
					t.Fatal(err)
				}
				data := []byte("synthetic-private-invalid-token")
				if mode == "oversized" {
					data = bytes.Repeat([]byte("x"), (1<<20)+1)
				}
				if _, err = p.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			return b.Bytes(), w.FormDataContentType()
		}
		for _, mode := range []string{"invalid", "duplicate", "confirmation", "oversized", "csrf"} {
			body, contentType := upload(mode)
			rec := request("organization-admin", "POST", path+"/token", contentType, body)
			want := 400
			if mode == "csrf" {
				want = 403
			}
			if rec.Code != want || strings.Contains(rec.Body.String(), "synthetic-private-invalid-token") {
				t.Fatal("unsafe token import", mode, rec.Code)
			}
		}
		// This fixture only stages durable operator intent. No ADE worker or
		// external Apple service is started by the console route test.
		if _, err = h.Model.DB.Exec(`UPDATE mdm_apple_ade_servers SET status='connected',token='synthetic-test-only',token_expires_at=clock_timestamp()+interval '1 year',apple_server_id='eeeeeeee-0000-4000-8000-000000000001',apple_organization_id='synthetic-console-org' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		profileForm := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "name": {"Synthetic automated Mac"}, "platform": {"macos"}, "site_id": {fmt.Sprint(site)}, "removal": {"disallowed"}, "await_configuration": {"yes"}, "ignore_backup_profile": {"yes"}}
		oversized := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "serials": {strings.Repeat("x", 129<<10)}}
		if rec := post("organization-admin", path+"/targets", oversized); rec.Code != 403 {
			t.Fatal("ADE body bound was bypassed by CSRF form parsing", rec.Code)
		}
		if rec := post("organization-admin", path+"/profiles", profileForm); rec.Code != 303 {
			t.Fatal("ADE profile intent failed", rec.Code, rec.Body.String())
		}
		profiles, err := h.Apple.ADEProfiles(ctx, tenant, id)
		if err != nil || len(profiles) != 1 || profiles[0].Status != "queued" || profiles[0].SiteID != site || profiles[0].Removable {
			t.Fatal("ADE profile intent not persisted", err)
		}
		profileID := profiles[0].ID
		profileForm.Set("site_id", fmt.Sprint(otherSite))
		if rec := post("organization-admin", path+"/profiles", profileForm); rec.Code != 400 {
			t.Fatal("ADE profile site switched", rec.Code)
		}
		profileForm.Set("site_id", fmt.Sprint(site))
		if _, err = h.Model.DB.Exec(`UPDATE mdm_apple_ade_profiles SET status='published',remote_id='SYNTHETICCONSOLE1' WHERE id=$1`, profileID); err != nil {
			t.Fatal(err)
		}
		if _, err = h.Model.DB.Exec(`INSERT INTO mdm_apple_ade_devices(tenant_id,server_id,serial,assigned,payload) VALUES($1,$2,'SYNTHETICCONSOLE1',true,'{}')`, tenant, id); err != nil {
			t.Fatal(err)
		}
		targetForm := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "profile_id": {profileID}, "serials": {"SYNTHETICCONSOLE1"}}
		if rec := post("organization-admin", path+"/targets", targetForm); rec.Code != 303 {
			t.Fatal("ADE target intent failed", rec.Code, rec.Body.String())
		}
		targets, _, err := h.Apple.ADETargets(ctx, tenant, id, "")
		if err != nil || len(targets) != 1 || targets[0].Status != "pending" || targets[0].DeviceID != "" {
			t.Fatal("assignment was confused with enrollment", err)
		}
		actionForm := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "operation": {"disable"}}
		if rec := post("organization-admin", path+"/profiles/"+profileID+"/action", actionForm); rec.Code != 409 {
			t.Fatal("assigned ADE version disabled", rec.Code)
		}
		if rec := post("organization-admin", path+"/targets/SYNTHETICCONSOLE1/rearm", url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}}); rec.Code != 404 {
			t.Fatal("unused activation rearmed", rec.Code)
		}
		targetForm.Set("profile_id", "clear")
		if rec := post("organization-admin", path+"/targets", targetForm); rec.Code != 303 {
			t.Fatal("ADE clear intent failed", rec.Code)
		}
		if rec := post("organization-admin", path+"/profiles/"+profileID+"/action", actionForm); rec.Code != 303 {
			t.Fatal("unassigned ADE version not disabled", rec.Code)
		}
		f := url.Values{"csrf": {"console-test-token"}, "operation": {"disable"}}
		if rec := post("organization-admin", path+"/action", f); rec.Code != 400 {
			t.Fatal("disable lacked confirmation", rec.Code)
		}
		f.Set("confirmed", "yes")
		f.Add("operation", "sync")
		if rec := post("organization-admin", path+"/action", f); rec.Code != 400 {
			t.Fatal("ambiguous action accepted", rec.Code)
		}
		f.Set("operation", "disable")
		if rec := post("organization-admin", path+"/action", f); rec.Code != 303 {
			t.Fatal("disable failed", rec.Code)
		}
		servers, err = h.Apple.ADEServers(ctx, tenant)
		if err != nil || servers[0].Status != "disabled" {
			t.Fatal("disable not persisted", err)
		}
		var n int
		if err = h.Model.DB.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE tenant_id=$1 AND action='apple.ade.certificate.download' AND resource_id=$2`, tenant, id).Scan(&n); err != nil || n != 1 {
			t.Fatal("certificate download audit missing", err)
		}
	})
}
