package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	consolemiddleware "github.com/open-uem/openuem-console/internal/controllers/router/middleware"
	"github.com/open-uem/openuem-console/internal/security/audit"
)

func exerciseAuditConsole(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	var err error
	h.Audit, err = audit.NewStore(h.Model.DB, h.Access)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Audit.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const admin = "apple-console-admin"
	sm := h.SessionManager.Manager
	defer sm.Put(ctx, "uid", admin)
	base := fmt.Sprintf("/tenant/%d/audit", tenant)
	siteBase := fmt.Sprintf("/tenant/%d/site/%d/audit", tenant, site)
	var other int
	if err = h.Model.DB.QueryRow(`SELECT id FROM tenants WHERE id<>$1 ORDER BY id LIMIT 1`, tenant).Scan(&other); err != nil {
		t.Fatal(err)
	}
	actor := `=HYPERLINK("https://example.test")<script>alert(1)</script>`
	if _, err = h.Model.DB.Exec(`INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details,created_at) SELECT $1,$2,'audit-fixture',$3,jsonb_build_object('site_id',$4::bigint,'result','failure','secret','must-not-export'),clock_timestamp()-interval '1 hour' FROM generate_series(1,105)`, tenant, actor, strings.Repeat("long-device-id-", 80), site); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Model.DB.Exec(`INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,created_at) VALUES($1,'foreign-audit-actor','audit-fixture','foreign-audit-target',clock_timestamp()-interval '1 hour')`, other); err != nil {
		t.Fatal(err)
	}
	request := func(user, method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		sm.Put(ctx, "uid", user)
		req := httptest.NewRequest(method, path, strings.NewReader(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	artifact := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if dir := os.Getenv("OPENUEM_AUDIT_UI_ARTIFACTS"); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+".html"), rec.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	field := func(rec *httptest.ResponseRecorder, name string) string {
		t.Helper()
		match := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`).FindStringSubmatch(rec.Body.String())
		if len(match) != 2 {
			t.Fatalf("missing field %s: HTTP %d", name, rec.Code)
		}
		return html.UnescapeString(match[1])
	}
	form := func() url.Values {
		return url.Values{"csrf": {"console-test-token"}, "format": {"json"}, "action": {"audit-fixture"}}
	}
	t.Run("audit scope pagination escaping and exports", func(t *testing.T) {
		for _, path := range []string{base, siteBase} {
			rec := request("organization-admin", "GET", path+"?action=audit-fixture", nil)
			if rec.Code != 200 || strings.Count(rec.Body.String(), `class="uk-card uk-card-default audit-event"`) != 100 || !strings.Contains(rec.Body.String(), "Older events") {
				t.Fatal("audit page missing", rec.Code, rec.Body.String())
			}
			for _, forbidden := range []string{"foreign-audit-actor", "must-not-export", "<script>alert(1)</script>"} {
				if strings.Contains(rec.Body.String(), forbidden) {
					t.Fatal("audit disclosure or HTML injection", forbidden)
				}
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing audit privacy headers")
			}
			if path == base {
				artifact("audit-log", rec)
			}
			match := regexp.MustCompile(`href="([^"]+)"[^>]*>Older events`).FindStringSubmatch(rec.Body.String())
			if len(match) != 2 {
				t.Fatal("missing pagination link")
			}
			rec = request("organization-admin", "GET", html.UnescapeString(match[1]), nil)
			if rec.Code != 200 || strings.Count(rec.Body.String(), `class="uk-card uk-card-default audit-event"`) != 5 {
				t.Fatal("cursor lost events", rec.Code)
			}
		}
		rec := request("organization-admin", "POST", base+"/export?tenant_id="+fmt.Sprint(other)+"&action=ignored", form())
		var events []audit.Event
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &events) != nil || len(events) != 105 {
			t.Fatal("scoped JSON export failed", rec.Code, rec.Body.String())
		}
		for _, event := range events {
			if event.TenantID != tenant || event.SiteID != site || event.Actor != actor || event.Result != "failure" {
				t.Fatal("export changed scope or values", event)
			}
		}
		if !strings.HasPrefix(rec.Header().Get("Content-Disposition"), `attachment; filename="openuem-audit-`) || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unsafe export headers")
		}
		csv := form()
		csv.Set("format", "csv")
		rec = request("organization-admin", "POST", base+"/export", csv)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "[text] =HYPERLINK") || strings.Contains(rec.Body.String(), "must-not-export") {
			t.Fatal("CSV text protection failed", rec.Code)
		}
		rec = request(admin, "POST", "/audit/export", form())
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "foreign-audit-actor") {
			t.Fatal("global scope missing", rec.Code)
		}
	})
	t.Run("audit permissions malformed scopes and form boundaries", func(t *testing.T) {
		for _, user := range []string{"scoped-viewer", "scoped-operator", "unassigned-user"} {
			for _, path := range []string{"/audit", base, siteBase} {
				for _, method := range []string{"GET", "POST"} {
					target := path
					if method == "POST" {
						target += "/export"
					}
					if rec := request(user, method, target, form()); rec.Code != 403 {
						t.Fatal("role reached audit", user, target, rec.Code)
					}
				}
			}
		}
		for _, path := range []string{"/audit", fmt.Sprintf("/tenant/%d/audit", other), fmt.Sprintf("/tenant/%d/site/999999/audit", tenant)} {
			if rec := request("organization-admin", "GET", path, nil); rec.Code != 403 {
				t.Fatal("organization scope widened", path, rec.Code)
			}
		}
		for _, suffix := range []string{"?actor=a&actor=b", "?before=garbage", "?from=not-a-date", "?from=2027-01-01T00:00:00Z&until=2026-01-01T00:00:00Z", "?result=unknown", "?tenant_id=1", "?actor=%zz"} {
			if rec := request(admin, "GET", base+suffix, nil); rec.Code != 400 {
				t.Fatal("invalid filter accepted", suffix, rec.Code)
			}
		}
		for _, invalid := range []url.Values{{"csrf": {"wrong"}, "format": {"json"}}, {"csrf": {"console-test-token", "console-test-token"}, "format": {"json"}}, {"format": {"json"}}} {
			if rec := request(admin, "POST", base+"/export?csrf=console-test-token", invalid); rec.Code != 403 {
				t.Fatal("invalid CSRF accepted", rec.Code)
			}
		}
		for _, mutate := range []func(url.Values){func(v url.Values) { v["format"] = []string{"json", "csv"} }, func(v url.Values) { v.Set("tenant_id", fmt.Sprint(other)) }, func(v url.Values) { v.Set("actor", strings.Repeat("x", 17000)) }, func(v url.Values) { v.Set("format", "xml") }} {
			v := form()
			mutate(v)
			if rec := request(admin, "POST", base+"/export", v); rec.Code != 400 {
				t.Fatal("invalid export body accepted", rec.Code)
			}
		}
		if err := h.Model.Client.User.UpdateOneID("organization-admin").SetUse2fa(true).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		rec := request("organization-admin", "POST", base+"/export", form())
		if rec.Header().Get("Content-Disposition") != "" || strings.Contains(rec.Body.String(), "foreign-audit-target") || strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Fatal("export bypassed second factor", rec.Code)
		}
		if err := h.Model.Client.User.UpdateOneID("organization-admin").SetUse2fa(false).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("retention UI requires a scoped preview and confirmation", func(t *testing.T) {
		rec := request("organization-admin", "GET", base+"/retention", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Retain indefinitely") {
			t.Fatal("default policy missing", rec.Code)
		}
		v := url.Values{"csrf": {"console-test-token"}, "days": {"30"}}
		for _, user := range []string{"scoped-viewer", "scoped-operator"} {
			if rec := request(user, "POST", base+"/retention/preview", v); rec.Code != 403 {
				t.Fatal("reader changed retention", rec.Code)
			}
		}
		rec = request("organization-admin", "POST", base+"/retention/preview", v)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Review retention change") {
			t.Fatal("preview missing", rec.Code, rec.Body.String())
		}
		artifact("audit-retention", rec)
		apply := url.Values{"csrf": {"console-test-token"}, "preview": {field(rec, "preview")}, "token": {field(rec, "token")}}
		if rec = request("organization-admin", "POST", base+"/retention/apply", apply); rec.Code != 400 {
			t.Fatal("confirmation not required", rec.Code)
		}
		apply.Set("confirm", "yes")
		if rec = request(admin, "POST", base+"/retention/apply", apply); rec.Code != 409 {
			t.Fatal("another actor consumed preview", rec.Code)
		}
		if rec = request("organization-admin", "POST", base+"/retention/apply", apply); rec.Code != 303 || rec.Header().Get("Location") != base+"/retention" {
			t.Fatal("policy not saved", rec.Code, rec.Body.String())
		}
		if rec = request("organization-admin", "POST", base+"/retention/apply", apply); rec.Code != 409 {
			t.Fatal("preview replayed", rec.Code)
		}
		rec = request("organization-admin", "GET", base+"/retention", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Retain 30 days") || !strings.Contains(rec.Body.String(), "retention.change") {
			t.Fatal("policy evidence missing", rec.Code)
		}
	})
	t.Run("audit uses the common cookie and origin CSRF protection", func(t *testing.T) {
		protected := echo.New()
		protected.Use(consolemiddleware.CSRF())
		h.RegisterAudit(protected)
		sm.Put(ctx, "uid", admin)
		req := httptest.NewRequest("GET", "https://uem.example.test"+base, nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatal("cookie bootstrap failed", rec.Code)
		}
		token := field(rec, "csrf")
		cookies := rec.Result().Cookies()
		for _, origin := range []string{"https://attacker.example", "https://uem.example.test"} {
			v := form()
			v.Set("csrf", token)
			req = httptest.NewRequest("POST", "https://uem.example.test"+base+"/export", strings.NewReader(v.Encode())).WithContext(ctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", origin)
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			rec = httptest.NewRecorder()
			protected.ServeHTTP(rec, req)
			want := 200
			if origin == "https://attacker.example" {
				want = 403
			}
			if rec.Code != want {
				t.Fatal("origin protection failed", origin, rec.Code)
			}
		}
	})
}
