package handlers

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

func exerciseOIDCAccountRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenantID, siteID int) {
	t.Helper()
	store, err := oidcaccounts.NewStore(h.Model.DB, h.Access)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h.OIDCAccounts = store
	settings, err := h.Model.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := settings.Update().SetUseOIDC(settings.UseOIDC).SetOIDCIssuerURL(settings.OIDCIssuerURL).SetOIDCClientID(settings.OIDCClientID).Exec(ctx); err != nil {
			t.Error(err)
		}
	}()
	if err = settings.Update().SetUseOIDC(true).SetOIDCIssuerURL("https://identity.example.test").SetOIDCClientID("owned-client").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"binding-account", "binding-other", "binding-viewer", "binding-operator", "binding-orgadmin"} {
		if err = h.Model.Client.User.Create().SetID(uid).SetName(uid).SetEmail(uid + "@example.test").SetOpenid(uid == "binding-account" || uid == "binding-other").SetUse2fa(false).SetRegister(nats.REGISTER_APPROVED).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []struct {
		uid  string
		role access.Role
	}{{"binding-viewer", access.Viewer}, {"binding-operator", access.Operator}, {"binding-orgadmin", access.TenantAdmin}} {
		scope := access.Scope{TenantID: tenantID, SiteID: siteID}
		if entry.role == access.TenantAdmin {
			scope.SiteID = 0
		}
		if err = h.Access.ReplaceGrants(ctx, "apple-console-admin", entry.uid, 0, []access.Grant{{Role: entry.role, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
	}
	sm := h.SessionManager.Manager
	defer sm.Put(ctx, "uid", "apple-console-admin")
	request := func(actor, method, path string, form url.Values) *httptest.ResponseRecorder {
		sm.Put(ctx, "uid", actor)
		sm.Put(ctx, "usepasswd", false)
		req := httptest.NewRequest(method, path, strings.NewReader(form.Encode())).WithContext(ctx)
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	valid := func() url.Values {
		return url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "user_id": {"binding-account"}, "issuer": {"https://identity.example.test"}, "client_id": {"owned-client"}, "subject": {"exact-subject"}, "action": {"link"}, "revision": {"0"}}
	}
	path := "/admin/oidc-accounts"
	for _, actor := range []string{"binding-viewer", "binding-operator", "binding-orgadmin"} {
		for _, method := range []string{"GET", "POST"} {
			if rec := request(actor, method, path+map[string]string{"GET": "?user_id=binding-account"}[method], valid()); rec.Code != 403 {
				t.Fatal("scoped role accessed account identity", actor, method, rec.Code)
			}
		}
	}
	admin := "apple-console-admin"
	if rec := request(admin, "GET", path+"?user_id=binding-account", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "No identities are linked.") || !strings.Contains(rec.Body.String(), `data-oidc-link`) {
		t.Fatal("identity migration page unavailable", rec.Code)
	}
	for _, mode := range []string{"csrf", "unconfirmed", "duplicate", "query", "provider", "mode", "revision"} {
		f := valid()
		target := path
		switch mode {
		case "csrf":
			f.Set("csrf", "wrong")
		case "unconfirmed":
			f.Del("confirmed")
		case "duplicate":
			f.Add("subject", "another")
		case "query":
			target += "?subject=other"
		case "provider":
			f.Set("issuer", "https://replacement.example.test")
		case "mode":
			f.Set("user_id", admin)
		case "revision":
			f.Set("revision", "1")
		}
		if rec := request(admin, "POST", target, f); rec.Code < 400 {
			t.Fatal("invalid identity form accepted", mode, rec.Code)
		}
	}
	page, err := store.Page(ctx, admin, "binding-account")
	if err != nil || page.Revision != 0 || len(page.Events) != 0 {
		t.Fatal("rejected form mutated identity", err)
	}
	if rec := request(admin, "POST", path, valid()); rec.Code != 303 {
		t.Fatal("explicit identity link failed", rec.Code, rec.Body.String())
	}
	if rec := request(admin, "POST", path, valid()); rec.Code != 409 {
		t.Fatal("stale identity form accepted", rec.Code)
	}
	if rec := request(admin, "GET", path+"?user_id=binding-account", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "exact-subject") || !strings.Contains(rec.Body.String(), "Revision 1") {
		t.Fatal("identity details or audit missing", rec.Code)
	}
	form := valid()
	form.Set("action", "disable")
	form.Set("revision", "1")
	if rec := request(admin, "POST", path, form); rec.Code != 303 {
		t.Fatal("disable failed", rec.Code)
	}
	form = valid()
	form.Set("user_id", "binding-other")
	if rec := request(admin, "POST", path, form); rec.Code != 409 {
		t.Fatal("reserved identity was reassigned", rec.Code)
	}
	form = valid()
	form.Set("action", "enable")
	form.Set("revision", "2")
	if rec := request(admin, "POST", path, form); rec.Code != 303 {
		t.Fatal("reenable failed", rec.Code)
	}
	if rec := request(admin, "POST", path, valid()); rec.Code != 409 {
		t.Fatal("old revision became valid again", rec.Code)
	}
	if rec := request(admin, "DELETE", "/admin/users/binding-account", nil); rec.Code != 409 || !strings.Contains(rec.Body.String(), "permanent OpenID identity records") || strings.Contains(rec.Body.String(), "uem_oidc_") {
		t.Fatal("bound-account deletion lacked a safe explanation", rec.Code, rec.Body.String())
	}
}
