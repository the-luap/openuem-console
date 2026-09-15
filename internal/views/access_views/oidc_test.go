package access_views

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
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestOIDCIdentityViewsAndConfirmation(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, "uid", "identity-admin")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "-1", SiteID: "-1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", CSRFToken: "owned-oidc-csrf", Tenants: []*ent.Tenant{}, Sites: []*ent.Site{}, Principal: access.Principal{UserID: "identity-admin", Grants: []access.Grant{{Role: access.Administrator}}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/admin/oidc-accounts?user_id=legacy-account", nil).WithContext(ctx), httptest.NewRecorder())
	for _, state := range []string{"unlinked", "active", "disabled", "ineligible", "long", "provider_disabled"} {
		page := &oidcaccounts.Page{UserID: "legacy-account", Name: "Legacy OIDC user", Issuer: "https://identity.example.test", ClientID: "owned-client", Eligible: true, Enabled: true, Revision: 3}
		if state == "ineligible" {
			page.Eligible = false
		}
		if state == "provider_disabled" {
			page.Enabled = false
		}
		if state == "active" || state == "disabled" || state == "long" {
			subject := `"><img src=x onerror="window.__ownedOIDC=true">`
			if state == "long" {
				page.UserID = strings.Repeat("account", 35)
				page.Name = strings.Repeat("Long name ", 80)
				page.Issuer += "/" + strings.Repeat("issuer", 300)
				subject = strings.Repeat("subject", 35)
			}
			page.Bindings = []oidcaccounts.Binding{{Issuer: page.Issuer, Subject: subject, Active: state != "disabled"}}
			page.Events = []oidcaccounts.Event{{ID: 1, Revision: 3, Actor: "identity-admin", Issuer: page.Issuer, Subject: subject, Action: "link", At: time.Date(2026, 9, 11, 10, 5, 3, 123456000, time.UTC)}}
		}
		var b bytes.Buffer
		if err = OIDCAccount(c, info, page).Render(ctx, &b); err != nil {
			t.Fatal(err)
		}
		html := b.String()
		if strings.Contains(html, `<img src=x`) || strings.Contains(html, "!(MISSING:") {
			t.Fatal("identity page injected markup or lost catalog")
		}
		if strings.Contains(html, "data-oidc-link") != page.CanLink() {
			t.Fatal("identity creation eligibility mismatch", state)
		}
		if !strings.Contains(html, "Latest 25 identity changes") || !strings.Contains(html, "email addresses do not establish identity") {
			t.Fatal("identity meaning or bounded history lost")
		}
		if len(page.Bindings) > 0 && !strings.Contains(html, `datetime="2026-09-11T10:05:03.123456Z"`) {
			t.Fatal("identity audit lost exact instant")
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			if err = os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "oidc-accounts-"+state+".html"), b.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
