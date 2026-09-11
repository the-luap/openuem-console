package account_views

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
	"github.com/open-uem/openuem-console/internal/preferences"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestAccountLanguageViewsUseCatalogFallbackAndResponsiveProfile(t *testing.T) {
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
	sm.Put(ctx, "uid", "account-reader")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/myaccount", nil).WithContext(ctx), httptest.NewRecorder())
	info.Principal = access.Principal{UserID: "account-reader", Grants: []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}
	for _, state := range []string{"browser", "en", "de", "es", "ca", "fr", "no", "pt", "unavailable", "long"} {
		code := state
		if state == "browser" || state == "unavailable" || state == "long" {
			code = "en"
		}
		if !preferences.ValidLanguage(code) {
			t.Fatal("unsupported fixture language")
		}
		localized, err := ctxi18n.WithLocale(ctx, code)
		if err != nil {
			t.Fatal(err)
		}
		if string(ctxi18n.Locale(localized).Code()) != code {
			t.Fatal("bundled catalog does not match preference", code)
		}
		c.SetRequest(c.Request().WithContext(localized))
		data := LanguageData{Selected: code, Unavailable: state == "unavailable"}
		if state == "browser" {
			data.Selected = ""
		}
		info.CSRFToken = "owned-language-csrf"
		user := &ent.User{ID: "account-reader", Name: "Example User", Email: "reader@example.test", Country: "de", Passwd: true}
		if state == "long" {
			user.Name = strings.Repeat("LongAccountName", 25)
			user.Email = strings.Repeat("localpart", 30) + "@example.test"
		}
		var body bytes.Buffer
		if err = MyAccountIndex("My Account", MyAccount(c, user, "de", info, "", data), info).Render(localized, &body); err != nil {
			t.Fatal(err)
		}
		html := body.String()
		if !strings.Contains(html, `lang="`+code+`"`) || strings.Contains(html, "!(MISSING:") || !strings.Contains(html, "Display language") {
			t.Fatal("document locale or English fallback missing", state)
		}
		if data.Unavailable {
			if strings.Contains(html, `id="account-language"`) || !strings.Contains(html, "Your language preference is unavailable") {
				t.Fatal("unavailable preference offered a save")
			}
		} else if !strings.Contains(html, `action="/myaccount/language"`) || !strings.Contains(html, `name="csrf" value="owned-language-csrf"`) {
			t.Fatal("account language form lost protected endpoint", state)
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			if err = os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "account-language-"+state+".html"), body.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
