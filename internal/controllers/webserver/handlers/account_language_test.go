package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/router"
	"github.com/open-uem/openuem-console/internal/preferences"
)

func exerciseAccountLanguageRoutes(t *testing.T, h *Handler) {
	t.Helper()
	store, err := preferences.NewStore(h.Model.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.Preferences = store
	// Use production locale, session and CSRF middleware with independent cookies.
	e := router.New(h.SessionManager, "console.test", "443", "1M")
	h.Register(e, 3)
	e.GET("/fixture/login/:id", func(c echo.Context) error {
		h.SessionManager.Manager.Put(c.Request().Context(), "uid", c.Param("id"))
		h.SessionManager.Manager.Put(c.Request().Context(), "usepasswd", false)
		return c.String(200, c.Get("csrf").(string))
	})
	type browser struct {
		cookies map[string]*http.Cookie
		token   string
	}
	request := func(b *browser, method, path, body, origin string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "https://console.test"+path, strings.NewReader(body))
		req.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.5")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		for _, cookie := range b.cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		for _, cookie := range rec.Result().Cookies() {
			b.cookies[cookie.Name] = cookie
		}
		return rec
	}
	login := func(id string) *browser {
		b := &browser{cookies: map[string]*http.Cookie{}}
		rec := request(b, "GET", "/fixture/login/"+id, "", "")
		if rec.Code != 200 {
			t.Fatal("fixture session unavailable", rec.Code)
		}
		b.token = rec.Body.String()
		return b
	}
	one, two, other := login("scoped-viewer"), login("scoped-viewer"), login("scoped-operator")
	account := func(b *browser, want string) {
		t.Helper()
		rec := request(b, "GET", "/myaccount", "", "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `lang="`+want+`"`) || !strings.Contains(rec.Body.String(), `id="account-language"`) {
			t.Fatal("account language unavailable", want, rec.Code, rec.Body.String())
		}
	}
	save := func(b *browser, code string) *httptest.ResponseRecorder {
		return request(b, "POST", "/myaccount/language", url.Values{"locale": {code}, "csrf": {b.token}}.Encode(), "https://console.test")
	}
	account(one, "de")
	if rec := save(one, "en"); rec.Code != 303 || rec.Header().Get("Location") != "/myaccount" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("language save failed", rec.Code, rec.Body.String())
	}
	account(one, "en")
	account(two, "en")
	account(other, "de")
	// A different browser header never overrides a saved choice, and a new session
	// for the same account reads persistence rather than a prior session field.
	account(login("scoped-viewer"), "en")
	for _, body := range []string{
		"locale=fr&locale=en", "locale=de-DE", "locale=%ff", "locale=%00", "locale=%zz", "unknown=fr", "user_id=scoped-operator&locale=fr", "locale=fr&csrf=x", "locale=" + strings.Repeat("x", 8193),
	} {
		rec := request(one, "POST", "/myaccount/language", body+"&csrf="+url.QueryEscape(one.token), "https://console.test")
		if rec.Code != 400 && rec.Code != 403 && rec.Code != 413 {
			t.Fatal("bad preference form accepted", rec.Code)
		}
		if got, err := store.Language(t.Context(), "scoped-viewer"); got != "en" || err != nil {
			t.Fatal("bad form changed preference", got, err)
		}
	}
	for _, entry := range []struct{ body, origin, path string }{
		{"locale=fr", "https://console.test", "/myaccount/language"},
		{url.Values{"locale": {"fr"}, "csrf": {one.token}}.Encode(), "https://foreign.test", "/myaccount/language"},
		{url.Values{"locale": {"fr"}, "csrf": {one.token}}.Encode(), "https://console.test", "/myaccount/language?user_id=scoped-operator"},
	} {
		rec := request(one, "POST", entry.path, entry.body, entry.origin)
		if rec.Code != 400 && rec.Code != 403 {
			t.Fatal("CSRF or query bypass accepted", rec.Code)
		}
	}
	account(other, "de")
	if rec := save(one, ""); rec.Code != 303 {
		t.Fatal("browser default could not be restored", rec.Code)
	}
	account(one, "de")
	account(two, "de")
	if rec := save(one, "en"); rec.Code != 303 {
		t.Fatal(rec.Code)
	}
	if _, err := h.Model.DB.Exec(`ALTER TABLE uem_user_preferences RENAME TO unavailable_user_preferences`); err != nil {
		t.Fatal(err)
	}
	defer h.Model.DB.Exec(`ALTER TABLE unavailable_user_preferences RENAME TO uem_user_preferences`)
	rec := request(one, "GET", "/myaccount", "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `lang="de"`) || !strings.Contains(rec.Body.String(), "Your language preference is unavailable") || strings.Contains(rec.Body.String(), `id="account-language"`) {
		t.Fatal("preference outage blocked browser fallback or offered unsafe save", rec.Code)
	}
	if rec = save(one, "fr"); rec.Code != 503 || strings.Contains(rec.Body.String(), "uem_user_preferences") {
		t.Fatal("preference storage failure not redacted", rec.Code, rec.Body.String())
	}
}
