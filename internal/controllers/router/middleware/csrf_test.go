package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestCSRFRequiresRequestTokenForEveryMutation(t *testing.T) {
	for _, metadata := range []string{"", "same-origin", "none", "same-site"} {
		e := echo.New()
		e.Use(CSRF())
		e.Any("/*", func(c echo.Context) error { return c.String(200, c.Get("csrf").(string)) })
		get := httptest.NewRequest("GET", "https://console.test/tenant/1/ios/setup", nil)
		get.Header.Set("Sec-Fetch-Site", metadata)
		initial := httptest.NewRecorder()
		e.ServeHTTP(initial, get)
		cookies := initial.Result().Cookies()
		if initial.Code != 200 || len(cookies) != 1 {
			t.Fatal("missing token issuance", initial.Code)
		}
		cookie := cookies[0]
		if cookie.Name != "__Host-openuem-csrf" || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || len(cookie.Value) != 32 || initial.Body.String() != cookie.Value {
			t.Fatal("invalid CSRF cookie or rendered token")
		}
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			for _, mode := range []string{"cookie only", "wrong header", "header", "form", "query only"} {
				t.Run(metadata+method+mode, func(t *testing.T) {
					values := url.Values{}
					if mode == "form" {
						values.Set("csrf", cookie.Value)
					}
					req := httptest.NewRequest(method, "https://console.test/tenant/1/ios/setup", strings.NewReader(values.Encode()))
					if mode == "query only" {
						req.URL.RawQuery = url.Values{"csrf": {cookie.Value}}.Encode()
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("Sec-Fetch-Site", metadata)
					req.Header.Set("Origin", "https://console.test")
					req.AddCookie(cookie)
					if mode == "header" {
						req.Header.Set("X-CSRF-TOKEN", cookie.Value)
					}
					if mode == "wrong header" {
						req.Header.Set("X-CSRF-TOKEN", "wrong")
					}
					result := httptest.NewRecorder()
					e.ServeHTTP(result, req)
					want := 403
					if mode == "header" || (mode == "form" && method != "DELETE") {
						want = 200
					}
					// net/http parses URL-encoded bodies for POST/PUT/PATCH. DELETE uses
					// the HTMX header supplied by the shared layout.
					if result.Code != want {
						t.Fatalf("got %d, want %d: %s", result.Code, want, result.Body.String())
					}
				})
			}
		}
		for _, origin := range []string{"https://evil.test", "https://other.console.test", "http://console.test", "null", "https://console.test:444", "https://console.test/path"} {
			req := httptest.NewRequest("POST", "https://console.test/ios/setup", nil)
			req.AddCookie(cookie)
			req.Header.Set("Origin", origin)
			req.Header.Set("X-CSRF-Token", cookie.Value)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			result := httptest.NewRecorder()
			e.ServeHTTP(result, req)
			if result.Code != 403 {
				t.Fatal("cross-origin mutation accepted", origin)
			}
		}
	}
}

func TestCSRFNativeFormRemainsReadable(t *testing.T) {
	e := echo.New()
	e.Use(CSRF())
	e.POST("/ios/setup", func(c echo.Context) error {
		if c.FormValue("organization") != "Example" {
			t.Fatal("middleware lost parsed form")
		}
		if c.Request().Header.Get("Sec-Fetch-Site") != "same-origin" {
			t.Fatal("middleware lost fetch metadata")
		}
		return c.NoContent(204)
	})
	token := strings.Repeat("a", 32)
	req := httptest.NewRequest("POST", "https://console.test/ios/setup", strings.NewReader(url.Values{"csrf": {token}, "organization": {"Example"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "__Host-openuem-csrf", Value: token})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

func TestCSRFLimitsNativeFormsBeforeTokenExtraction(t *testing.T) {
	e := echo.New()
	e.Use(CSRF())
	e.POST("/ios/setup", func(echo.Context) error { t.Fatal("oversized native form reached handler"); return nil })
	req := httptest.NewRequest("POST", "https://console.test/ios/setup", strings.NewReader("csrf="+strings.Repeat("a", 32)+"&data="+strings.Repeat("x", 4<<20)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "__Host-openuem-csrf", Value: strings.Repeat("a", 32)})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

func TestCSRFLimitsWindowsFormsBeforeTokenExtraction(t *testing.T) {
	for _, route := range []string{"/windows/setup", "/tenant/:tenant/windows/invitations", "/tenant/:tenant/site/:site/windows/:id/revoke"} {
		e := echo.New()
		e.Use(CSRF())
		e.POST(route, func(echo.Context) error { t.Fatal("oversized Windows form reached handler"); return nil })
		path := strings.NewReplacer(":tenant", "1", ":site", "11", ":id", "device").Replace(route)
		r := httptest.NewRequest("POST", "https://console.test"+path, strings.NewReader("csrf="+strings.Repeat("a", 32)+"&data="+strings.Repeat("x", 8192)))
		r.ContentLength = -1
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: "__Host-openuem-csrf", Value: strings.Repeat("a", 32)})
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != 413 {
			t.Fatal("Windows form body was parsed beyond its bound", w.Code)
		}
	}
}

func TestCSRFSmallFormsRejectWirePaddingWithEitherTokenPath(t *testing.T) {
	for _, route := range []string{"/login/new", "/ios/:id/update", "/tenant/:tenant/site/:site/ios/update-plans", "/devices/export", "/device-groups", "/tenant/:tenant/site/:site/device-groups/:group", "/tenant/:tenant/site/:site/ios/configurations/:id/assign", "/tenant/:tenant/site/:site/ios/configurations/:id/group-assignments"} {
		for _, header := range []bool{false, true} {
			e := echo.New()
			e.Use(CSRF())
			e.POST(route, func(echo.Context) error { t.Fatal("oversized normalized form reached handler"); return nil })
			path := strings.NewReplacer(":tenant", "1", ":site", "11", ":id", "profile", ":group", "group").Replace(route)
			token := strings.Repeat("a", 32)
			body := "csrf=" + token + strings.Repeat("&", int(scopedFormLimit(route)))
			r := httptest.NewRequest(http.MethodPost, "https://console.test"+path, strings.NewReader(body))
			r.ContentLength = -1
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: "__Host-openuem-csrf", Value: token})
			if header {
				r.Header.Set("X-CSRF-Token", token)
			}
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("route %s header=%v: got %d", route, header, w.Code)
			}
		}
	}
}
