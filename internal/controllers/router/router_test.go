package router

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
)

func TestRouterAppliesCSRFAcrossNativeAndHTMXForms(t *testing.T) {
	e := New(&sessions.SessionManager{Manager: scs.New()}, "console.test", "443", "1M")
	e.GET("/csrf-test", func(c echo.Context) error { return c.String(200, c.Get("csrf").(string)) })
	mutations := 0
	for _, path := range []string{"/admin/settings", "/tenant/1/ios/setup", "/tenant/1/site/1/profiles"} {
		e.POST(path, func(c echo.Context) error { mutations++; return c.String(200, c.FormValue("name")) })
	}
	req := httptest.NewRequest("GET", "https://console.test/csrf-test", nil)
	req.Header.Set("Sec-Fetch-Site", "none")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	token := rec.Body.String()
	var csrf *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "__Host-openuem-csrf" {
			csrf = cookie
		}
	}
	if csrf == nil || csrf.Value != token {
		t.Fatal("router did not issue a usable token")
	}
	for _, path := range []string{"/admin/settings", "/tenant/1/ios/setup", "/tenant/1/site/1/profiles"} {
		for _, mode := range []string{"cookie-only", "native", "htmx"} {
			form := url.Values{"name": {"Example"}}
			if mode == "native" {
				form.Set("csrf", token)
			}
			req := httptest.NewRequest("POST", "https://console.test"+path, strings.NewReader(form.Encode()))
			req.AddCookie(csrf)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Origin", "https://console.test")
			if mode == "htmx" {
				req.Header.Set("HX-Request", "true")
				req.Header.Set("X-CSRF-TOKEN", token)
			}
			rec := httptest.NewRecorder()
			before := mutations
			e.ServeHTTP(rec, req)
			if mode == "cookie-only" {
				if mutations != before || rec.Code != http.StatusForbidden {
					t.Fatal("cookie alone authorized mutation")
				}
			} else if rec.Code != 200 || mutations != before+1 || rec.Body.String() != "Example" {
				t.Fatalf("%s %s failed: %d %s", path, mode, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestHTTPErrorRendererHidesInternalFailures(t *testing.T) {
	const secret = "owned-private-token-canary"
	for _, code := range []int{400, 409, 422, 500, 501, 502, 503, 504, 599} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			e := New(&sessions.SessionManager{Manager: scs.New()}, "console.test", "443", "1M")
			e.Logger.SetOutput(io.Discard)
			message := "Check the selected device and try again."
			if code >= 500 {
				message = "Post https://push.example.test/device/" + secret
			}
			e.GET("/owned-error", func(c echo.Context) error {
				return echo.NewHTTPError(code, message).SetInternal(errors.New("database credential=" + secret))
			})
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://console.test/owned-error", nil))
			if rec.Code != code {
				t.Fatal("error rendering changed the response status", rec.Code)
			}
			if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "push.example.test") || strings.Contains(rec.Body.String(), "internal=") {
				t.Error("error rendering exposed internal failure details")
			}
			if code < 500 && !strings.Contains(rec.Body.String(), message) {
				t.Error("error rendering lost an actionable client rejection")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("error response permitted browser storage")
			}
		})
	}
}

func TestHTTPErrorRendererPreservesStatus(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 405, 413, 429, 500} {
		e := echo.New()
		e.HTTPErrorHandler = customHTTPErrorHandler
		e.GET("/error", func(c echo.Context) error { return echo.NewHTTPError(code, "Request rejected") })
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest("GET", "https://console.test/error", nil))
		if rec.Code != code {
			t.Fatalf("rendered error %d as HTTP %d", code, rec.Code)
		}
	}
}

func TestHTTPErrorRendererBeforeLocaleAndAfterCommit(t *testing.T) {
	for _, typed := range []bool{false, true} {
		e := echo.New()
		e.Logger.SetOutput(io.Discard)
		e.HTTPErrorHandler = customHTTPErrorHandler
		e.GET("/error", func(c echo.Context) error {
			if typed {
				return echo.NewHTTPError(500, "owned-private-canary")
			}
			return errors.New("owned-private-canary")
		})
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://console.test/error", nil))
		if rec.Code != 500 || !strings.Contains(rec.Body.String(), "Refresh the page to check its status") || strings.Contains(rec.Body.String(), "owned-private-canary") || strings.Contains(rec.Body.String(), "MISSING") {
			t.Fatal("early error lost safe English fallback", typed, rec.Code)
		}
	}
	e := echo.New()
	e.HTTPErrorHandler = customHTTPErrorHandler
	e.GET("/committed", func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "private, max-age=30")
		if err := c.String(http.StatusAccepted, "Already committed"); err != nil {
			return err
		}
		return echo.NewHTTPError(500, "owned-private-canary")
	})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://console.test/committed", nil))
	if rec.Code != http.StatusAccepted || rec.Body.String() != "Already committed" || rec.Header().Get(echo.HeaderCacheControl) != "private, max-age=30" {
		t.Fatal("late error modified an already committed response")
	}
}
