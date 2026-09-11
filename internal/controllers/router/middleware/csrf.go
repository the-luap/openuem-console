package middleware

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	mw "github.com/labstack/echo/v4/middleware"
)

// CSRF validates a request token for both HTMX requests and native HTML forms.
// Fetch metadata is an additional restriction, never a token-check bypass.
func CSRF() echo.MiddlewareFunc {
	tokens := mw.CSRFWithConfig(mw.CSRFConfig{
		TokenLookup: "header:X-CSRF-Token",
		CookieName:  "__Host-openuem-csrf", CookiePath: "/", CookieSecure: true,
		CookieHTTPOnly: true, CookieSameSite: http.SameSiteStrictMode,
		ErrorHandler: func(error, echo.Context) error { return echo.NewHTTPError(http.StatusForbidden, "Invalid CSRF token") },
	})
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			original := c.Request()
			switch original.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
			default:
				if original.Header.Get("Sec-Fetch-Site") == "cross-site" || !sameRequestOrigin(original) {
					return echo.NewHTTPError(http.StatusForbidden, "Cross-origin request rejected")
				}
			}
			// Echo's optional Fetch Metadata shortcut uses a fixed placeholder token.
			// Always take its cryptographically random cookie/request-token path so
			// ordinary forms and HTMX share one invariant, regardless of browser age.
			request := original.Clone(original.Context())
			request.Header.Del("Sec-Fetch-Site")
			if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions && request.Header.Get("X-CSRF-Token") == "" {
				// Parse PostForm, not Form: query parameters must never become
				// CSRF credentials or appear in access logs as token-bearing URLs.
				// Native console forms are small. Large package uploads use
				// the HTMX header and retain the configured global upload limit.
				limit := int64(4 << 20)
				route := strings.TrimPrefix(strings.TrimPrefix(c.Path(), "/tenant/:tenant/site/:site"), "/tenant/:tenant")
				if route == "/myaccount/language" || route == "/windows" || strings.HasPrefix(route, "/windows/") {
					limit = 8192
				}
				request.Body = http.MaxBytesReader(c.Response(), request.Body, limit)
				parseErr := request.ParseForm()
				if parseErr == nil {
					parseErr = request.ParseMultipartForm(4 << 20)
				}
				var tooLarge *http.MaxBytesError
				if errors.As(parseErr, &tooLarge) {
					return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Form is too large")
				}
				if parseErr != nil && !errors.Is(parseErr, http.ErrNotMultipart) {
					return echo.NewHTTPError(http.StatusBadRequest, "Invalid form")
				}
				if request.MultipartForm != nil {
					defer request.MultipartForm.RemoveAll()
				}
				if token := request.PostForm.Get("csrf"); token != "" {
					request.Header.Set("X-CSRF-Token", token)
				}
			}
			c.SetRequest(request)
			defer c.SetRequest(original)
			return tokens(func(c echo.Context) error {
				// Keep parsed form/body state for handlers while restoring fetch metadata.
				if value := original.Header.Values("Sec-Fetch-Site"); len(value) > 0 {
					request.Header["Sec-Fetch-Site"] = value
				}
				return next(c)
			})(c)
		}
	}
}

func sameRequestOrigin(r *http.Request) bool {
	value := r.Header.Get("Origin")
	if value == "" {
		return true
	} // Non-browser/older clients still need a valid token.
	origin, err := url.Parse(value)
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.Host == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	target, err := url.Parse(scheme + "://" + r.Host)
	if err != nil {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return origin.Scheme == target.Scheme && strings.EqualFold(origin.Hostname(), target.Hostname()) && port(origin) == port(target)
}
