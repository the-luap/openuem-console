package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestAppleFormsRequireMatchingCSRF(t *testing.T) {
	h := &Handler{}
	for _, token := range []string{"", "wrong", "expected-token"} {
		t.Run(token, func(t *testing.T) {
			form := url.Values{"csrf": {token}}
			r := httptest.NewRequest(http.MethodPost, "/ios/setup", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			c := echo.New().NewContext(r, httptest.NewRecorder())
			c.Set("csrf", "expected-token")
			called := false
			err := h.AppleCSRF(func(echo.Context) error { called = true; return nil })(c)
			if token == "expected-token" {
				if err != nil || !called {
					t.Fatal("valid form rejected", err)
				}
			} else if err == nil || called {
				t.Fatal("invalid form reached mutation")
			}
		})
	}
}

func TestAppleResourceIDsRejectNonUUIDs(t *testing.T) {
	for _, id := range []string{"../settings", "abc", "1 OR 1=1", ""} {
		c := echo.New().NewContext(httptest.NewRequest("GET", "/ios/"+url.PathEscape(id), nil), httptest.NewRecorder())
		c.SetParamNames("id")
		c.SetParamValues(id)
		if _, err := appleID(c); err == nil {
			t.Fatalf("accepted invalid device ID %q", id)
		}
	}
}
