package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestAuditCSRFRejectsOversizedAlreadyParsedAndChunkedForms(t *testing.T) {
	for _, preparsed := range []bool{false, true} {
		form := url.Values{"csrf": {"valid"}, "actor": {strings.Repeat("x", 20000)}}
		req := httptest.NewRequest("POST", "/audit/export", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = -1
		if preparsed {
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
		}
		c := echo.New().NewContext(req, httptest.NewRecorder())
		c.Set("csrf", "valid")
		called := false
		err := (&Handler{}).AuditCSRF(func(echo.Context) error { called = true; return nil })(c)
		if err == nil || called {
			t.Fatal("oversized form reached audit", preparsed)
		}
	}
}
