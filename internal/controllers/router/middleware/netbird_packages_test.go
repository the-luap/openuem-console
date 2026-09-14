package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestNetbirdPackageCSRFBoundsBeforeFormNormalization(t *testing.T) {
	for _, route := range []string{"/tenant/:tenant/netbird/packages", "/tenant/:tenant/netbird/packages/:approval/revoke"} {
		for _, header := range []bool{false, true} {
			e := echo.New()
			e.Use(CSRF())
			e.POST(route, func(echo.Context) error { t.Fatal("oversized package form reached the handler"); return nil })
			path := strings.NewReplacer(":tenant", "1", ":approval", "10000000-0000-4000-8000-000000000001").Replace(route)
			token := strings.Repeat("t", 32)
			r := httptest.NewRequest(http.MethodPost, "https://console.test"+path, strings.NewReader("csrf="+token+strings.Repeat("&", 16<<10)))
			r.ContentLength = -1
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: "__Host-openuem-csrf", Value: token})
			if header {
				r.Header.Set("X-CSRF-Token", token)
			}
			response := httptest.NewRecorder()
			e.ServeHTTP(response, r)
			require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
		}
	}
}
