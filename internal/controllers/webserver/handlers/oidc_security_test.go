package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestOIDCRedirectUsesOnlyConfiguredOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, public, proxy, want string
	}{
		{"public", "https://console.example.test", "proxy.internal", "https://console.example.test/oidc/callback"},
		{"proxy", "", "proxy.example.test:8443", "https://proxy.example.test:8443/oidc/callback"},
		{"direct", "", "", "https://console.internal:1323/oidc/callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{PublicOrigin: tc.public, ReverseProxyServer: tc.proxy, ServerName: "console.internal", ConsolePort: "1323"}
			for _, referer := range []string{"", "https://untrusted.invalid/", "https://untrusted.invalid:9443/", "//untrusted.invalid/"} {
				r := httptest.NewRequest("GET", "https://injected.invalid/oidc", nil)
				r.Header.Set("Referer", referer)
				r.Header.Set("X-Forwarded-Host", "untrusted.invalid")
				c := echo.New().NewContext(r, httptest.NewRecorder())
				if got := h.GetRedirectURI(c); got != tc.want {
					t.Errorf("redirect = %q, want %q", got, tc.want)
				}
			}
		})
	}
}

func TestOIDCIssuerRequiresAnUnambiguousHTTPSURL(t *testing.T) {
	for _, raw := range []string{"https://issuer.example", "https://issuer.example/realm", "https://issuer.example:8443/", "https://[::1]/issuer"} {
		if !oidcIssuer(raw) {
			t.Error("valid issuer rejected", raw)
		}
	}
	for _, raw := range []string{"", "http://issuer.example", "//issuer.example", "https:///issuer", "https://user:password@issuer.example", "https://issuer.example?", "https://issuer.example?q=x", "https://issuer.example/#fragment"} {
		if oidcIssuer(raw) {
			t.Error("ambiguous or insecure issuer accepted", raw)
		}
	}
}
