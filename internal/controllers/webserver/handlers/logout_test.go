package handlers

import (
	"net/url"
	"strings"
	"testing"

	"github.com/open-uem/ent"
)

func TestOIDCLogoutURLPreservesConfigurationAndEscapesParameters(t *testing.T) {
	for _, origin := range []struct {
		name string
		h    Handler
		want string
	}{
		{"public", Handler{PublicOrigin: "https://console.example.test:8443", ReverseProxyServer: "proxy.internal"}, "https://console.example.test:8443"},
		{"proxy", Handler{ReverseProxyServer: "proxy.example.test:8443"}, "https://proxy.example.test:8443"},
		{"direct", Handler{ServerName: "console.internal", ConsolePort: "1323"}, "https://console.internal:1323"},
	} {
		for provider, endpoint := range map[string]string{"authelia": "logout", "authentik": "end-session/", "keycloak": "protocol/openid-connect/logout", "zitadel": "oidc/v1/end_session"} {
			for _, slash := range []string{"", "/"} {
				t.Run(origin.name+"/"+provider+"/"+slash, func(t *testing.T) {
					const prefix = "/realm/owned%2Fidentity/"
					const client = "owned + client&post_logout_redirect_uri=https://untrusted.invalid/?a=b#雪"
					settings := &ent.Authentication{OIDCProvider: provider, OIDCIssuerURL: "https://identity.example.test:9443" + strings.TrimSuffix(prefix, "/") + slash, OIDCClientID: client}
					target, err := url.Parse(origin.h.oidcLogoutURL(settings))
					if err != nil {
						t.Fatal(err)
					}
					if target.Scheme != "https" || target.Host != "identity.example.test:9443" || target.EscapedPath() != prefix+endpoint || target.User != nil || target.Fragment != "" {
						t.Fatal("logout URL changed the issuer or endpoint", target)
					}
					query := target.Query()
					switch provider {
					case "authelia":
						if len(query) != 1 || query.Get("rd") != origin.want {
							t.Fatal("logout lost its configured return origin", query)
						}
					case "authentik":
						if len(query) != 0 {
							t.Fatal("logout added unsupported parameters", query)
						}
					default:
						if len(query) != 2 || query.Get("client_id") != client || query.Get("post_logout_redirect_uri") != origin.want {
							t.Fatal("client identifier altered logout parameters", query)
						}
					}
				})
			}
		}
	}
}

func TestOIDCLogoutUnavailableProviderReturnsToConsole(t *testing.T) {
	h := &Handler{PublicOrigin: "https://console.example.test"}
	for _, issuer := range []string{"", "http://identity.example.test", "https://user:password@identity.example.test", "https://identity.example.test?", "https://identity.example.test?next=untrusted", "https://identity.example.test/#fragment"} {
		if target := h.oidcLogoutURL(&ent.Authentication{OIDCProvider: "authelia", OIDCIssuerURL: issuer}); target != h.PublicOrigin {
			t.Error("invalid provider URL prevented a local logout destination", target)
		}
	}
	if h.oidcLogoutURL(nil) != h.PublicOrigin || h.oidcLogoutURL(&ent.Authentication{OIDCProvider: "unsupported", OIDCIssuerURL: "https://identity.example.test"}) != h.PublicOrigin {
		t.Fatal("unavailable provider lost the local logout destination")
	}
}
