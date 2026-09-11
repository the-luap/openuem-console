package handlers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/open-uem/ent"
)

func oidcSignedFixture(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"owned-key"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCIdentityVerificationUsesOwnedTLSProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "userinfo_endpoint": server.URL + "/userinfo", "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "owned-key", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	h := &Handler{oidcHTTPTransport: server.Client().Transport}
	ctx, cancel := h.oidcContext(t.Context())
	defer cancel()
	provider, err := oidc.NewProvider(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	flow := oidcFlow{Issuer: server.URL, ClientID: "owned-client", Nonce: strings.Repeat("n", 64)}
	for _, name := range []string{"valid", "wrong signature", "wrong issuer", "wrong audience", "expired", "missing nonce", "wrong nonce", "missing subject", "long subject", "missing issued at", "future issued at", "wrong authorized party", "multiple audiences without authorized party", "multiple audiences with authorized party", "wrong access token hash", "valid access token hash", "missing token", "wrong token type"} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{"iss": server.URL, "sub": "owned-subject", "aud": "owned-client", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "nonce": flow.Nonce}
			signer := key
			valid := name == "valid" || name == "multiple audiences with authorized party" || name == "valid access token hash"
			switch name {
			case "wrong signature":
				signer = wrongKey
			case "wrong issuer":
				claims["iss"] = "https://wrong-issuer.invalid"
			case "wrong audience":
				claims["aud"] = "other-client"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			case "missing nonce":
				delete(claims, "nonce")
			case "wrong nonce":
				claims["nonce"] = "wrong"
			case "missing subject":
				delete(claims, "sub")
			case "long subject":
				claims["sub"] = strings.Repeat("x", 256)
			case "missing issued at":
				delete(claims, "iat")
			case "future issued at":
				claims["iat"] = time.Now().Add(time.Hour).Unix()
			case "wrong authorized party":
				claims["azp"] = "other-client"
			case "multiple audiences without authorized party":
				claims["aud"] = []string{"owned-client", "another"}
			case "multiple audiences with authorized party":
				claims["aud"] = []string{"owned-client", "another"}
				claims["azp"] = "owned-client"
			case "wrong access token hash":
				claims["at_hash"] = "wrong"
			case "valid access token hash":
				digest := sha256.Sum256([]byte("owned-access-token"))
				claims["at_hash"] = base64.RawURLEncoding.EncodeToString(digest[:16])
			}
			tokens := &OAuth2TokenResponse{AccessToken: "owned-access-token", TokenType: "Bearer", IDToken: oidcSignedFixture(t, signer, claims)}
			if name == "missing token" {
				tokens.IDToken = ""
			}
			if name == "wrong token type" {
				tokens.TokenType = "MAC"
			}
			identity, err := verifyOIDCIdentity(ctx, provider, tokens, flow)
			if valid {
				if err != nil || identity == nil || identity.Subject != "owned-subject" {
					t.Fatal("valid identity rejected", err)
				}
			} else if err == nil || identity != nil {
				t.Fatal("invalid identity admitted", name)
			}
		})
	}
}

func TestOIDCFlowExpiresAndBindsConfiguration(t *testing.T) {
	now := time.Now()
	settings := &ent.Authentication{UseOIDC: true, OIDCIssuerURL: "https://issuer.example", OIDCClientID: "owned-client"}
	original := oidcFlow{Policy: oidcPolicy(settings), State: strings.Repeat("s", 64), Nonce: strings.Repeat("n", 64), Verifier: strings.Repeat("v", 43), Issuer: settings.OIDCIssuerURL, ClientID: settings.OIDCClientID, Redirect: "https://console.example/oidc/callback", Expires: now.Add(10 * time.Minute).Unix()}
	if !original.valid(settings, original.Redirect, original.State, now) {
		t.Fatal("fresh flow rejected")
	}
	for _, name := range []string{"expired", "future", "state", "nonce", "verifier", "issuer", "client", "redirect"} {
		f := original
		switch name {
		case "expired":
			f.Expires = now.Unix()
		case "future":
			f.Expires = now.Add(11 * time.Minute).Unix()
		case "state":
			f.State = strings.Repeat("x", 64)
		case "nonce":
			f.Nonce = ""
		case "verifier":
			f.Verifier = ""
		case "issuer":
			f.Issuer = "https://other.example"
		case "client":
			f.ClientID = "other"
		case "redirect":
			f.Redirect = "https://untrusted.invalid"
		}
		if f.valid(settings, original.Redirect, original.State, now) {
			t.Fatal("unbound flow accepted", name)
		}
	}
}

func TestOIDCHTTPRejectsRedirectsErrorsOversizeAndCancellation(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(`{"sub":"owned-subject"}`))
		case "/redirect":
			http.Redirect(w, r, server.URL+"/ok", http.StatusFound)
		case "/error":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"sub":"must-not-be-admitted"}`))
		case "/large":
			w.Write([]byte(`{"sub":"` + strings.Repeat("x", 1<<20) + `"}`))
		case "/utf8":
			w.Write([]byte{'{', '"', 's', 'u', 'b', '"', ':', '"', 0xff, '"', '}'})

		case "/trailing":
			w.Write([]byte(`{"sub":"owned-subject"} {}`))
		}
	}))
	t.Cleanup(server.Close)
	h := &Handler{oidcHTTPTransport: server.Client().Transport}
	ctx, cancel := h.oidcContext(t.Context())
	defer cancel()
	for _, path := range []string{"/ok", "/redirect", "/error", "/large", "/trailing", "/utf8"} {
		var response UserInfoResponse
		err := oidcJSON(ctx, http.MethodGet, server.URL+path, "owned-access-token", nil, &response)
		if path == "/ok" {
			if err != nil || response.Subject != "owned-subject" {
				t.Fatal("valid bounded response failed", err)
			}
		} else if err == nil {
			t.Fatal("invalid response accepted", path)
		}
	}
	var response UserInfoResponse
	if err := oidcJSON(ctx, http.MethodGet, "http://127.0.0.1:1/", "owned-access-token", nil, &response); err == nil {
		t.Fatal("plaintext token transport allowed")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := oidcJSON(cancelled, http.MethodGet, server.URL+"/ok", "owned-access-token", nil, &response); err == nil {
		t.Fatal("cancelled request continued")
	}
}
