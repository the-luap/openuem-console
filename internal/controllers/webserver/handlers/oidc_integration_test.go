package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/router"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

type ownedOIDCGrant struct {
	query                   url.Values
	mode, username, subject string
}
type ownedOIDCProvider struct {
	server           *httptest.Server
	key              *rsa.PrivateKey
	mu               sync.Mutex
	codes            map[string]ownedOIDCGrant
	tokens           map[string]ownedOIDCGrant
	calls, serial    int
	insecureEndpoint string
}

func newOwnedOIDCProvider(t *testing.T) *ownedOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &ownedOIDCProvider{key: key, codes: make(map[string]ownedOIDCGrant), tokens: make(map[string]ownedOIDCGrant)}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.calls++
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			metadata := map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "userinfo_endpoint": p.server.URL + "/userinfo", "jwks_uri": p.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
			p.mu.Lock()
			endpoint := p.insecureEndpoint
			p.mu.Unlock()
			if endpoint != "" {
				metadata[endpoint] = "http://untrusted.invalid"
			}
			json.NewEncoder(w).Encode(metadata)
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "owned-key", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		case "/token":
			if r.Method != "POST" || r.ParseForm() != nil {
				w.WriteHeader(400)
				return
			}
			code := r.PostForm.Get("code")
			p.mu.Lock()
			grant, ok := p.codes[code]
			delete(p.codes, code)
			p.mu.Unlock()
			digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if !ok || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("client_id") != grant.query.Get("client_id") || r.PostForm.Get("redirect_uri") != grant.query.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(digest[:]) != grant.query.Get("code_challenge") {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"owned-secret-canary"}`))
				return
			}
			if grant.mode == "token_error" {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"owned-secret-canary"}`))
				return
			}
			claims := map[string]any{"iss": p.server.URL, "sub": grant.subject, "aud": "owned-client", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "nonce": grant.query.Get("nonce")}
			if grant.mode == "wrong_nonce" {
				claims["nonce"] = "wrong"
			}
			idToken := oidcSignedFixture(t, p.key, claims)
			if grant.mode == "missing_id_token" {
				idToken = ""
			}
			token := "owned-access-" + code
			p.mu.Lock()
			p.tokens[token] = grant
			p.mu.Unlock()
			json.NewEncoder(w).Encode(OAuth2TokenResponse{AccessToken: token, IDToken: idToken, TokenType: "Bearer", ExpiresIn: 60})
		case "/userinfo", "/auth/v1/permissions/me/_search":
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			p.mu.Lock()
			grant, ok := p.tokens[token]
			p.mu.Unlock()
			if !ok {
				w.WriteHeader(401)
				return
			}
			groups := []string{"uem-users"}
			if grant.mode == "role_denied" {
				groups = nil
			}
			if r.URL.Path != "/userinfo" {
				json.NewEncoder(w).Encode(ZitadelRolesResponse{Roles: groups})
				return
			}
			if grant.mode == "userinfo_error" {
				w.WriteHeader(500)
				w.Write([]byte(`{"error":"owned-secret-canary"}`))
				return
			}
			subject := grant.subject
			if grant.mode == "wrong_subject" {
				subject = "different-subject"
			}
			json.NewEncoder(w).Encode(UserInfoResponse{Subject: subject, PreferredUsername: grant.username, Name: "Owned OIDC user", Email: "owned-oidc@example.test", EmailVerified: true, Groups: groups})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *ownedOIDCProvider) grant(t *testing.T, location, mode, username string, subjects ...string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || u.String() == "" || !strings.HasPrefix(location, p.server.URL+"/authorize?") {
		t.Fatal("authorization target changed")
	}
	q := u.Query()
	if q.Get("client_id") != "owned-client" || q.Get("redirect_uri") != "https://console.test/oidc/callback" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || len(q.Get("nonce")) != 64 || len(q.Get("state")) != 64 || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatal("authorization lost PKCE, nonce or configured origin")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.serial++
	code := fmt.Sprintf("owned-code-%d", p.serial)
	subject := "subject-" + username
	if len(subjects) > 0 {
		subject = subjects[0]
	}
	p.codes[code] = ownedOIDCGrant{query: q, mode: mode, username: username, subject: subject}
	return "/oidc/callback?" + url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {p.server.URL}}.Encode()
}

func TestOIDCConsoleWithPostgresAndOwnedTLSProvider(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for OIDC integration")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "oidc_console_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	t.Setenv("ENV", "test")
	m, err := models.New(u.String(), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.Client.Settings.Create().Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = m.CreateDefaultTenantAndSite(); err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct {
		id             string
		openid, passwd bool
	}{{"oidc-reader", true, false}, {"password-victim", false, true}, {"certificate-victim", false, false}, {"revoked-oidc", true, false}} {
		if err = m.Client.User.Create().SetID(user.id).SetName(user.id).SetEmail(user.id + "@example.test").SetEmailVerified(true).SetOpenid(user.openid).SetPasswd(user.passwd).SetRegister(nats.REGISTER_APPROVED).SetUse2fa(false).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	provider := newOwnedOIDCProvider(t)
	settings, err := m.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	configure := func(kind string) {
		t.Helper()
		if err := settings.Update().SetUseOIDC(true).SetOIDCProvider(kind).SetOIDCIssuerURL(provider.server.URL).SetOIDCClientID("owned-client").SetOIDCRole("uem-users").SetOIDCCookieEncriptionKey(strings.Repeat("k", 32)).SetOIDCAutoCreateAccount(false).SetOIDCAutoApprove(false).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	configure("authelia")
	permissions, err := access.NewStore(m.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(t.Context(), "certificate-victim"); err != nil {
		t.Fatal(err)
	}
	accounts, err := oidcaccounts.NewStore(m.DB, permissions)
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"oidc-reader", "revoked-oidc"} {
		if err = accounts.Change(t.Context(), "certificate-victim", uid, provider.server.URL, "owned-client", "subject-"+uid, "link", 0); err != nil {
			t.Fatal(err)
		}
	}
	pool, err := pgxpool.New(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sm := scs.New()
	sm.Store = sessions.NewWithConfig(pool, sessions.Config{})
	sm.Cookie.Secure = true
	h := &Handler{Model: m, Access: permissions, OIDCAccounts: accounts, SessionManager: &sessions.SessionManager{Manager: sm, Pool: pool}, PublicOrigin: "https://console.test", ReverseProxyServer: "proxy.internal", oidcHTTPTransport: provider.server.Client().Transport}
	e := router.New(h.SessionManager, "console.test", "443", "1M")
	e.GET("/oidc", h.OIDCLogIn)
	e.GET("/oidc/callback", h.OIDCCallback)
	e.GET("/fixture/session", func(c echo.Context) error { return c.String(200, sm.GetString(c.Request().Context(), "uid")) })
	type browser map[string]*http.Cookie
	request := func(b browser, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("GET", "https://console.test"+path, nil)
		req.Header.Set("Referer", "https://untrusted.invalid/")
		for _, cookie := range b {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		for _, cookie := range rec.Result().Cookies() {
			if cookie.MaxAge < 0 {
				delete(b, cookie.Name)
			} else {
				b[cookie.Name] = cookie
			}
		}
		if strings.Contains(rec.Body.String(), "owned-secret-canary") {
			t.Fatal("provider details leaked into response")
		}
		return rec
	}
	begin := func(b browser, mode, username string, subjects ...string) string {
		t.Helper()
		rec := request(b, "/oidc")
		if rec.Code != 302 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("OIDC start failed", rec.Code)
		}
		cookie := b[oidcFlowCookie]
		if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("OIDC flow cookie lost host binding")
		}
		return provider.grant(t, rec.Header().Get("Location"), mode, username, subjects...)
	}
	for _, endpoint := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint"} {
		provider.mu.Lock()
		provider.insecureEndpoint = endpoint
		provider.mu.Unlock()
		b := browser{}
		if rec := request(b, "/oidc"); rec.Code != 503 || b[oidcFlowCookie] != nil {
			t.Fatal("insecure discovery endpoint started sign-in", endpoint, rec.Code)
		}
	}
	provider.mu.Lock()
	provider.insecureEndpoint = ""
	provider.mu.Unlock()

	for _, kind := range []string{"authelia", "authentik", "keycloak", "zitadel"} {
		configure(kind)
		b := browser{}
		callback := begin(b, "valid", "oidc-reader")
		saved := *b[oidcFlowCookie]
		rec := request(b, callback)
		if rec.Code != 302 || request(b, "/fixture/session").Body.String() != "oidc-reader" || b[oidcFlowCookie] != nil {
			t.Fatal("valid OIDC callback did not create and bind a session", kind, rec.Code)
		}
		replay := browser{oidcFlowCookie: &saved}
		if rec = request(replay, callback); rec.Code < 400 || request(replay, "/fixture/session").Body.String() != "" {
			t.Fatal("authorization code replay created a session", kind, rec.Code)
		}
		denied := browser{}
		rec = request(denied, begin(denied, "role_denied", "oidc-reader"))
		if rec.Code < 400 || request(denied, "/fixture/session").Body.String() != "" {
			t.Fatal("provider role requirement bypassed", kind, rec.Code)
		}
	}
	configure("authelia")
	for _, username := range []string{"renamed-user", "password-victim", "certificate-victim", ""} {
		b := browser{}
		if rec := request(b, begin(b, "valid", username, "subject-oidc-reader")); rec.Code != 302 || request(b, "/fixture/session").Body.String() != "oidc-reader" {
			t.Fatal("verified subject lost account after username change", rec.Code)
		}
	}
	recycled := browser{}
	if rec := request(recycled, begin(recycled, "valid", "oidc-reader", "replacement-subject")); rec.Code != 401 || request(recycled, "/fixture/session").Body.String() != "" {
		t.Fatal("recycled username inherited an existing account", rec.Code)
	}
	if err = settings.Update().SetOIDCAutoCreateAccount(true).SetOIDCAutoApprove(true).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	newAccount := browser{}
	if rec := request(newAccount, begin(newAccount, "valid", "certificate-victim", "brand-new-subject")); rec.Code != 302 {
		t.Fatal("automatic identity registration failed", rec.Code)
	}
	newUID := request(newAccount, "/fixture/session").Body.String()
	if !strings.HasPrefix(newUID, "oidc-") {
		t.Fatal("automatic registration used a provider username")
	}
	principal, err := permissions.Principal(t.Context(), newUID)
	if err != nil || len(principal.Grants) != 0 {
		t.Fatal("new identity inherited account permissions", err)
	}
	configure("authelia")
	for _, mode := range []string{"missing_id_token", "wrong_nonce", "wrong_subject", "token_error", "userinfo_error"} {
		b := browser{}
		rec := request(b, begin(b, mode, "oidc-reader"))
		if rec.Code < 400 || request(b, "/fixture/session").Body.String() != "" || b[oidcFlowCookie] != nil {
			t.Fatal("invalid identity created a session", mode, rec.Code)
		}
	}
	for _, victim := range []string{"password-victim", "certificate-victim"} {
		b := browser{}
		rec := request(b, begin(b, "valid", victim))
		if rec.Code != 401 || request(b, "/fixture/session").Body.String() != "" {
			t.Fatal("OIDC username selected another authentication mode", victim, rec.Code)
		}
	}
	if err = m.Client.User.UpdateOneID("revoked-oidc").SetRegister(nats.REGISTER_REVOKED).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = settings.Update().SetOIDCAutoApprove(true).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	revoked := browser{}
	if rec := request(revoked, begin(revoked, "valid", "revoked-oidc")); rec.Code != 401 || request(revoked, "/fixture/session").Body.String() != "" {
		t.Fatal("auto approval reactivated a revoked OIDC account", rec.Code)
	}

	for _, mode := range []string{"expired", "tampered", "duplicate cookie", "duplicate state", "changed client", "changed issuer", "changed role", "changed provider", "changed approval", "disabled"} {
		configure("authelia")
		b := browser{}
		callback := begin(b, "valid", "oidc-reader")
		switch mode {
		case "expired":
			req := httptest.NewRequest("GET", "https://console.test", nil)
			req.AddCookie(b[oidcFlowCookie])
			c := echo.New().NewContext(req, httptest.NewRecorder())
			raw, err := ReadOIDCCookie(c, oidcFlowCookie, strings.Repeat("k", 32))
			if err != nil {
				t.Fatal(err)
			}
			var flow oidcFlow
			if err = json.Unmarshal([]byte(raw), &flow); err != nil {
				t.Fatal(err)
			}
			flow.Expires = time.Now().Add(-time.Second).Unix()
			data, _ := json.Marshal(flow)
			rec := httptest.NewRecorder()
			c = echo.New().NewContext(httptest.NewRequest("GET", "/", nil), rec)
			if err = h.WriteOIDCCookie(c, oidcFlowCookie, string(data), strings.Repeat("k", 32)); err != nil {
				t.Fatal(err)
			}
			b[oidcFlowCookie] = rec.Result().Cookies()[0]
		case "tampered":
			b[oidcFlowCookie].Value = "invalid"
		case "duplicate cookie":
			duplicate := *b[oidcFlowCookie]
			b["duplicate"] = &duplicate

		case "duplicate state":
			callback += "&state=duplicate"
		case "changed client":
			if err = settings.Update().SetOIDCClientID("changed").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		case "changed issuer":
			if err = settings.Update().SetOIDCIssuerURL("https://untrusted.invalid").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		case "changed role":
			if err = settings.Update().SetOIDCRole("other-role").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		case "changed provider":
			if err = settings.Update().SetOIDCProvider("zitadel").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		case "changed approval":
			if err = settings.Update().SetOIDCAutoApprove(true).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}

		case "disabled":
			if err = settings.Update().SetUseOIDC(false).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		provider.mu.Lock()
		before := provider.calls
		provider.mu.Unlock()
		rec := request(b, callback)
		provider.mu.Lock()
		after := provider.calls
		provider.mu.Unlock()
		if rec.Code < 400 || before != after || request(b, "/fixture/session").Body.String() != "" || b[oidcFlowCookie] != nil {
			t.Fatal("invalid flow continued to the provider or session", mode, rec.Code, before, after)
		}
	}
}
