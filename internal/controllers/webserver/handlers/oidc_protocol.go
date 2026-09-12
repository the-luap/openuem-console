package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"golang.org/x/oauth2"
)

const oidcFlowCookie = "__Host-openuem-oidc"

var errOIDCResponse = errors.New("invalid OIDC response")

type oidcFlow struct {
	State, Verifier, Nonce     string
	Issuer, ClientID, Redirect string
	Policy, PolicyGeneration   string
	Expires                    int64
}

func oidcPolicy(settings *ent.Authentication) string {
	data, _ := json.Marshal([]any{settings.UseOIDC, settings.OIDCIssuerURL, settings.OIDCClientID, settings.OIDCProvider, settings.OIDCRole, settings.OIDCAutoCreateAccount, settings.OIDCAutoApprove})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (f oidcFlow) valid(settings *ent.Authentication, generation, redirect, state string, now time.Time) bool {
	return len(f.State) == 64 && len(f.Nonce) == 64 && len(f.Verifier) >= 43 && len(f.Verifier) <= 128 &&
		subtle.ConstantTimeCompare([]byte(f.State), []byte(state)) == 1 &&
		settings.UseOIDC && generation != "" && f.PolicyGeneration == generation && f.Policy == oidcPolicy(settings) && f.Issuer == settings.OIDCIssuerURL && f.ClientID == settings.OIDCClientID && f.Redirect == redirect &&
		f.Expires > now.Unix() && f.Expires <= now.Add(10*time.Minute).Unix()
}

func oidcHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func oidcIssuer(raw string) bool {
	if !oidcHTTPS(raw) {
		return false
	}
	u, _ := url.Parse(raw)
	return u.RawQuery == "" && !u.ForceQuery
}

type oidcTransport struct{ base http.RoundTripper }

func (t oidcTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !oidcHTTPS(req.URL.String()) {
		return nil, errOIDCResponse
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, 1<<20)
	return resp, nil
}

// All discovery, JWKS, token, UserInfo and role calls share a bounded client.
// The optional transport is supplied only by owned TLS tests.
func (h *Handler) oidcContext(parent context.Context) (context.Context, context.CancelFunc) {
	base := http.DefaultTransport
	if h.oidcHTTPTransport != nil {
		base = h.oidcHTTPTransport
	}
	client := &http.Client{Transport: oidcTransport{base}, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	return oidc.ClientContext(ctx, client), cancel
}

func oidcJSON(ctx context.Context, method, endpoint, bearer string, form url.Values, out any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errOIDCResponse
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")
	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		return errOIDCResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return errOIDCResponse
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errOIDCResponse
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil || !utf8.Valid(data) || json.Unmarshal(data, out) != nil {
		return errOIDCResponse
	}
	return nil
}

func verifyOIDCIdentity(ctx context.Context, provider *oidc.Provider, tokens *OAuth2TokenResponse, flow oidcFlow) (*oidc.IDToken, error) {
	if tokens.AccessToken == "" || len(tokens.AccessToken) > 32768 || tokens.IDToken == "" || len(tokens.IDToken) > 262144 || !strings.EqualFold(tokens.TokenType, "Bearer") {
		return nil, errOIDCResponse
	}
	id, err := provider.Verifier(&oidc.Config{ClientID: flow.ClientID}).Verify(ctx, tokens.IDToken)
	if err != nil || id.Issuer != flow.Issuer || id.Subject == "" || len(id.Subject) > 255 || strings.IndexFunc(id.Subject, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 || id.IssuedAt.IsZero() || id.IssuedAt.After(time.Now().Add(time.Minute)) || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(flow.Nonce)) != 1 {
		return nil, errOIDCResponse
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if id.Claims(&claims) != nil || (claims.AuthorizedParty != "" && claims.AuthorizedParty != flow.ClientID) || (len(id.Audience) > 1 && claims.AuthorizedParty != flow.ClientID) {
		return nil, errOIDCResponse
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(tokens.AccessToken) != nil {
		return nil, errOIDCResponse
	}
	return id, nil
}

func clearOIDCFlow(c echo.Context) {
	c.SetCookie(&http.Cookie{Name: oidcFlowCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
