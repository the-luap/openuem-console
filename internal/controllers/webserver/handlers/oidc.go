package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/auth"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/utils"
	"golang.org/x/oauth2"
)

type OAuth2TokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type UserInfoResponse struct {
	Subject           string   `json:"sub,omitempty"`
	Name              string   `json:"name,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	UpdatedAt         int      `json:"updated_at,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	Error             string   `json:"error,omitempty"`
	ErrorDescription  string   `json:"error_description,omitempty"`
	Groups            []string `json:"groups"`
}

type ZitadelRolesResponse struct {
	Roles   []string `json:"result"`
	Message string   `json:"message"`
}

type OIDCSessionInfo struct {
	Issuer, Subject, Policy string
	ID, Name, Email, Phone  string
	EmailVerified           bool
}

func (h *Handler) OIDCLogIn(c echo.Context) error {
	ctx, cancel := h.oidcContext(c.Request().Context())
	defer cancel()
	c.SetRequest(c.Request().WithContext(ctx))
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")

	settings, err := h.Model.GetAuthenticationSettings()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.could_not_get_settings"))
	}

	if !settings.UseOIDC {
		return echo.NewHTTPError(http.StatusForbidden, "OpenID sign-in is disabled")
	}

	// if CloudFlare Turnstile is used, check response
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err))
	}

	isTurnstileEnabled := tsSecretKey != "" && tsSiteKey != ""

	if isTurnstileEnabled {
		cfTurnStileResponse := c.QueryParam("cf-turnstile-response")
		if cfTurnStileResponse == "" {
			return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "settings.turnstile_challenge_not_found"))
		}
		if err := h.TurnstileCheckChallenge(c, cfTurnStileResponse, tsSecretKey); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	if !oidcIssuer(settings.OIDCIssuerURL) || settings.OIDCClientID == "" {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "OpenID sign-in is unavailable")
	}
	provider, err := oidc.NewProvider(ctx, settings.OIDCIssuerURL)
	if err != nil {
		log.Print("[ERROR]: could not instantiate OIDC provider")
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not instantiate OIDC provider")
	}

	if !oidcHTTPS(provider.Endpoint().AuthURL) || !oidcHTTPS(provider.Endpoint().TokenURL) || !oidcHTTPS(provider.UserInfoEndpoint()) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "OpenID provider endpoints must use HTTPS")
	}

	oauth2Config := oauth2.Config{
		ClientID:    settings.OIDCClientID,
		RedirectURL: h.GetRedirectURI(c),
		Endpoint:    provider.Endpoint(),
	}

	authProvider := settings.OIDCProvider
	cookieEncryptionKey := settings.OIDCCookieEncriptionKey

	if h.EncryptionMasterKey != "" {
		isKeyEncrypted, err := utils.IsSensitiveFieldEncrypted(cookieEncryptionKey, h.EncryptionMasterKey)
		if err != nil {
			return err
		}

		if isKeyEncrypted {
			cookieEncryptionKey, err = utils.DecryptSensitiveField(cookieEncryptionKey, h.EncryptionMasterKey)
			if err != nil {
				return err
			}
		}
	}

	oauth2Config.Scopes = []string{"openid", "profile", "email"}
	switch authProvider {
	case auth.AUTHELIA:
		oauth2Config.Scopes = append(oauth2Config.Scopes, "groups")
	case auth.ZITADEL:
		oauth2Config.Scopes = append(oauth2Config.Scopes, "phone", "urn:zitadel:iam:org:project:id:zitadel:aud")
	}

	state, err := randomBytestoHex(32)
	if err != nil {
		log.Printf("[ERROR]: we could not generate random OIDC state, reason: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not generate random OIDC state")
	}

	verifier := oauth2.GenerateVerifier()
	codeChallenge := oauth2.S256ChallengeOption(verifier)
	codeChallengeMethod := oauth2.SetAuthURLParam("code_challenge_method", "S256")

	nonce, err := randomBytestoHex(32)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not start OpenID sign-in")
	}
	flow := oidcFlow{Policy: oidcPolicy(settings), State: state, Verifier: verifier, Nonce: nonce, Issuer: settings.OIDCIssuerURL, ClientID: settings.OIDCClientID, Redirect: h.GetRedirectURI(c), Expires: time.Now().Add(10 * time.Minute).Unix()}
	payload, err := json.Marshal(flow)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not start OpenID sign-in")
	}
	if err := h.WriteOIDCCookie(c, oidcFlowCookie, string(payload), cookieEncryptionKey); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not start OpenID sign-in")
	}
	u := oauth2Config.AuthCodeURL(state, codeChallenge, codeChallengeMethod, oidc.Nonce(nonce))

	return c.Redirect(http.StatusFound, u)
}

func (h *Handler) OIDCCallback(c echo.Context) error {
	ctx, cancel := h.oidcContext(c.Request().Context())
	defer cancel()
	c.SetRequest(c.Request().WithContext(ctx))
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")

	clearOIDCFlow(c)

	settings, err := h.Model.GetAuthenticationSettings()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.could_not_get_settings"))
	}

	if !settings.UseOIDC {
		return echo.NewHTTPError(http.StatusForbidden, "OpenID sign-in is disabled")
	}
	if !oidcIssuer(settings.OIDCIssuerURL) || settings.OIDCClientID == "" {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "OpenID sign-in is unavailable")
	}

	if len(c.Request().URL.RawQuery) > 8192 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid OpenID response")
	}
	query, err := url.ParseQuery(c.Request().URL.RawQuery)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid OpenID response")
	}
	for _, key := range []string{"state", "code", "error", "iss"} {
		if len(query[key]) > 1 {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid OpenID response")
		}
	}
	code, state := query.Get("code"), query.Get("state")
	if query.Get("error") != "" || code == "" || len(code) > 4096 || len(state) != 64 || (query.Get("iss") != "" && query.Get("iss") != settings.OIDCIssuerURL) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid OpenID response; start sign-in again")
	}

	cookieEncryptionKey := settings.OIDCCookieEncriptionKey

	if h.EncryptionMasterKey != "" {
		isKeyEncrypted, err := utils.IsSensitiveFieldEncrypted(cookieEncryptionKey, h.EncryptionMasterKey)
		if err != nil {
			return err
		}

		if isKeyEncrypted {
			cookieEncryptionKey, err = utils.DecryptSensitiveField(cookieEncryptionKey, h.EncryptionMasterKey)
			if err != nil {
				return err
			}
		}
	}

	payload, err := ReadOIDCCookie(c, oidcFlowCookie, cookieEncryptionKey)
	var flow oidcFlow
	if err != nil || json.Unmarshal([]byte(payload), &flow) != nil || !flow.valid(settings, h.GetRedirectURI(c), state, time.Now()) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid OpenID sign-in; start again")
	}

	provider, err := oidc.NewProvider(ctx, settings.OIDCIssuerURL)
	if err != nil {
		log.Print("[ERROR]: could not instantiate OIDC provider")
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not instantiate OIDC provider")
	}

	if !oidcHTTPS(provider.Endpoint().AuthURL) || !oidcHTTPS(provider.Endpoint().TokenURL) || !oidcHTTPS(provider.UserInfoEndpoint()) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "OpenID provider endpoints must use HTTPS")
	}

	// Get access token in exchange of code
	oAuth2TokenResponse, err := h.ExchangeCodeForAccessToken(c, code, flow.Verifier, provider.Endpoint().TokenURL, settings.OIDCClientID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not exchange OIDC code for token")
	}

	idToken, err := verifyOIDCIdentity(ctx, provider, oAuth2TokenResponse, flow)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "OpenID identity verification failed")
	}

	authProvider := settings.OIDCProvider

	// Get user account info from remote endpoint
	u, err := GetUserInfo(ctx, oAuth2TokenResponse.AccessToken, provider.UserInfoEndpoint())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not get user info from OIDC endpoint")
	}

	if u.Subject != idToken.Subject || u.PreferredUsername == "" || len(u.PreferredUsername) > 255 || strings.IndexFunc(u.PreferredUsername, unicode.IsControl) >= 0 {
		return echo.NewHTTPError(http.StatusUnauthorized, "OpenID identity verification failed")
	}

	// Get user information
	oidcUser := OIDCSessionInfo{
		Issuer: idToken.Issuer, Subject: idToken.Subject, Policy: flow.Policy,
		ID:            u.PreferredUsername,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Phone:         u.Phone,
	}

	// Check if user is member of specified group or role
	if authProvider == auth.ZITADEL {
		if settings.OIDCRole != "" {
			// Get roles info from remote endpoint
			data, err := h.ZitadelGetUserRoles(ctx, oAuth2TokenResponse.AccessToken, settings)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "could not get roles from permissions endpoint")
			}

			if !slices.Contains(data.Roles, settings.OIDCRole) {
				return echo.NewHTTPError(http.StatusUnauthorized, "user has no permission to log in to OpenUEM")
			}
		}
	} else {

		if settings.OIDCRole != "" {
			if !slices.Contains(u.Groups, settings.OIDCRole) {
				return echo.NewHTTPError(http.StatusUnauthorized, "user has no permission to log in to OpenUEM")
			}
		}
	}

	// Manage session
	return h.ManageOIDCSession(c, &oidcUser)
}

// Reference: https://chrisguitarguy.com/2022/12/07/oauth-pkce-with-go/
func randomBytestoHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

func (h *Handler) WriteOIDCCookie(c echo.Context, name string, value string, secretKey string) error {
	expiry := time.Now().Add(10 * time.Minute)

	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiry,
		MaxAge:   int(time.Until(expiry).Seconds() + 1),
	}

	// Reference: https://www.alexedwards.net/blog/working-with-cookies-in-go#encrypted-cookies

	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Printf("[ERROR]: we could not create AES cipher block, reason: %v", err)
		return err
	}

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR]: we could not wrap AES cipher block, reason: %v", err)
		return err
	}

	// Create a unique nonce containing 12 random bytes.
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		log.Printf("[ERROR]: we could not create nonce, reason: %v", err)
		return err
	}

	// Prepare the plaintext input for encryption
	plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)

	// Encrypt the data using aesGCM.Seal()
	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Set the cookie value to the encryptedValue.
	cookie.Value = base64.StdEncoding.EncodeToString(encryptedValue)

	c.SetCookie(cookie)

	return nil
}

func ReadOIDCCookie(c echo.Context, name string, secretKey string) (string, error) {
	// Reference: https://www.alexedwards.net/blog/working-with-cookies-in-go#encrypted-cookies

	count := 0
	for _, cookie := range c.Request().Cookies() {
		if cookie.Name == name {
			count++
		}
	}
	if count != 1 {
		return "", errors.New("invalid OIDC cookie")
	}

	// Read the encrypted value from the cookie as normal.
	cookie, err := c.Request().Cookie(name)
	if err != nil {
		log.Printf("[ERROR]: we could not read the cookie, reason: %v", err)
		return "", err
	}

	if len(cookie.Value) > 4096 {
		return "", errors.New("invalid OIDC cookie")
	}

	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Printf("[ERROR]: we could not create the cipher block, reason: %v", err)
		return "", err
	}

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR]: we could not wrap the cipher block, reason: %v", err)
		return "", err
	}

	// Get the nonce size.
	nonceSize := aesGCM.NonceSize()

	// Convert from base64
	enc, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		log.Printf("[ERROR]: could not base64 decode the value, reason: %v", err)
		return "", err
	}

	// To avoid a potential 'index out of range' panic in the next step, we
	// check that the length of the encrypted value is at least the nonce
	// size.
	if len(enc) < nonceSize {
		log.Printf("[ERROR]: invalid value in cookie, reason: %v", err)
		return "", errors.New("invalid value")
	}

	// Split apart the nonce from the actual encrypted data.
	nonce := enc[:nonceSize]
	ciphertext := enc[nonceSize:]

	// Use aesGCM.Open() to decrypt and authenticate the data. If this fails,
	// return a ErrInvalidValue error.
	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		log.Printf("[ERROR]: could not decrypt value in cookie, reason: %v", err)
		return "", errors.New("invalid value")
	}

	// The plaintext value is in the format "{cookie name}:{cookie value}". We
	// use strings.Cut() to split it on the first ":" character.
	expectedName, value, ok := strings.Cut(string(plaintext), ":")
	if !ok {
		log.Printf("[ERROR]: could not find the expected value, reason: %v", err)
		return "", errors.New("invalid value")
	}

	// Check that the cookie name is the expected one and hasn't been changed.
	if expectedName != name {
		log.Printf("[ERROR]: unexpected cookie name, reason: %v", err)
		return "", errors.New("invalid value")
	}

	return value, nil
}

func (h *Handler) CreateSession(c echo.Context, user *ent.User) error {
	msg := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if msg != user.ID {
		err := h.SessionManager.Manager.RenewToken(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		h.SessionManager.Manager.Put(c.Request().Context(), "uid", user.ID)
		h.SessionManager.Manager.Put(c.Request().Context(), "username", user.Name)
		h.SessionManager.Manager.Put(c.Request().Context(), "user-agent", c.Request().UserAgent())
		h.SessionManager.Manager.Put(c.Request().Context(), "ip-address", c.Request().RemoteAddr)
		h.SessionManager.Manager.Put(c.Request().Context(), "usepasswd", user.Passwd)
		h.SessionManager.Manager.Put(c.Request().Context(), "email", user.Email)
		token, expiry, err := h.SessionManager.Manager.Commit(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		h.SessionManager.Manager.WriteSessionCookie(c.Request().Context(), c.Response().Writer, token, expiry)

		if err := h.Model.AddUserToSession(token, user.ID, h.EncryptionMasterKey); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// if it's the first time let's confirm login
		if err := h.Model.ConfirmLogIn(user.ID); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	return nil
}

func (h *Handler) GetRedirectURI(c echo.Context) string {
	return h.consoleOrigin() + "/oidc/callback"
}

func (h *Handler) ManageOIDCSession(c echo.Context, u *OIDCSessionInfo) error {
	settings, err := h.Model.GetAuthenticationSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "authentication.could_not_get_settings", err.Error()), true))
	}

	if !settings.UseOIDC || u.Issuer != settings.OIDCIssuerURL || u.Subject == "" || u.Policy != oidcPolicy(settings) {
		return echo.NewHTTPError(http.StatusUnauthorized, "OpenID configuration changed; start sign-in again")
	}

	// Check if user exists
	userExists, err := h.Model.UserExists(u.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.cannot_check_if_user_exists"))
	}

	// If user doesn't exist create user in database if auto creation is enabled
	if !userExists {
		if settings.OIDCAutoCreateAccount {
			if err := h.Model.AddOIDCUser(u.ID, u.Name, u.Email, u.Phone, u.EmailVerified, settings.OIDCAutoApprove); err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.cannot_create_oidc_user", err.Error()))
			}
		} else {
			return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "authentication.an_admin_must_create_your_account"))
		}
	}

	// If user exists, check if account is in a valid state
	account, err := h.Model.GetUserById(u.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "cannot get user from database")
	}

	if !account.Openid || account.Register == nats.REGISTER_REVOKED {
		return echo.NewHTTPError(http.StatusUnauthorized, "This account cannot use OpenID sign-in")
	}

	// If user has been approved by admin, auto approve is on or user already logged in (register completed)
	if account.Register == nats.REGISTER_APPROVED || settings.OIDCAutoApprove || account.Register == nats.REGISTER_COMPLETE {
		if err := h.CreateSession(c, account); err != nil {
			log.Printf("[ERROR]: could not create session, reason: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "could not create session")
		}

		if h.AuthLogger != nil {
			h.AuthLogger.Printf("user %s has logged in with OpenID (%s)", u.ID, settings.OIDCProvider)
		}

		myTenant, err := h.Model.GetDefaultTenant()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		mySite, err := h.Model.GetDefaultSite(myTenant)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if h.PublicOrigin != "" {
			return c.Redirect(http.StatusFound, fmt.Sprintf("%s/tenant/%d/site/%d/dashboard", h.PublicOrigin, myTenant.ID, mySite.ID))
		}
		if h.ReverseProxyServer != "" {
			return c.Redirect(http.StatusSeeOther, "/devices")
		} else {
			return c.Redirect(http.StatusFound, fmt.Sprintf("https://%s:%s/tenant/%d/site/%d/dashboard", h.ServerName, h.ConsolePort, myTenant.ID, mySite.ID))
		}
	}

	return echo.NewHTTPError(http.StatusForbidden, "An admin must approve your account")
}

func (h *Handler) ExchangeCodeForAccessToken(c echo.Context, code string, verifier string, endpoint string, clientID string) (*OAuth2TokenResponse, error) {
	var z OAuth2TokenResponse

	v := url.Values{}

	url := endpoint
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	v.Set("redirect_uri", h.GetRedirectURI(c))
	v.Set("client_id", clientID)
	v.Set("code_verifier", verifier)

	if err := oidcJSON(c.Request().Context(), http.MethodPost, url, "", v, &z); err != nil || z.Error != "" {
		return nil, errOIDCResponse
	}
	return &z, nil
}

func GetUserInfo(ctx context.Context, accessToken string, endpoint string) (*UserInfoResponse, error) {
	var user UserInfoResponse
	if err := oidcJSON(ctx, http.MethodGet, endpoint, accessToken, nil, &user); err != nil || user.Error != "" {
		return nil, errOIDCResponse
	}
	return &user, nil
}

func (h *Handler) ZitadelGetUserRoles(ctx context.Context, accessToken string, settings *ent.Authentication) (*ZitadelRolesResponse, error) {
	var roles ZitadelRolesResponse
	endpoint := strings.TrimRight(settings.OIDCIssuerURL, "/") + "/auth/v1/permissions/me/_search"
	if err := oidcJSON(ctx, http.MethodPost, endpoint, accessToken, nil, &roles); err != nil || roles.Message != "" {
		return nil, errOIDCResponse
	}
	return &roles, nil
}
