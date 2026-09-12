package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/views/register_views"
)

type MyCustomClaims struct {
	jwt.RegisteredClaims
}

func (h *Handler) Auth(c echo.Context) error {
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

	if h.PublicOrigin != "" {
		return c.Redirect(http.StatusFound, h.PublicOrigin+"/auth")
	}
	if h.ReverseProxyServer != "" && h.ReverseProxyAuthPort != "" {
		return c.Redirect(http.StatusFound, fmt.Sprintf("https://%s:%s/auth", h.ReverseProxyServer, h.ReverseProxyAuthPort))
	} else {
		return c.Redirect(http.StatusFound, fmt.Sprintf("https://%s:%s/auth", h.ServerName, h.AuthPort))
	}

}

const emailConfirmationSubject = "Email Confirmation"

var errEmailConfirmationToken = errors.New("invalid email confirmation token")

type emailConfirmationClaims struct {
	jwt.RegisteredClaims
	AccountBinding string `json:"account_binding"`
}

func (h *Handler) generateConfirmationToken(account *ent.User) (string, error) {
	// Use a stored snapshot so the binding retains database timestamp precision.
	claims := emailConfirmationClaims{
		RegisteredClaims: emailTokenClaims(account.ID, emailConfirmationSubject, 24),
		AccountBinding:   models.EmailConfirmationBinding(account),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString([]byte(h.JWTKey))
}

func (h *Handler) parseEmailConfirmationToken(encoded string) (*emailConfirmationClaims, error) {
	if h.JWTKey == "" || encoded == "" || len(encoded) > 8192 {
		return nil, errEmailConfirmationToken
	}
	claims := &emailConfirmationClaims{}
	token, err := jwt.ParseWithClaims(encoded, claims, func(*jwt.Token) (any, error) {
		return []byte(h.JWTKey), nil
	}, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired(),
		jwt.WithIssuer("OpenUEM"), jwt.WithSubject(emailConfirmationSubject), jwt.WithIssuedAt())
	if err != nil || !token.Valid || claims.ID == "" || len(claims.AccountBinding) != 64 || claims.IssuedAt == nil ||
		claims.ExpiresAt == nil || !time.Now().Before(claims.ExpiresAt.Time) ||
		!claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 24*time.Hour {
		return nil, errEmailConfirmationToken
	}
	return claims, nil
}

func (h *Handler) ConfirmEmail(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodPost {
		c.Response().Header().Set("Allow", "GET, POST")
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	invalid := func() error {
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "authentication.email_confirmation_invalid"))
	}
	unavailable := func(err error) error {
		return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.email_confirmation_unavailable")).SetInternal(err)
	}
	claims, err := h.parseEmailConfirmationToken(c.Param("token"))
	if err != nil {
		return invalid()
	}
	csrfToken, ok := c.Get("csrf").(string)
	if !ok || csrfToken == "" {
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "authentication.csrf_token_not_found"))
	}
	if c.Request().Method == http.MethodPost {
		if err := emailConfirmationForm(c, csrfToken); err != nil {
			return err
		}
	}
	turnstileSiteKey, turnstileSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return unavailable(err)
	}
	ctx, cancel := context.WithDeadline(c.Request().Context(), claims.ExpiresAt.Time)
	defer cancel()
	account, err := h.Model.PendingEmailConfirmation(ctx, claims.ID)
	if ent.IsNotFound(err) {
		return invalid()
	}
	if err != nil {
		return unavailable(err)
	}
	if subtle.ConstantTimeCompare([]byte(models.EmailConfirmationBinding(account)), []byte(claims.AccountBinding)) != 1 {
		return invalid()
	}
	if c.Request().Method == http.MethodGet {
		action := "/auth/confirm/" + url.PathEscape(c.Param("token"))
		return RenderView(c, register_views.RegisterIndex(register_views.EmailConfirmation(account.Email, csrfToken, action), csrfToken, turnstileSecretKey != "" && turnstileSiteKey != ""))
	}
	if err := h.Model.ConfirmEmail(ctx, account); err != nil {
		if errors.Is(err, models.ErrEmailConfirmationState) {
			return invalid()
		}
		return unavailable(err)
	}
	return RenderView(c, register_views.RegisterIndex(register_views.EmailConfirmed(), csrfToken, turnstileSecretKey != "" && turnstileSiteKey != ""))
}

func emailConfirmationForm(c echo.Context, expected string) error {
	formError := func(status int, key string) error {
		return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "authentication.email_confirmation_"+key))
	}
	r := c.Request()
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" {
		return formError(http.StatusUnsupportedMediaType, "form_required")
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return formError(http.StatusBadRequest, "form_query")
	}
	const limit = 8192
	if r.ContentLength > limit {
		return formError(http.StatusRequestEntityTooLarge, "form_large")
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, limit)
	if err := r.ParseForm(); err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			return formError(http.StatusRequestEntityTooLarge, "form_large")
		}
		return formError(http.StatusBadRequest, "form_invalid")
	}
	if len(r.PostForm.Encode()) > limit {
		return formError(http.StatusRequestEntityTooLarge, "form_large")
	}
	if len(r.PostForm) != 1 || len(r.PostForm["csrf"]) != 1 || subtle.ConstantTimeCompare([]byte(expected), []byte(r.PostForm.Get("csrf"))) != 1 {
		return formError(http.StatusForbidden, "csrf")
	}
	return nil
}
