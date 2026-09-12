package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
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

func (h *Handler) parseEmailConfirmationToken(encoded string) (*jwt.RegisteredClaims, error) {
	if h.JWTKey == "" || encoded == "" || len(encoded) > 8192 {
		return nil, errEmailConfirmationToken
	}
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(encoded, claims, func(*jwt.Token) (any, error) {
		return []byte(h.JWTKey), nil
	}, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired(),
		jwt.WithIssuer("OpenUEM"), jwt.WithSubject(emailConfirmationSubject), jwt.WithIssuedAt())
	if err != nil || !token.Valid || claims.ID == "" || claims.IssuedAt == nil ||
		claims.ExpiresAt == nil || !time.Now().Before(claims.ExpiresAt.Time) ||
		!claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 24*time.Hour {
		return nil, errEmailConfirmationToken
	}
	return claims, nil
}

func (h *Handler) ConfirmEmail(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
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
	turnstileSiteKey, turnstileSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return unavailable(err)
	}
	ctx, cancel := context.WithDeadline(c.Request().Context(), claims.ExpiresAt.Time)
	defer cancel()
	if err := h.Model.ConfirmEmail(ctx, claims.ID); err != nil {
		if errors.Is(err, models.ErrEmailConfirmationState) {
			return invalid()
		}
		return unavailable(err)
	}
	return RenderView(c, register_views.RegisterIndex(register_views.EmailConfirmed(), csrfToken, turnstileSecretKey != "" && turnstileSiteKey != ""))
}
