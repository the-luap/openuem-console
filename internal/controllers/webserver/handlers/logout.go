package handlers

import (
	"net/http"
	"net/url"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/auth"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) Logout(c echo.Context) error {
	settings, err := h.Model.GetAuthenticationSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "authentication.could_not_get_settings", err.Error()), true))
	}

	uid, ok := h.SessionManager.Manager.Get(c.Request().Context(), "uid").(string)
	if !ok || len(uid) == 0 {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "authentication.could_not_get_user_id"), true))
	}

	u, err := h.Model.GetUserById(uid)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "authentication.could_not_get_user_info", err.Error()), true))
	}

	if err := h.SessionManager.Manager.Destroy(c.Request().Context()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if h.AuthLogger != nil {
		h.AuthLogger.Printf("user %s has logged out from the console", u.ID)
	}

	if u.Openid {
		c.Response().Header().Set("HX-Redirect", h.oidcLogoutURL(settings))
		return c.String(http.StatusFound, "")
	}

	return h.Login(c)
}

// Logout destinations use trusted configuration only. URL construction keeps
// issuer path prefixes and escapes the client ID and return URL independently.
func (h *Handler) oidcLogoutURL(settings *ent.Authentication) string {
	origin := h.consoleOrigin()
	if settings == nil || !oidcIssuer(settings.OIDCIssuerURL) {
		return origin
	}
	issuer, _ := url.Parse(settings.OIDCIssuerURL)
	query := url.Values{}
	var endpoint string
	switch settings.OIDCProvider {
	case auth.AUTHELIA:
		endpoint = "logout"
		query.Set("rd", origin)
	case auth.AUTHENTIK:
		endpoint = "end-session/"
	case auth.KEYCLOAK:
		endpoint = "protocol/openid-connect/logout"
		query.Set("client_id", settings.OIDCClientID)
		query.Set("post_logout_redirect_uri", origin)
	case auth.ZITADEL:
		endpoint = "oidc/v1/end_session"
		query.Set("client_id", settings.OIDCClientID)
		query.Set("post_logout_redirect_uri", origin)
	default:
		return origin
	}
	target := issuer.JoinPath(endpoint)
	target.RawQuery = query.Encode()
	return target.String()
}
