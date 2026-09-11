package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
	"github.com/open-uem/openuem-console/internal/views/access_views"
)

func oidcAccountFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Server administrator required")
	case errors.Is(err, sql.ErrNoRows):
		return echo.NewHTTPError(404, "Account not found")
	case errors.Is(err, oidcaccounts.ErrConflict):
		return echo.NewHTTPError(409, "The account, identity or provider changed. Reload before saving.")
	case errors.Is(err, oidcaccounts.ErrIdentity):
		return echo.NewHTTPError(400, "Select an eligible OpenID account and the exact provider subject.")
	default:
		return echo.NewHTTPError(503, "OpenID account registration is unavailable")
	}
}

func (h *Handler) OIDCAccountBindings(c echo.Context) error {
	actor, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	if !actor.IsAdministrator() {
		return echo.NewHTTPError(403, "Server administrator required")
	}
	if h.OIDCAccounts == nil {
		return oidcAccountFailure(errors.New("unavailable"))
	}
	uid := c.QueryParam("user_id")
	if uid == "" {
		uid = actor.UserID
	}
	if len(uid) > 255 || len(c.QueryParams()["user_id"]) > 1 {
		return echo.NewHTTPError(400, "Invalid account selection")
	}
	page, err := h.OIDCAccounts.Page(c.Request().Context(), actor.UserID, uid)
	if err != nil {
		return oidcAccountFailure(err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, access_views.OIDCAccount(c, info, page))
}

func (h *Handler) ChangeOIDCAccountBinding(c echo.Context) error {
	actor, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	if !actor.IsAdministrator() {
		return echo.NewHTTPError(403, "Server administrator required")
	}
	if h.OIDCAccounts == nil {
		return oidcAccountFailure(errors.New("unavailable"))
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 8192)
	if c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery || c.Request().ParseForm() != nil {
		return echo.NewHTTPError(400, "Invalid OpenID identity form")
	}
	f := c.Request().PostForm
	allowed := map[string]bool{"csrf": true, "confirmed": true, "user_id": true, "issuer": true, "client_id": true, "subject": true, "action": true, "revision": true}
	for key, values := range f {
		if !allowed[key] || len(values) != 1 {
			return echo.NewHTTPError(400, "Ambiguous OpenID identity form")
		}
	}
	if f.Get("confirmed") != "yes" || len(f["csrf"]) != 1 || f.Get("user_id") == "" || len(f.Get("user_id")) > 255 {
		return echo.NewHTTPError(400, "Confirm the identity change for this account")
	}
	revision, err := strconv.ParseInt(f.Get("revision"), 10, 64)
	if err != nil || revision < 0 {
		return echo.NewHTTPError(400, "Invalid account revision")
	}
	if f.Get("action") == "disable" && f.Get("user_id") == actor.UserID {
		return echo.NewHTTPError(400, "Another server administrator must disable your sign-in identity")
	}
	err = h.OIDCAccounts.Change(c.Request().Context(), actor.UserID, f.Get("user_id"), f.Get("issuer"), f.Get("client_id"), f.Get("subject"), f.Get("action"), revision)
	if err != nil {
		return oidcAccountFailure(err)
	}
	return c.Redirect(http.StatusSeeOther, "/admin/oidc-accounts?user_id="+url.QueryEscape(f.Get("user_id")))
}
