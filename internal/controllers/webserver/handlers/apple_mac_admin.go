package handlers

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"net/http"
)

func macAdminFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Administrator password permission denied")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(404, "Administrator record not found in this scope")
	case errors.Is(err, apple.ErrMacAdmin), errors.Is(err, apple.ErrConflict):
		return echo.NewHTTPError(409, "The administrator action is unavailable. Check enrollment, current account inventory and unresolved commands. Up to 128 passwords are retained per enrollment.")
	default:
		return echo.NewHTTPError(503, "Administrator management is temporarily unavailable")
	}
}
func (h *Handler) AppleMacAdmin(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "operation")
	if err != nil {
		return err
	}
	if err = h.Apple.RequestMacAdmin(c.Request().Context(), scope, id, f.Get("operation"), h.appleActor(c), h.Access); err != nil {
		return macAdminFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}
func (h *Handler) AppleMacAdminPassword(c echo.Context) error {
	header := c.Response().Header()
	header.Set("Cache-Control", "no-store, max-age=0")
	header.Set("Pragma", "no-cache")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	_, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	if _, err = adeEnrollmentForm(c); err != nil {
		return err
	}
	password, err := h.Apple.RevealMacAdminPassword(c.Request().Context(), scope, id, c.Param("key"), h.appleActor(c), h.Access)
	if err != nil {
		return macAdminFailure(err)
	}
	defer clear(password)
	return c.Blob(http.StatusOK, "text/plain; charset=utf-8", password)
}
