package handlers

import (
	"errors"
	"net/http"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func (h *Handler) DesktopSecurity(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopReportFilter(c.Request().URL.RawQuery)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "security_inventory.invalid_filter"))
	}
	page, err := inventory.ReadSecurity(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID,
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"), filter)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, i18n.T(c.Request().Context(), "security_inventory.not_found"))
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "security_inventory.denied"))
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "security_inventory.unavailable"))
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, desktop_views.Security(c, info, page, filter))
}
