package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func (h *Handler) DesktopNetwork(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopReportFilter(c.Request().URL.RawQuery)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid network search or page. Open the first page and try again.")
	}
	page, err := inventory.ReadNetwork(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID,
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"), filter)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "Computer not found")
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, "Permission denied for this organization or site")
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Network inventory is unavailable. Try again later.")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, desktop_views.Network(c, info, page, filter))
}
