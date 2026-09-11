package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func (h *Handler) DesktopInventory(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusForbidden, "This action requires a server administrator")
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	d, err := inventory.ReadDesktop(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID,
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"))
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "Computer not found")
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, "Permission denied for this organization or site")
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Computer inventory is unavailable. Try again later.")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, desktop_views.Inventory(c, info, d))
}
