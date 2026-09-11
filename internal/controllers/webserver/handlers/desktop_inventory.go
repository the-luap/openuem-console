package handlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
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
	refresh := desktop_views.RefreshData{}
	if h.InventoryRefresh != nil {
		refresh.Request, err = h.InventoryRefresh.Latest(c.Request().Context(), info.Principal.UserID, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, d.ID)
		if err != nil {
			return desktopRefreshFailure(err)
		}
		refresh.NewID = uuid.NewString()
		refresh.Available = inventory.ValidReportDeviceID(d.ID) && (d.Status == "Enabled" || d.Status == "No contact")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, desktop_views.InventoryWithRefresh(c, info, d, refresh))
}
