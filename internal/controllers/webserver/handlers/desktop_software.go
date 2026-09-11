package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func desktopSoftwareFilter(raw string) (inventory.SoftwareFilter, error) {
	var filter inventory.SoftwareFilter
	if len(raw) > 4096 {
		return filter, inventory.ErrSoftwareFilter
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return filter, inventory.ErrSoftwareFilter
	}
	for key, values := range query {
		if len(values) != 1 || key != "q" && key != "after" {
			return filter, inventory.ErrSoftwareFilter
		}
	}
	filter.Search = query.Get("q")
	if cursor, present := query["after"]; present {
		filter.After, err = strconv.ParseInt(cursor[0], 10, 64)
		if err != nil || filter.After <= 0 || strconv.FormatInt(filter.After, 10) != cursor[0] {
			return filter, inventory.ErrSoftwareFilter
		}
	}
	if !filter.Valid() {
		return filter, inventory.ErrSoftwareFilter
	}
	return filter, nil
}

func (h *Handler) DesktopSoftware(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopSoftwareFilter(c.Request().URL.RawQuery)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid software search or page. Open the first page and try again.")
	}
	page, err := inventory.ReadSoftware(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID,
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"), filter)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "Computer not found")
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, "Permission denied for this organization or site")
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Software inventory is unavailable. Try again later.")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, desktop_views.Software(c, info, page, filter))
}
