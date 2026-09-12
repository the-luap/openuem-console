package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func desktopPeripheralsFilter(raw string, fixed inventory.PeripheralsKind) (inventory.PeripheralsFilter, error) {
	filter := inventory.PeripheralsFilter{Kind: inventory.MonitorReports}
	if len(raw) > 4096 {
		return filter, inventory.ErrPeripheralsFilter
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return filter, inventory.ErrPeripheralsFilter
	}
	if kinds, present := query["kind"]; present {
		if len(kinds) != 1 {
			return filter, inventory.ErrPeripheralsFilter
		}
		filter.Kind = inventory.PeripheralsKind(kinds[0])
	}
	// Legacy GET aliases select a fixed report kind; conflicting query values
	// cannot silently display another inventory than their path names.
	if fixed != "" {
		if _, present := query["kind"]; present && filter.Kind != fixed {
			return filter, inventory.ErrPeripheralsFilter
		}
		filter.Kind = fixed
	}
	query.Del("kind")
	filter.ReportFilter, err = desktopReportFilter(query.Encode())
	if err != nil || !filter.Valid() {
		return filter, inventory.ErrPeripheralsFilter
	}
	return filter, nil
}

func (h *Handler) DesktopPeripherals(c echo.Context) error {
	return h.desktopPeripherals(c, "")
}

func (h *Handler) desktopPeripherals(c echo.Context, fixed inventory.PeripheralsKind) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopPeripheralsFilter(c.Request().URL.RawQuery, fixed)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "peripherals_inventory.invalid_filter"))
	}
	page, err := inventory.ReadPeripherals(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID,
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"), filter)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, i18n.T(c.Request().Context(), "peripherals_inventory.not_found"))
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "peripherals_inventory.denied"))
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "peripherals_inventory.unavailable"))
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, desktop_views.Peripherals(c, info, page, filter))
}
