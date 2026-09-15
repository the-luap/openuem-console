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

func desktopStorageFilter(raw string, fixed inventory.StorageKind) (inventory.StorageFilter, error) {
	filter := inventory.StorageFilter{Kind: inventory.PhysicalStorage}
	if len(raw) > 4096 {
		return filter, inventory.ErrStorageFilter
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return filter, inventory.ErrStorageFilter
	}
	if kinds, present := query["kind"]; present {
		if len(kinds) != 1 {
			return filter, inventory.ErrStorageFilter
		}
		filter.Kind = inventory.StorageKind(kinds[0])
	}
	// Legacy GET aliases select a fixed report kind; conflicting query values
	// cannot silently display another inventory than their path names.
	if fixed != "" {
		if _, present := query["kind"]; present && filter.Kind != fixed {
			return filter, inventory.ErrStorageFilter
		}
		filter.Kind = fixed
	}
	query.Del("kind")
	filter.ReportFilter, err = desktopReportFilter(query.Encode())
	if err != nil || !filter.Valid() {
		return filter, inventory.ErrStorageFilter
	}
	return filter, nil
}

func (h *Handler) DesktopStorage(c echo.Context) error {
	return h.desktopStorage(c, "")
}

func (h *Handler) desktopStorage(c echo.Context, fixed inventory.StorageKind) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopStorageFilter(c.Request().URL.RawQuery, fixed)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "storage_inventory.invalid_filter"))
	}
	page, err := inventory.ReadStorage(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID,
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"), filter)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, i18n.T(c.Request().Context(), "storage_inventory.not_found"))
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "storage_inventory.denied"))
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "storage_inventory.unavailable"))
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, desktop_views.Storage(c, info, page, filter))
}
