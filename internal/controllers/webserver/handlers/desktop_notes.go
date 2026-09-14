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
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) Notes(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, selected, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	scope := access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}
	id := c.Param("uuid")
	var data *inventory.DeviceNotes
	var draft, message string
	status := http.StatusOK
	if c.Request().Method == http.MethodPost {
		if c.Request().URL.RawQuery != "" || c.Request().ParseForm() != nil {
			return echo.NewHTTPError(http.StatusBadRequest, i18n.T(ctx, "device_notes.invalid"))
		}
		form := c.Request().PostForm
		for key, values := range form {
			if len(values) != 1 || (key != "markdown" && key != "revision" && key != "csrf") {
				return echo.NewHTTPError(http.StatusBadRequest, i18n.T(ctx, "device_notes.invalid"))
			}
		}
		if len(form["markdown"]) != 1 || len(form["revision"]) != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, i18n.T(ctx, "device_notes.invalid"))
		}
		draft = form.Get("markdown")
		data, err = inventory.UpdateDeviceNotes(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id, form.Get("revision"), draft)
		if errors.Is(err, inventory.ErrDeviceNotesConflict) {
			// Reading the current private notes needs its own successful audit.
			data, err = inventory.ReadDeviceNotes(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id)
			status = http.StatusConflict
			message = i18n.T(ctx, "device_notes.conflict")
		} else if err == nil {
			return c.Redirect(http.StatusSeeOther, partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(id)+"/notes"))
		}
	} else {
		data, err = inventory.ReadDeviceNotes(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id)
		if err == nil {
			draft = data.Notes
		}
	}
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, i18n.T(ctx, "device_notes.not_found"))
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(ctx, "device_notes.denied"))
	case errors.Is(err, inventory.ErrDeviceNotesInvalid):
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(ctx, "device_notes.invalid"))
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(ctx, "device_notes.unavailable"))
	}
	c.Response().Status = status
	return renderApple(c, desktop_views.Notes(c, info, data, draft, message))
}
