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

func (h *Handler) DesktopDetails(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, selected, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	if c.Request().URL.RawQuery != "" {
		return echo.NewHTTPError(400, i18n.T(ctx, "device_details.invalid"))
	}
	scope := access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}
	id := c.Param("uuid")
	var data *inventory.DeviceDetails
	var draft inventory.DeviceDetailValues
	message, status := "", http.StatusOK
	if c.Request().Method == http.MethodPost {
		if c.Request().ParseForm() != nil {
			return echo.NewHTTPError(400, i18n.T(ctx, "device_details.invalid"))
		}
		form := c.Request().PostForm
		for key, values := range form {
			if len(values) != 1 || key != "csrf" && key != "revision" && key != "nickname" && key != "description" && key != "endpoint_type" {
				return echo.NewHTTPError(400, i18n.T(ctx, "device_details.invalid"))
			}
		}
		for _, key := range []string{"revision", "nickname", "description", "endpoint_type"} {
			if len(form[key]) != 1 {
				return echo.NewHTTPError(400, i18n.T(ctx, "device_details.invalid"))
			}
		}
		draft = inventory.DeviceDetailValues{Nickname: form.Get("nickname"), Description: form.Get("description"), EndpointType: form.Get("endpoint_type")}
		data, err = inventory.UpdateDeviceDetails(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id, form.Get("revision"), draft)
		if errors.Is(err, inventory.ErrDeviceDetailsConflict) {
			data, err = inventory.ReadDeviceDetails(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id)
			message, status = i18n.T(ctx, "device_details.conflict"), http.StatusConflict
		} else if err == nil {
			return c.Redirect(http.StatusSeeOther, partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(id)+"/details"))
		}
	} else {
		data, err = inventory.ReadDeviceDetails(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id)
		if err == nil {
			draft = data.Values
		}
	}
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, i18n.T(ctx, "device_details.denied"))
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(404, i18n.T(ctx, "device_details.not_found"))
	case errors.Is(err, inventory.ErrDeviceDetailsInvalid):
		return echo.NewHTTPError(400, i18n.T(ctx, "device_details.invalid"))
	case err != nil:
		return echo.NewHTTPError(503, i18n.T(ctx, "device_details.unavailable"))
	}
	c.Response().Status = status
	return renderApple(c, desktop_views.Details(c, info, data, draft, message))
}
