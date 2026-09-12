package handlers

import (
	"crypto/subtle"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func deviceExportForm(c echo.Context) (url.Values, error) {
	return deviceManagementForm(c, "mdm.devices.export_invalid", []string{"csrf", "format", "q", "platform", "sort"})
}

func deviceManagementForm(c echo.Context, errorKey string, allowed []string) (url.Values, error) {
	failure := func(status int) (url.Values, error) {
		return nil, echo.NewHTTPError(status, i18n.T(c.Request().Context(), errorKey))
	}
	r := c.Request()
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" {
		return failure(http.StatusUnsupportedMediaType)
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return failure(http.StatusBadRequest)
	}
	if r.ContentLength > 8192 {
		return failure(http.StatusRequestEntityTooLarge)
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 8192)
	if err = r.ParseForm(); err != nil {
		return failure(http.StatusBadRequest)
	}
	f := r.PostForm
	if len(f.Encode()) > 8192 {
		return failure(http.StatusRequestEntityTooLarge)
	}
	for key, values := range f {
		known := false
		for _, field := range allowed {
			if key == field {
				known = true
				break
			}
		}
		if len(values) != 1 || !known {
			return failure(http.StatusBadRequest)
		}
	}
	expected, _ := c.Get("csrf").(string)
	if len(f["csrf"]) != 1 || expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(f.Get("csrf"))) != 1 {
		return failure(http.StatusForbidden)
	}
	return f, nil
}

func (h *Handler) ExportDeviceInventory(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("X-Content-Type-Options", "nosniff")
	if c.Request().Method != http.MethodPost {
		c.Response().Header().Set("Allow", http.MethodPost)
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	_, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	f, err := deviceExportForm(c)
	if err != nil {
		return err
	}
	format := f.Get("format")
	data, err := inventory.ExportDevices(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c),
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, inventory.DeviceSources{Apple: h.Apple != nil, Windows: h.Windows != nil},
		inventory.DeviceFilter{Platform: f.Get("platform"), Search: f.Get("q"), Sort: f.Get("sort")}, format)
	if err != nil {
		status, key := http.StatusServiceUnavailable, "export_unavailable"
		switch {
		case errors.Is(err, inventory.ErrReportFilter):
			status, key = http.StatusBadRequest, "export_invalid"
		case errors.Is(err, inventory.ErrDeviceExportTooLarge):
			status, key = http.StatusUnprocessableEntity, "export_large"
		case errors.Is(err, inventory.ErrDeviceExportBusy):
			status, key = http.StatusTooManyRequests, "export_busy"
		case errors.Is(err, access.ErrDenied):
			status, key = http.StatusForbidden, "permission_denied"
		}
		return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "mdm.devices."+key))
	}
	contentType := "application/json; charset=utf-8"
	if format == "csv" {
		contentType = "text/csv; charset=utf-8"
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="openuem-devices-`+time.Now().UTC().Format("20060102T150405Z")+`.`+format+`"`)
	return c.Blob(http.StatusOK, contentType, data)
}
