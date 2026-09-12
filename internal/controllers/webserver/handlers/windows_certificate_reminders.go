package handlers

import (
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func (h *Handler) WindowsCertificateReminders(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	q, err := url.ParseQuery(c.Request().URL.RawQuery)
	if err != nil || c.Request().URL.ForceQuery || len(q) > 1 || (len(q) == 1 && (!q.Has("offset") || len(q["offset"]) != 1 || q.Get("offset") == "")) {
		return echo.NewHTTPError(400, "Invalid certificate reminder history page")
	}
	offset, err := windowsOffset(c, "offset")
	if err != nil {
		return err
	}
	history, err := h.Windows.CertificateReminders(c.Request().Context(), h.appleActor(c), scope, offset, 26)
	if err != nil {
		return windowsFailure(err)
	}
	more := len(history) > 25
	if more {
		history = history[:25]
	}
	return renderApple(c, windows_views.CertificateReminders(c, info, history, offset, more))
}
