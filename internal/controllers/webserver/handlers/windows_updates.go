package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func (h *Handler) WindowsUpdateRuns(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	offset, err := windowsOffset(c, "offset")
	if err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsFailure(err)
	}
	runs, err := h.Windows.UpdateRuns(c.Request().Context(), h.appleActor(c), scope, device.ID, offset, 26)
	if err != nil {
		return windowsFailure(err)
	}
	more := len(runs) > 25
	if more {
		runs = runs[:25]
	}
	return renderApple(c, windows_views.UpdateRuns(c, info, *device, runs, offset, more))
}

func (h *Handler) WindowsUpdateRun(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsFailure(err)
	}
	detail, err := h.Windows.UpdateRunDetails(c.Request().Context(), h.appleActor(c), scope, device.ID, c.Param("run"))
	if err != nil {
		return windowsFailure(err)
	}
	return renderApple(c, windows_views.UpdateRun(c, info, *device, *detail))
}

func (h *Handler) WindowsCancelUpdateRun(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	form, err := windowsForm(c, "confirm_cancel")
	if err != nil {
		return err
	}
	if form.Get("confirm_cancel") != "yes" {
		return echo.NewHTTPError(400, "Confirm cancellation of the remaining undelivered steps")
	}
	if err := h.Windows.CancelUpdateRun(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), c.Param("run")); err != nil {
		return windowsFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+c.Param("id")+"/updates/"+c.Param("run"))
}
