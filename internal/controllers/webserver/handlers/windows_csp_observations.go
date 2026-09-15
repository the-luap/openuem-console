package handlers

import (
	"net/url"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func (h *Handler) WindowsCSPObservations(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	query, queryErr := url.ParseQuery(c.Request().URL.RawQuery)
	if queryErr != nil || c.Request().URL.ForceQuery || len(query) > 1 || len(query) == 1 && (!query.Has("offset") || len(query["offset"]) != 1 || query.Get("offset") == "") {
		return echo.NewHTTPError(400, "Invalid observation page")
	}
	offset, err := windowsOffset(c, "offset")
	if err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsCSPFailure(err)
	}
	history, err := h.Windows.CSPObservations(c.Request().Context(), h.appleActor(c), scope, device.ID, c.Param("command"), offset, 11)
	if err != nil {
		return windowsCSPFailure(err)
	}
	more := len(history.Observations) > 10
	if more {
		history.Observations = history.Observations[:10]
	}
	return renderApple(c, windows_views.CSPObservations(c, info, *device, *history, offset, more))
}

func (h *Handler) WindowsCSPObservation(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	message, err := strconv.Atoi(c.Param("message"))
	if err != nil || strconv.Itoa(message) != c.Param("message") || c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery {
		return echo.NewHTTPError(400, "Invalid observation identifier")
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsCSPFailure(err)
	}
	history, err := h.Windows.CSPObservationDetails(c.Request().Context(), h.appleActor(c), scope, device.ID, c.Param("command"), message)
	if err != nil {
		return windowsCSPFailure(err)
	}
	return renderApple(c, windows_views.CSPObservation(c, info, *device, history.Command, history.Observations[0]))
}
