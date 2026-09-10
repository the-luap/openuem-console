package handlers

import (
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsUnenrollmentFailure(err error) error {
	if errors.Is(err, windows.ErrUnenrollmentRequest) {
		return echo.NewHTTPError(409, "This disconnection action conflicts with the device's current request. Review its history before trying again.")
	}
	return windowsCSPFailure(err)
}

func windowsUnenrollmentQuery(c echo.Context, history bool) error {
	query, err := url.ParseQuery(c.Request().URL.RawQuery)
	if err != nil || c.Request().URL.ForceQuery || !history && c.Request().URL.RawQuery != "" || history && (len(query) > 1 || len(query) == 1 && (!query.Has("offset") || len(query["offset"]) != 1 || query.Get("offset") == "")) {
		return echo.NewHTTPError(400, "Invalid disconnection page parameters")
	}
	return nil
}

func (h *Handler) WindowsUnenrollmentRequests(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err = h.windowsReady(); err != nil {
		return err
	}
	if err = windowsUnenrollmentQuery(c, true); err != nil {
		return err
	}
	offset, err := windowsOffset(c, "offset")
	if err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsUnenrollmentFailure(err)
	}
	history, err := h.Windows.UnenrollmentRequests(c.Request().Context(), h.appleActor(c), scope, device.ID, offset, 11)
	if err != nil {
		return windowsUnenrollmentFailure(err)
	}
	more := len(history) > 10
	if more {
		history = history[:10]
	}
	return renderApple(c, windows_views.UnenrollmentRequests(c, info, *device, history, offset, more))
}

func (h *Handler) WindowsUnenrollmentRequest(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err = h.windowsReady(); err != nil {
		return err
	}
	if err = windowsUnenrollmentQuery(c, false); err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsUnenrollmentFailure(err)
	}
	detail, err := h.Windows.UnenrollmentRequestDetails(c.Request().Context(), h.appleActor(c), scope, device.ID, c.Param("request"))
	if err != nil {
		return windowsUnenrollmentFailure(err)
	}
	return renderApple(c, windows_views.UnenrollmentRequest(c, info, *device, *detail))
}

func (h *Handler) WindowsNewUnenrollmentRequest(c echo.Context) error {
	if err := windowsUnenrollmentQuery(c, false); err != nil {
		return err
	}
	info, scope, device, err := h.windowsUpdateFormContext(c)
	if err != nil {
		return err
	}
	history, err := h.Windows.UnenrollmentRequests(c.Request().Context(), h.appleActor(c), scope, device.ID, 0, 1)
	if err != nil {
		return windowsUnenrollmentFailure(err)
	}
	if len(history) > 0 && windows_views.UnenrollmentRequestPending(history[0]) {
		return appleRedirect(c, info, "/windows/"+device.ID+"/disconnections/"+history[0].Command.ID)
	}
	form := url.Values{"request_key": {uuid.NewString()}, "hours": {"24"}}
	return renderApple(c, windows_views.UnenrollmentForm(c, info, *device, windows_views.UnenrollmentDraft{Form: form}))
}

func parseWindowsUnenrollmentDraft(form url.Values) (time.Duration, error) {
	id, err := uuid.Parse(form.Get("request_key"))
	if err != nil || id == uuid.Nil || id.String() != form.Get("request_key") {
		return 0, errors.New("Start a new disconnection request to obtain a valid request identifier")
	}
	hours, err := strconv.Atoi(form.Get("hours"))
	if err != nil || hours < 1 || hours > 168 || strconv.Itoa(hours) != form.Get("hours") {
		return 0, errors.New("Choose a delivery window from 1 through 168 whole hours")
	}
	if !validWindowsCSPResolution(form.Get("reason")) {
		return 0, errors.New("Enter a short, single-line reason without leading or trailing spaces (at most 320 bytes)")
	}
	return time.Duration(hours) * time.Hour, nil
}

func (h *Handler) WindowsPreviewUnenrollmentRequest(c echo.Context) error {
	info, _, device, err := h.windowsUpdateFormContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, "request_key", "hours", "reason", "edit_request")
	if err != nil {
		return err
	}
	draft := windows_views.UnenrollmentDraft{Form: form}
	_, err = parseWindowsUnenrollmentDraft(form)
	if err != nil {
		c.Response().Status = 400
		draft.Error = err.Error()
		return renderApple(c, windows_views.UnenrollmentForm(c, info, *device, draft))
	}
	if form.Get("edit_request") == "yes" {
		return renderApple(c, windows_views.UnenrollmentForm(c, info, *device, draft))
	}
	if form.Get("edit_request") != "" {
		return echo.NewHTTPError(400, "Invalid disconnection review action")
	}
	return renderApple(c, windows_views.UnenrollmentPreview(c, info, *device, draft))
}

func (h *Handler) WindowsCreateUnenrollmentRequest(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err = h.windowsReady(); err != nil {
		return err
	}
	form, err := windowsForm(c, "request_key", "hours", "reason", "confirm_disconnect")
	if err != nil {
		return err
	}
	lifetime, err := parseWindowsUnenrollmentDraft(form)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if form.Get("confirm_disconnect") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm disconnection of the selected device")
	}
	// Options come only from server configuration. The store binds them to the
	// original enrollment and checks new-work access after exact intent replay.
	command, err := h.Windows.EnqueueUnenrollmentRequest(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), form.Get("request_key"), form.Get("reason"), lifetime, h.WindowsOptions)
	if err != nil {
		return windowsUnenrollmentFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+command.DeviceID+"/disconnections/"+command.ID)
}

func (h *Handler) WindowsCancelUnenrollmentRequest(c echo.Context) error {
	return h.windowsResolveUnenrollmentRequest(c, false)
}
func (h *Handler) WindowsReleaseUnenrollmentRequest(c echo.Context) error {
	return h.windowsResolveUnenrollmentRequest(c, true)
}
func (h *Handler) windowsResolveUnenrollmentRequest(c echo.Context, release bool) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err = h.windowsReady(); err != nil {
		return err
	}
	fields := []string{"expected_revision", "confirm_cancel"}
	if release {
		fields = []string{"expected_revision", "resolution", "confirm_release"}
	}
	form, err := windowsForm(c, fields...)
	if err != nil {
		return err
	}
	revision, err := parseWindowsCSPRevision(form.Get("expected_revision"))
	if err != nil {
		return err
	}
	if release {
		if form.Get("confirm_release") != "yes" {
			return echo.NewHTTPError(400, "Confirm that the delivered request was investigated and may still disconnect this device")
		}
		if !validWindowsCSPResolution(form.Get("resolution")) {
			return echo.NewHTTPError(400, "Enter a short, single-line review reason without leading or trailing spaces (at most 320 bytes)")
		}
		err = h.Windows.ReleaseUnenrollmentRequest(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), c.Param("request"), revision, form.Get("resolution"))
	} else {
		if form.Get("confirm_cancel") != "yes" {
			return echo.NewHTTPError(400, "Confirm cancellation of this undelivered disconnection request")
		}
		err = h.Windows.CancelUnenrollmentRequest(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), c.Param("request"), revision)
	}
	if err != nil {
		return windowsUnenrollmentFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+c.Param("id")+"/disconnections/"+c.Param("request"))
}
