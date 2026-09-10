package handlers

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsCSPFailure(err error) error {
	switch {
	case errors.Is(err, windows.ErrCSPCommand):
		return echo.NewHTTPError(400, "Invalid Windows CSP command request")
	case errors.Is(err, windows.ErrCSPConflict):
		return echo.NewHTTPError(409, "The command revision changed. Review its current evidence before taking another action.")
	case errors.Is(err, windows.ErrCSPAlreadySent):
		return echo.NewHTTPError(409, "This action is unavailable in the command's current state. Review its delivery and outcome.")
	default:
		return windowsFailure(err)
	}
}

func (h *Handler) WindowsCSPCommands(c echo.Context) error {
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
		return windowsCSPFailure(err)
	}
	commands, err := h.Windows.CSPCommands(c.Request().Context(), h.appleActor(c), scope, device.ID, offset, 26)
	if err != nil {
		return windowsCSPFailure(err)
	}
	more := len(commands) > 25
	if more {
		commands = commands[:25]
	}
	return renderApple(c, windows_views.CSPCommands(c, info, *device, commands, offset, more))
}

func (h *Handler) WindowsCSPCommand(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsCSPFailure(err)
	}
	detail, err := h.Windows.CSPCommandDetails(c.Request().Context(), h.appleActor(c), scope, device.ID, c.Param("command"))
	if err != nil {
		return windowsCSPFailure(err)
	}
	return renderApple(c, windows_views.CSPCommand(c, info, *device, *detail))
}

func parseWindowsCSPRevision(value string) (int64, error) {
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != value {
		return 0, echo.NewHTTPError(400, "Review the current command revision")
	}
	return revision, nil
}

func (h *Handler) WindowsCancelCSPCommand(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	form, err := windowsForm(c, "expected_revision", "confirm_cancel")
	if err != nil {
		return err
	}
	revision, err := parseWindowsCSPRevision(form.Get("expected_revision"))
	if err != nil {
		return err
	}
	if form.Get("confirm_cancel") != "yes" {
		return echo.NewHTTPError(400, "Confirm cancellation of this undelivered command")
	}
	command, err := h.Windows.CSPCommand(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), c.Param("command"))
	if err != nil {
		return windowsCSPFailure(err)
	}
	// The immutable owner determines the cancellation workflow. Keep typed runs'
	// all-step cancellation checks, including another step's sent/unknown barrier.
	if command.UpdateRunID != "" {
		return echo.NewHTTPError(409, "Cancel remaining work from the owning update policy run")
	}
	if err := h.Windows.CancelCSPCommand(c.Request().Context(), h.appleActor(c), scope, command.DeviceID, command.ID, revision); err != nil {
		return windowsCSPFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+command.DeviceID+"/commands/"+command.ID)
}

func validWindowsCSPResolution(note string) bool {
	if note == "" || len(note) > 320 || !utf8.ValidString(note) || strings.TrimSpace(note) != note {
		return false
	}
	for _, r := range note {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (h *Handler) WindowsAbandonCSPCommand(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	form, err := windowsForm(c, "expected_revision", "resolution", "confirm_abandon")
	if err != nil {
		return err
	}
	revision, err := parseWindowsCSPRevision(form.Get("expected_revision"))
	if err != nil {
		return err
	}
	if form.Get("confirm_abandon") != "yes" || !validWindowsCSPResolution(form.Get("resolution")) {
		return echo.NewHTTPError(400, "Confirm release of the uncertain command and enter a resolution note of 1–320 UTF-8 bytes, without surrounding whitespace or control characters")
	}
	if err := h.Windows.AbandonCSPCommand(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), c.Param("command"), revision, form.Get("resolution")); err != nil {
		return windowsCSPFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+c.Param("id")+"/commands/"+c.Param("command"))
}
