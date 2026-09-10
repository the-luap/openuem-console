package handlers

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

const windowsScheduleTimeLayout = "2006-01-02T15:04"

func windowsScheduleNames() []string {
	return []string{"ring_revision", "request_key", "mode", "hours", "devices", "not_before", "activation_minutes", "confirm_schedule"}
}

// Parse only immutable timing syntax here. A new-work clock check belongs in
// preview and store admission, after the store's exact-request replay branch.
func parseWindowsScheduleTiming(form url.Values) (time.Time, time.Duration, error) {
	raw := form.Get("not_before")
	start, err := time.ParseInLocation(windowsScheduleTimeLayout, raw, time.UTC)
	if err != nil || start.IsZero() || start.Year() < 1 || start.Format(windowsScheduleTimeLayout) != raw {
		return time.Time{}, 0, fmt.Errorf("Enter a complete activation date and time in UTC, to the minute")
	}
	minutes, err := strconv.Atoi(form.Get("activation_minutes"))
	if err != nil || minutes < 1 || minutes > 10080 || strconv.Itoa(minutes) != form.Get("activation_minutes") {
		return time.Time{}, 0, fmt.Errorf("Choose an activation window from 1 to 10080 whole minutes")
	}
	return start, time.Duration(minutes) * time.Minute, nil
}

func windowsScheduleFailure(err error) error {
	switch {
	case errors.Is(err, windows.ErrUpdateScheduleConflict):
		return echo.NewHTTPError(409, "The schedule state or request changed. Review the current schedule before taking another action.")
	case errors.Is(err, windows.ErrUpdateScheduleFull):
		return echo.NewHTTPError(409, "This site already has 256 pending schedules. Review its scheduled and waiting plans.")
	case errors.Is(err, windows.ErrUpdateSchedule):
		return echo.NewHTTPError(400, "Invalid update schedule. Review the source, targets and activation window; new plans must start within 90 days.")
	case errors.Is(err, windows.ErrCSPAlreadySent):
		return echo.NewHTTPError(409, "This schedule is no longer waiting for activation. Review its status and any resulting device runs.")
	case errors.Is(err, windows.ErrCSPDeadline):
		return echo.NewHTTPError(409, "The activation window closed before this schedule could be saved. Review a new activation time.")
	default:
		return windowsFailure(err)
	}
}

func (h *Handler) WindowsCreateUpdateSchedule(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, windowsScheduleNames()...)
	if err != nil {
		return err
	}
	revision, targets, lifetime, err := parseWindowsAssignment(form)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	start, window, err := parseWindowsScheduleTiming(form)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if form.Get("confirm_schedule") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm the exact revision, devices and activation window")
	}
	schedule, err := h.Windows.ScheduleUpdateRing(c.Request().Context(), h.appleActor(c), scope, c.Param("ring"), revision, form.Get("request_key"), targets, form.Get("mode") == "remove", start, window, lifetime)
	if err != nil {
		return windowsScheduleFailure(err)
	}
	return appleRedirect(c, info, "/windows/update-schedules/"+schedule.ID)
}

func (h *Handler) WindowsUpdateSchedules(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	offset, err := windowsOffset(c, "offset")
	if err != nil {
		return err
	}
	schedules, err := h.Windows.UpdateSchedules(c.Request().Context(), h.appleActor(c), scope, offset, 26)
	if err != nil {
		return windowsScheduleFailure(err)
	}
	more := len(schedules) > 25
	if more {
		schedules = schedules[:25]
	}
	rows := []windows_views.UpdateScheduleRow{}
	for _, schedule := range schedules {
		ring, err := h.windowsRingRevision(c, scope, schedule.RingID, schedule.RingRevision)
		if err != nil {
			return err
		}
		rows = append(rows, windows_views.UpdateScheduleRow{Schedule: schedule, Name: ring.Name})
	}
	return renderApple(c, windows_views.UpdateSchedules(c, info, rows, offset, more))
}

func (h *Handler) WindowsUpdateSchedule(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	schedule, err := h.Windows.UpdateScheduleDetails(c.Request().Context(), h.appleActor(c), scope, c.Param("schedule"))
	if err != nil {
		return windowsScheduleFailure(err)
	}
	ring, err := h.windowsRingRevision(c, scope, schedule.RingID, schedule.RingRevision)
	if err != nil {
		return err
	}
	targets := []windows_views.UpdateScheduleTarget{}
	for _, id := range schedule.Targets {
		device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, id)
		if err != nil && !errors.Is(err, windows.ErrNotFound) {
			return windowsFailure(err)
		}
		// Preserve the original reviewed UUID if its live record is unavailable.
		// Never follow a device into a different site to recover its current name.
		targets = append(targets, windows_views.UpdateScheduleTarget{ID: id, Device: device})
	}
	return renderApple(c, windows_views.UpdateSchedule(c, info, *schedule, *ring, targets))
}

func (h *Handler) WindowsCancelUpdateSchedule(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, "expected_revision", "confirm_cancel")
	if err != nil {
		return err
	}
	revision, err := strconv.ParseInt(form.Get("expected_revision"), 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != form.Get("expected_revision") || form.Get("confirm_cancel") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm cancellation of this pending schedule")
	}
	if err := h.Windows.CancelUpdateSchedule(c.Request().Context(), h.appleActor(c), scope, c.Param("schedule"), revision); err != nil {
		return windowsScheduleFailure(err)
	}
	return appleRedirect(c, info, "/windows/update-schedules/"+c.Param("schedule"))
}
