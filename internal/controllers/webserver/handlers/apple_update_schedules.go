package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func appleUpdateScheduleFailure(c echo.Context, err error) error {
	switch {
	case errors.Is(err, apple.ErrUpdateSchedule):
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "apple_update_schedules.invalid"))
	case errors.Is(err, apple.ErrUpdateScheduleFull):
		return echo.NewHTTPError(http.StatusConflict, i18n.T(c.Request().Context(), "apple_update_schedules.full"))
	default:
		return appleUpdateGroupFailure(c, err)
	}
}
func appleUpdateScheduleTiming(f url.Values) (time.Time, time.Duration, error) {
	raw := f.Get("not_before")
	at, err := time.Parse("2006-01-02T15:04:05Z", raw)
	if err != nil || at.Format("2006-01-02T15:04:05Z") != raw {
		return time.Time{}, 0, apple.ErrUpdateSchedule
	}
	minutes, err := groupRevision(f.Get("activation_window_minutes"))
	if err != nil || minutes < 1 || minutes > 10080 {
		return time.Time{}, 0, apple.ErrUpdateSchedule
	}
	return at, time.Duration(minutes) * time.Minute, nil
}
func (h *Handler) AppleScheduleUpdatePlan(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	f, err := boundedDeviceManagementForm(c, "apple_update_schedules.invalid", []string{"csrf", "expected_revision", "group_id", "group_revision", "group_source", "request_key", "devices", "confirmed", "not_before", "activation_window_minutes"}, 16<<10)
	if err != nil {
		return err
	}
	revision, groupRevision, selection, err := appleUpdateGroupSelection(f)
	if err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	at, window, err := appleUpdateScheduleTiming(f)
	if err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	organization, err := appleUpdateGroupSource(f.Get("group_source"))
	if err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	scheduleGroup := h.Apple.ScheduleUpdatePlanFromGroup
	if organization {
		scheduleGroup = h.Apple.ScheduleUpdatePlanFromOrganizationGroup
	}
	r, err := scheduleGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, c.Param("plan"), revision, f.Get("group_id"), groupRevision, f.Get("request_key"), selection, at, window)
	if err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	return appleRedirect(c, info, mdm_views.UpdateSchedulePath(r.Plan.ID)+"/"+r.ID)
}
func (h *Handler) AppleUpdateSchedule(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	r, err := h.Apple.UpdateScheduleDetails(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("schedule"))
	if err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateSchedule(c, info, *r))
}
func (h *Handler) AppleUpdateSchedules(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	items, next, err := h.Apple.UpdateSchedules(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), q.Get("before"))
	if err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateSchedules(c, info, c.Param("plan"), items, next))
}
func (h *Handler) AppleCancelUpdateSchedule(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	f, err := deviceManagementForm(c, "apple_update_schedules.invalid", []string{"csrf", "expected_revision", "confirmed"})
	if err != nil {
		return err
	}
	revision, err := groupRevision(f.Get("expected_revision"))
	if err != nil || revision < 1 || f.Get("confirmed") != "yes" {
		return appleUpdateScheduleFailure(c, apple.ErrUpdateSchedule)
	}
	if err = h.Apple.CancelUpdateSchedule(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("schedule"), revision); err != nil {
		return appleUpdateScheduleFailure(c, err)
	}
	return appleRedirect(c, info, mdm_views.UpdateSchedulePath(c.Param("plan"))+"/"+c.Param("schedule"))
}
