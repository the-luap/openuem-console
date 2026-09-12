package handlers

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func parseWindowsAssignment(form url.Values) (int64, []string, time.Duration, error) {
	revision, err := strconv.ParseInt(form.Get("ring_revision"), 10, 64)
	if err != nil || revision < 1 || revision > 1000000 || strconv.FormatInt(revision, 10) != form.Get("ring_revision") {
		return 0, nil, 0, fmt.Errorf("Choose an exact saved ring revision")
	}
	key, err := uuid.Parse(form.Get("request_key"))
	if err != nil || key == uuid.Nil || key.String() != form.Get("request_key") {
		return revision, nil, 0, fmt.Errorf("The request identifier is invalid. Start a new assignment.")
	}
	if form.Get("mode") != "apply" && form.Get("mode") != "remove" {
		return revision, nil, 0, fmt.Errorf("Choose whether to apply or remove this revision's settings")
	}
	hours, err := strconv.Atoi(form.Get("hours"))
	if err != nil || hours < 1 || hours > 168 || strconv.Itoa(hours) != form.Get("hours") {
		return revision, nil, 0, fmt.Errorf("Choose an admission lifetime from 1 to 168 whole hours")
	}
	// One UUID per line. Only ordinary surrounding line whitespace is accepted;
	// duplicate targets are rejected instead of silently changing the selection.
	raw := strings.Trim(form.Get("devices"), " \t\r\n")
	if len(raw) > 4000 {
		return revision, nil, 0, fmt.Errorf("Select 1 to 100 native Windows device IDs, one per line")
	}
	targets := strings.Split(raw, "\n")
	if len(targets) < 1 || len(targets) > 100 {
		return revision, nil, 0, fmt.Errorf("Select 1 to 100 native Windows device IDs, one per line")
	}
	for i, raw := range targets {
		idText := strings.Trim(raw, " \t\r")
		id, err := uuid.Parse(idText)
		if err != nil || id == uuid.Nil || id.String() != idText {
			return revision, nil, 0, fmt.Errorf("Use one complete native Windows device UUID on each line, without empty lines")
		}
		targets[i] = idText
	}
	slices.Sort(targets)
	for i := 1; i < len(targets); i++ {
		if targets[i] == targets[i-1] {
			return revision, nil, 0, fmt.Errorf("Each device may appear only once in the assignment")
		}
	}
	return revision, targets, time.Duration(hours) * time.Hour, nil
}

func windowsAssignmentNames() []string {
	return []string{"ring_revision", "request_key", "mode", "hours", "devices", "confirm_assignment"}
}

func (h *Handler) windowsAssignmentRing(c echo.Context, scope access.Scope, revision int64) (*windows.UpdateRingRevision, error) {
	return h.windowsRingRevision(c, scope, c.Param("ring"), revision)
}

func (h *Handler) windowsRingRevision(c echo.Context, scope access.Scope, id string, revision int64) (*windows.UpdateRingRevision, error) {
	rings, err := h.Windows.UpdateRingRevisions(c.Request().Context(), h.appleActor(c), scope, id, revision+1, 1)
	if err != nil {
		return nil, windowsGroupFailure(c, err)
	}
	if len(rings) != 1 || rings[0].Revision != revision {
		return nil, windowsFailure(windows.ErrNotFound)
	}
	return &rings[0], nil
}

func (h *Handler) WindowsNewUpdateAssignment(c echo.Context) error {
	return h.windowsNewAssignment(c, false)
}

func (h *Handler) WindowsNewUpdateSchedule(c echo.Context) error {
	return h.windowsNewAssignment(c, true)
}

func (h *Handler) windowsNewAssignment(c echo.Context, scheduled bool) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	allowed := []string{"revision", "mode"}
	if !scheduled {
		allowed = append(allowed, "group", "group_revision")
	}
	query, err := groupQuery(c, allowed...)
	if err != nil {
		return groupError(c, err)
	}
	form := url.Values{"ring_revision": {c.QueryParam("revision")}, "request_key": {uuid.NewString()}, "mode": {c.QueryParam("mode")}, "hours": {"24"}, "devices": {""}}
	if len(c.QueryParams()["revision"]) != 1 || len(c.QueryParams()["mode"]) > 1 {
		return echo.NewHTTPError(400, "Choose one ring revision and action")
	}
	if form.Get("mode") == "" {
		form.Set("mode", "apply")
	}
	revision, err := strconv.ParseInt(form.Get("ring_revision"), 10, 64)
	if err != nil || revision < 1 || revision > 1000000 || strconv.FormatInt(revision, 10) != form.Get("ring_revision") || (form.Get("mode") != "apply" && form.Get("mode") != "remove") {
		return echo.NewHTTPError(400, "Choose an exact ring revision and action")
	}
	ring, err := h.windowsAssignmentRing(c, scope, revision)
	if err != nil {
		return err
	}
	if scheduled {
		form.Set("not_before", time.Now().UTC().Add(time.Hour).Truncate(time.Minute).Format(windowsScheduleTimeLayout))
		form.Set("activation_minutes", "60")
	}
	draft := windows_views.UpdateAssignmentDraft{Form: form, Ring: *ring, Scheduled: scheduled}
	if query.Get("group") != "" || query.Get("group_revision") != "" {
		form.Set("group_id", query.Get("group"))
		form.Set("group_revision", query.Get("group_revision"))
		draft.Group, err = h.windowsAssignmentGroup(c, scope, form)
		if err != nil {
			return err
		}
		form.Set("devices", strings.Join(draft.Group.Targets, "\n"))
	}
	return renderApple(c, windows_views.UpdateAssignmentForm(c, info, draft))
}

func (h *Handler) WindowsPreviewUpdateAssignment(c echo.Context) error {
	return h.windowsPreviewAssignment(c, false)
}

func (h *Handler) WindowsPreviewUpdateSchedule(c echo.Context) error {
	return h.windowsPreviewAssignment(c, true)
}

func (h *Handler) windowsPreviewAssignment(c echo.Context, scheduled bool) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	names := windowsImmediateAssignmentNames()
	if scheduled {
		names = windowsScheduleNames()
	}
	form, err := windowsForm(c, append(names, "edit_assignment")...)
	if err != nil {
		return err
	}
	revision, targets, _, parseErr := parseWindowsAssignment(form)
	// Reject invalid source metadata before rendering a protected source policy.
	if revision == 0 {
		return echo.NewHTTPError(400, parseErr.Error())
	}
	ring, err := h.windowsAssignmentRing(c, scope, revision)
	if err != nil {
		return err
	}
	draft := windows_views.UpdateAssignmentDraft{Form: form, Ring: *ring, Scheduled: scheduled}
	if scheduled {
		var timingErr error
		draft.NotBefore, draft.ActivationWindow, timingErr = parseWindowsScheduleTiming(form)
		if parseErr == nil {
			parseErr = timingErr
		}
	}
	if parseErr != nil {
		c.Response().Status = 400
		draft.Error = parseErr.Error()
		return renderApple(c, windows_views.UpdateAssignmentForm(c, info, draft))
	}
	if !scheduled {
		draft.Group, err = h.windowsAssignmentGroup(c, scope, form)
		if err != nil {
			return err
		}
		if draft.Group != nil && !slices.Equal(draft.Group.Targets, targets) {
			return windowsGroupFailure(c, windows.ErrUpdateGroupConflict)
		}
	}
	if form.Get("edit_assignment") == "yes" {
		return renderApple(c, windows_views.UpdateAssignmentForm(c, info, draft))
	}
	if form.Get("edit_assignment") != "" {
		return echo.NewHTTPError(400, "Invalid assignment review action")
	}
	if scheduled {
		now := time.Now().UTC()
		if draft.NotBefore.Before(now.Add(-time.Minute)) || draft.NotBefore.After(now.Add(90*24*time.Hour)) || !draft.NotBefore.Add(draft.ActivationWindow).After(now) {
			c.Response().Status = 400
			draft.Error = "Choose an activation time within the next 90 days and an activation window that is still open. All times are UTC."
			return renderApple(c, windows_views.UpdateAssignmentForm(c, info, draft))
		}
	}
	if form.Get("mode") == "apply" {
		current, err := h.Windows.UpdateRingRevisions(c.Request().Context(), h.appleActor(c), scope, ring.RingID, 0, 1)
		if err != nil {
			return windowsGroupFailure(c, err)
		}
		if len(current) != 1 || current[0].Revision != revision || !ring.Enabled {
			c.Response().Status = 409
			draft.Error = "New apply assignments require the current enabled ring revision. Review the latest revision or explicitly select source removal."
			return renderApple(c, windows_views.UpdateAssignmentForm(c, info, draft))
		}
	}
	for _, id := range targets {
		device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, id)
		if err != nil {
			return windowsGroupFailure(c, err)
		}
		if device.RevokedAt != nil || device.CertificateRevokedAt != nil || !device.CertificateExpiresAt.After(time.Now()) {
			return windowsFailure(windows.ErrManagementIdentity)
		}
		draft.Devices = append(draft.Devices, *device)
	}
	// Canonical target order is also the persisted store order. It does not alter
	// the set the operator selected, and exact retries accept equivalent ordering.
	form.Set("devices", strings.Join(targets, "\n"))
	return renderApple(c, windows_views.UpdateAssignmentPreview(c, info, draft))
}

func (h *Handler) WindowsCreateUpdateAssignment(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, windowsImmediateAssignmentNames()...)
	if err != nil {
		return err
	}
	revision, targets, lifetime, err := parseWindowsAssignment(form)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if form.Get("confirm_assignment") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm the exact ring revision and selected devices")
	}
	// Admission rechecks all source/target authority in one transaction. Do not
	// precede this call with new-work eligibility checks that would break an exact
	// retry after the original ring was changed or a device finished its work.
	groupID, groupRevision, err := windowsAssignmentGroupReference(form)
	if err != nil {
		return windowsGroupFailure(c, err)
	}
	var rollout *windows.UpdateRollout
	if groupID != "" {
		rollout, err = h.Windows.AssignUpdateRingFromGroup(c.Request().Context(), h.appleActor(c), scope, c.Param("ring"), revision, form.Get("request_key"), targets, form.Get("mode") == "remove", lifetime, inventory.DeviceSources{Apple: h.Apple != nil, Windows: h.Windows != nil}, groupID, groupRevision)
	} else {
		rollout, err = h.Windows.AssignUpdateRing(c.Request().Context(), h.appleActor(c), scope, c.Param("ring"), revision, form.Get("request_key"), targets, form.Get("mode") == "remove", lifetime)
	}
	if err != nil {
		return windowsGroupFailure(c, err)
	}
	return appleRedirect(c, info, "/windows/update-rollouts/"+rollout.ID)
}

func (h *Handler) WindowsUpdateRollout(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	rollout, err := h.Windows.UpdateRolloutDetails(c.Request().Context(), h.appleActor(c), scope, c.Param("rollout"))
	if err != nil {
		return windowsGroupFailure(c, err)
	}
	// RolloutDetails already authenticates the original ring and every run. Read
	// their protected current history separately so phase labels retain the same
	// historical-evidence meaning as the per-device run page.
	rows := []windows_views.UpdateRolloutRow{}
	for _, run := range rollout.Runs {
		device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, run.DeviceID)
		if err != nil {
			return windowsGroupFailure(c, err)
		}
		detail, err := h.Windows.UpdateRunDetails(c.Request().Context(), h.appleActor(c), scope, run.DeviceID, run.ID)
		if err != nil {
			return windowsGroupFailure(c, err)
		}
		rows = append(rows, windows_views.UpdateRolloutRow{Device: *device, Detail: *detail})
	}
	return renderApple(c, windows_views.UpdateRollout(c, info, *rollout, rows))
}
