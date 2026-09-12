package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func appleUpdateGroupFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "permission"
	case errors.Is(err, apple.ErrNotFound), errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "missing"
	case errors.Is(err, apple.ErrConflict), errors.Is(err, inventory.ErrGroupConflict):
		status, key = http.StatusConflict, "changed"
	case errors.Is(err, inventory.ErrGroupSnapshotLarge):
		status, key = http.StatusUnprocessableEntity, "large"
	case errors.Is(err, apple.ErrUpdatePlanGroup), errors.Is(err, apple.ErrUpdatePlan), errors.Is(err, inventory.ErrGroupInvalid):
		status, key = http.StatusBadRequest, "invalid"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "apple_update_groups."+key))
}
func (h *Handler) AppleUpdatePlanGroups(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "revision", "after")
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	revision, err := groupRevision(q.Get("revision"))
	if err != nil || revision == 0 {
		return appleUpdateGroupFailure(c, apple.ErrUpdatePlanGroup)
	}
	plan, err := h.Apple.UpdatePlanForGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), revision)
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	groups, err := inventory.ListDeviceGroups(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, q.Get("after"))
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = mdm_views.UpdatePlanGroupChoiceURL(info, *plan, "")
	}
	if groups.Next != "" {
		paging.Next = mdm_views.UpdatePlanGroupChoiceURL(info, *plan, groups.Next)
	}
	return renderApple(c, mdm_views.AppleUpdatePlanGroups(c, info, *plan, groups, paging))
}
func (h *Handler) ApplePreviewUpdatePlanGroup(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "revision", "group_revision")
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	revision, err := groupRevision(q.Get("revision"))
	if err != nil || revision == 0 {
		return appleUpdateGroupFailure(c, apple.ErrUpdatePlanGroup)
	}
	groupVersion, err := groupRevision(q.Get("group_revision"))
	if err != nil || groupVersion == 0 {
		return appleUpdateGroupFailure(c, apple.ErrUpdatePlanGroup)
	}
	preview, err := h.Apple.PreviewUpdatePlanGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, c.Param("plan"), revision, c.Param("group"), groupVersion)
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdatePlanGroupPreview(c, info, *preview, uuid.NewString()))
}
func appleUpdateGroupSelection(f url.Values) (int, int, []apple.UpdatePlanGroupSelection, error) {
	revision, err := groupRevision(f.Get("expected_revision"))
	if err != nil || revision == 0 || f.Get("confirmed") != "yes" {
		return 0, 0, nil, apple.ErrUpdatePlanGroup
	}
	groupVersion, err := groupRevision(f.Get("group_revision"))
	if err != nil || groupVersion == 0 {
		return 0, 0, nil, apple.ErrUpdatePlanGroup
	}
	lines := strings.Split(strings.TrimSpace(f.Get("devices")), "\n")
	if len(lines) < 1 || len(lines) > 100 {
		return 0, 0, nil, apple.ErrUpdatePlanGroup
	}
	selected := make([]apple.UpdatePlanGroupSelection, len(lines))
	for i, line := range lines {
		id, token, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			return 0, 0, nil, apple.ErrUpdatePlanGroup
		}
		selected[i] = apple.UpdatePlanGroupSelection{DeviceID: id, PolicyToken: token}
	}
	return revision, groupVersion, selected, nil
}

func (h *Handler) AppleAssignUpdatePlanGroup(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	f, err := boundedDeviceManagementForm(c, "apple_update_groups.invalid", []string{"csrf", "expected_revision", "group_id", "group_revision", "request_key", "devices", "confirmed"}, 16<<10)
	if err != nil {
		return err
	}
	revision, groupVersion, selected, err := appleUpdateGroupSelection(f)
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	assignment, err := h.Apple.AssignUpdatePlanFromGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, c.Param("plan"), revision, f.Get("group_id"), groupVersion, f.Get("request_key"), selected)
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return appleRedirect(c, info, mdm_views.UpdatePlanGroupHistoryPath(assignment.Plan.ID)+"/"+assignment.ID)
}
func (h *Handler) AppleUpdatePlanGroupAssignment(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	assignment, err := h.Apple.UpdatePlanGroupAssignmentDetails(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"))
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdatePlanGroupAssignment(c, info, *assignment))
}

func (h *Handler) AppleUpdatePlanGroupProgress(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	progress, err := h.Apple.UpdatePlanGroupProgress(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"))
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateGroupProgress(c, info, *progress))
}
func (h *Handler) AppleUpdatePlanGroupAssignments(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	items, next, err := h.Apple.UpdatePlanGroupAssignments(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), q.Get("before"))
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdatePlanGroupAssignments(c, info, c.Param("plan"), items, next))
}
