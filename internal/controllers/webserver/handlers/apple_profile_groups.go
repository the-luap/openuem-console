package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func appleProfileGroupFailure(c echo.Context, err error) error {
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
	case errors.Is(err, apple.ErrProfileGroup), errors.Is(err, inventory.ErrGroupInvalid), errors.Is(err, apple.ErrProfilePrerequisite):
		status, key = http.StatusBadRequest, "invalid"
	}
	return echo.NewHTTPError(status, appleErrorText(c, "apple_groups."+key))
}

func (h *Handler) appleProfileGroupContext(c echo.Context) (*partials.CommonInfo, apple.Scope, error) {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if scope.SiteID <= 0 || c.Param("site") == "" {
		return nil, scope, echo.NewHTTPError(http.StatusBadRequest, appleErrorText(c, "apple_groups.site"))
	}
	if err = h.appleReady(); err != nil {
		return nil, scope, err
	}
	if _, err = profileRevisionParameter(c.Param("id")); err != nil {
		return nil, scope, err
	}
	return info, scope, nil
}

func appleProfileGroupSource(raw string) (bool, error) {
	switch raw {
	case "", "site":
		return false, nil
	case "organization":
		return true, nil
	default:
		return false, apple.ErrProfileGroup
	}
}

func appleProfileGroupQuery(c echo.Context, fields ...string) (url.Values, int, string, error) {
	q, err := groupQuery(c, fields...)
	if err != nil {
		return nil, 0, "", err
	}
	revision, err := groupRevision(q.Get("revision"))
	desired := q.Get("desired")
	if desired == "" {
		desired = "installed"
	}
	if err != nil || revision == 0 || (desired != "installed" && desired != "removed") {
		return nil, 0, "", apple.ErrProfileGroup
	}
	return q, revision, desired, nil
}

func (h *Handler) AppleProfileGroups(c echo.Context) error {
	info, scope, err := h.appleProfileGroupContext(c)
	if err != nil {
		return err
	}
	q, revision, desired, err := appleProfileGroupQuery(c, "revision", "desired", "source", "after")
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	organization, err := appleProfileGroupSource(q.Get("source"))
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	groupScope := access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}
	if organization {
		groupScope.SiteID = 0
	}
	p, err := h.Apple.ProfileForGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("id"), revision)
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	groups, err := inventory.ListDeviceGroups(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), groupScope, q.Get("after"))
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	choice := mdm_views.ProfileGroupChoice{Organization: organization, ProfileID: p.ID, ProfileName: p.Name, Revision: p.Revision, Desired: desired}
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = mdm_views.ProfileGroupChoiceURL(info, choice, "")
	}
	if groups.Next != "" {
		paging.Next = mdm_views.ProfileGroupChoiceURL(info, choice, groups.Next)
	}
	return renderApple(c, mdm_views.AppleProfileGroups(c, info, choice, groups, paging))
}

func (h *Handler) ApplePreviewProfileGroup(c echo.Context) error {
	info, scope, err := h.appleProfileGroupContext(c)
	if err != nil {
		return err
	}
	q, revision, desired, err := appleProfileGroupQuery(c, "revision", "desired", "source", "group_revision")
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	groupVersion, err := groupRevision(q.Get("group_revision"))
	if err != nil || groupVersion == 0 {
		return appleProfileGroupFailure(c, apple.ErrProfileGroup)
	}
	organization, err := appleProfileGroupSource(q.Get("source"))
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	previewGroup := h.Apple.PreviewProfileGroup
	if organization {
		previewGroup = h.Apple.PreviewProfileOrganizationGroup
	}
	preview, err := previewGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, c.Param("id"), revision, c.Param("group"), groupVersion, desired)
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleProfileGroupPreview(c, info, *preview, uuid.NewString()))
}

func (h *Handler) AppleAssignProfileGroup(c echo.Context) error {
	info, scope, err := h.appleProfileGroupContext(c)
	if err != nil {
		return err
	}
	f, err := deviceManagementForm(c, "apple_groups.invalid", []string{"csrf", "expected_revision", "group_id", "group_revision", "group_source", "request_key", "devices", "desired", "confirmed"})
	if err != nil {
		return err
	}
	revision, err := groupRevision(f.Get("expected_revision"))
	if err != nil || revision == 0 || f.Get("confirmed") != "yes" {
		return appleProfileGroupFailure(c, apple.ErrProfileGroup)
	}
	groupVersion, err := groupRevision(f.Get("group_revision"))
	if err != nil || groupVersion == 0 {
		return appleProfileGroupFailure(c, apple.ErrProfileGroup)
	}
	devices := strings.Split(strings.TrimSpace(f.Get("devices")), "\n")
	for i, id := range devices {
		devices[i] = strings.TrimSpace(id)
	}
	organization, err := appleProfileGroupSource(f.Get("group_source"))
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	assignGroup := h.Apple.AssignProfileFromGroup
	if organization {
		assignGroup = h.Apple.AssignProfileFromOrganizationGroup
	}
	assignment, err := assignGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, c.Param("id"), revision, f.Get("group_id"), groupVersion, f.Get("request_key"), devices, f.Get("desired"))
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/configurations/"+assignment.ProfileID+"/group-assignments/"+assignment.ID)
}

func (h *Handler) AppleProfileGroupAssignment(c echo.Context) error {
	info, scope, err := h.appleProfileGroupContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleProfileGroupFailure(c, err)
	}
	r, err := h.Apple.ProfileGroupAssignmentDetails(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("id"), c.Param("assignment"))
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleProfileGroupAssignment(c, info, *r))
}

func (h *Handler) AppleProfileGroupAssignments(c echo.Context) error {
	info, scope, err := h.appleProfileGroupContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	items, next, err := h.Apple.ProfileGroupAssignments(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("id"), q.Get("before"))
	if err != nil {
		return appleProfileGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleProfileGroupAssignments(c, info, c.Param("id"), items, next))
}
