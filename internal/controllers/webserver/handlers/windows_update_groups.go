package handlers

import (
	"errors"
	"net/url"
	"strconv"

	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsImmediateAssignmentNames() []string {
	return append(windowsAssignmentNames(), "group_id", "group_revision")
}
func windowsAssignmentGroupReference(form url.Values) (string, int, error) {
	id, raw := form.Get("group_id"), form.Get("group_revision")
	if id == "" && raw == "" {
		return "", 0, nil
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return "", 0, windows.ErrUpdateGroup
	}
	revision, err := groupRevision(raw)
	if err != nil || revision == 0 {
		return "", 0, windows.ErrUpdateGroup
	}
	return id, revision, nil
}
func (h *Handler) windowsAssignmentGroup(c echo.Context, scope access.Scope, form url.Values) (*windows.UpdateGroupPreview, error) {
	id, revision, err := windowsAssignmentGroupReference(form)
	if err != nil {
		return nil, windowsGroupFailure(c, err)
	}
	if id == "" {
		return nil, nil
	}
	preview, err := h.Windows.PreviewUpdateGroup(c.Request().Context(), h.appleActor(c), scope, inventory.DeviceSources{Apple: h.Apple != nil, Windows: h.Windows != nil}, id, revision)
	if err != nil {
		return nil, windowsGroupFailure(c, err)
	}
	return preview, nil
}
func (h *Handler) WindowsUpdateAssignmentGroups(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	query, err := groupQuery(c, "revision", "mode", "after")
	if err != nil {
		return groupError(c, err)
	}
	revision, err := strconv.ParseInt(query.Get("revision"), 10, 64)
	mode := query.Get("mode")
	if mode == "" {
		mode = "apply"
	}
	if err != nil || revision < 1 || revision > 1000000 || strconv.FormatInt(revision, 10) != query.Get("revision") || mode != "apply" && mode != "remove" {
		return windowsGroupFailure(c, windows.ErrUpdateGroup)
	}
	ring, err := h.windowsAssignmentRing(c, scope, revision)
	if err != nil {
		return err
	}
	groups, err := inventory.ListDeviceGroups(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), scope, query.Get("after"))
	if err != nil {
		return groupError(c, err)
	}
	path := partials.GetNavigationUrl(info, "/windows/update-rings/"+ring.RingID+"/assign/groups")
	pageURL := func(after string) string {
		q := url.Values{"revision": {strconv.FormatInt(revision, 10)}, "mode": {mode}}
		if after != "" {
			q.Set("after", after)
		}
		return path + "?" + q.Encode()
	}
	paging := mdm_views.DevicePagination{}
	if query.Get("after") != "" {
		paging.First = pageURL("")
	}
	if groups.Next != "" {
		paging.Next = pageURL(groups.Next)
	}
	return renderApple(c, windows_views.UpdateAssignmentGroups(c, info, *ring, mode, groups, paging))
}

func windowsGroupFailure(c echo.Context, err error) error {
	status, key := 0, ""
	switch {
	case errors.Is(err, windows.ErrUpdateGroup):
		status, key = 400, "invalid"
	case errors.Is(err, windows.ErrUpdateGroupConflict):
		status, key = 409, "conflict"
	case errors.Is(err, windows.ErrUpdateGroupLarge):
		status, key = 422, "large"
	default:
		return windowsFailure(err)
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "windows_groups."+key))
}
