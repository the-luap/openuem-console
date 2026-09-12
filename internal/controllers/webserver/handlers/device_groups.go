package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func groupQuery(c echo.Context, allowed ...string) (url.Values, error) {
	raw := c.Request().URL.RawQuery
	if len(raw) > 16<<10 {
		return nil, inventory.ErrGroupInvalid
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, inventory.ErrGroupInvalid
	}
	for key, values := range q {
		known := false
		for _, field := range allowed {
			if field == key {
				known = true
				break
			}
		}
		if !known || len(values) != 1 {
			return nil, inventory.ErrGroupInvalid
		}
	}
	return q, nil
}
func groupRevision(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > 2147483647 || strconv.Itoa(n) != raw {
		return 0, inventory.ErrGroupInvalid
	}
	return n, nil
}
func groupError(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrGroupInvalid), errors.Is(err, inventory.ErrReportFilter):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrGroupConflict):
		status, key = http.StatusConflict, "conflict"
	case errors.Is(err, inventory.ErrGroupLimit):
		status, key = http.StatusUnprocessableEntity, "limit"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "permission_denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "mdm.groups."+key))
}

// An organization group URL always means the whole organization. The shared
// console's site fallback must not silently create a site group at that URL.
func (h *Handler) deviceGroupInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, selected, err := h.appleInfo(c)
	if err != nil {
		return nil, access.Scope{}, err
	}
	scope := access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}
	if c.Param("site") == "" {
		scope.SiteID = 0
		if err = h.requireApplePermission(c, scope); err != nil {
			return nil, scope, err
		}
		info.SiteID = "-1"
	}
	return info, scope, nil
}

func (h *Handler) DeviceGroups(c echo.Context) error {
	info, scope, err := h.deviceGroupInfo(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "after")
	if err != nil {
		return groupError(c, err)
	}
	page, err := inventory.ListDeviceGroups(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, q.Get("after"))
	if err != nil {
		return groupError(c, err)
	}
	path := partials.GetNavigationUrl(info, "/device-groups")
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = path
	}
	if page.Next != "" {
		paging.Next = path + "?" + url.Values{"after": {page.Next}}.Encode()
	}
	return renderApple(c, mdm_views.DeviceGroups(c, info, page, paging))
}

func (h *Handler) DeviceGroup(c echo.Context) error {
	info, scope, err := h.deviceGroupInfo(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "revision", "after", "history")
	if err != nil {
		return groupError(c, err)
	}
	revision, err := groupRevision(q.Get("revision"))
	if err != nil {
		return groupError(c, err)
	}
	before, err := groupRevision(q.Get("history"))
	if err != nil {
		return groupError(c, err)
	}
	group, err := inventory.InspectDeviceGroup(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, inventory.DeviceSources{Apple: h.Apple != nil, Windows: h.Windows != nil}, c.Param("group"), inventory.DeviceGroupPosition{Revision: revision, After: q.Get("after"), HistoryBefore: before})
	if err != nil {
		return groupError(c, err)
	}
	path := partials.GetNavigationUrl(info, "/device-groups/"+group.Group.ID)
	pageURL := func(after string, history int) string {
		v := url.Values{"revision": {strconv.Itoa(group.Group.Revision)}}
		if after != "" {
			v.Set("after", after)
		}
		if history > 0 {
			v.Set("history", strconv.Itoa(history))
		}
		return path + "?" + v.Encode()
	}
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = pageURL("", before)
	}
	if group.Members.Next != "" {
		paging.Next = pageURL(group.Members.Next, before)
	}
	history := mdm_views.DevicePagination{}
	if before > 0 {
		history.First = pageURL(q.Get("after"), 0)
	}
	if group.HistoryBefore > 0 {
		history.Next = pageURL(q.Get("after"), group.HistoryBefore)
	}
	return renderApple(c, mdm_views.DeviceGroup(c, info, group, deviceViewRows(c.Request().Context(), group.Members.Entries), paging, history))
}

func (h *Handler) SaveDeviceGroup(c echo.Context) error {
	info, scope, err := h.deviceGroupInfo(c)
	if err != nil {
		return err
	}
	f, err := deviceManagementForm(c, "mdm.groups.invalid", []string{"csrf", "name", "description", "platform", "q", "archived", "revision"})
	if err != nil {
		return err
	}
	revision, err := groupRevision(f.Get("revision"))
	if err != nil {
		return groupError(c, err)
	}
	if f.Get("archived") != "" && f.Get("archived") != "true" {
		return groupError(c, inventory.ErrGroupInvalid)
	}
	group, err := inventory.SaveDeviceGroup(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("group"), revision, inventory.DeviceGroupDefinition{Name: f.Get("name"), Description: f.Get("description"), Rule: inventory.DeviceGroupRule{Platform: f.Get("platform"), Search: f.Get("q")}, Archived: f.Get("archived") == "true"})
	if err != nil {
		return groupError(c, err)
	}
	return c.Redirect(http.StatusSeeOther, partials.GetNavigationUrl(info, "/device-groups/"+group.ID))
}
