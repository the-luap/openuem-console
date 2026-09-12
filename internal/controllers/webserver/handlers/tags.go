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

func tagCapability(method, path string) (access.Capability, bool) {
	switch path {
	case "/tenant/:tenant/admin", "/tenant/:tenant/admin/tags", "/tenant/:tenant/admin/tags/:tag":
		if method == http.MethodGet {
			return access.ReadDevices, true
		}
		if method == http.MethodPost {
			return access.ManageTags, true
		}
	case "/tenant/:tenant/admin/tags/:tag/delete":
		if method == http.MethodPost {
			return access.ManageTags, true
		}
	}
	return "", false
}

func tagFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTagInvalid), errors.Is(err, inventory.ErrReportFilter):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrTagConflict):
		status, key = http.StatusConflict, "conflict"
	case errors.Is(err, inventory.ErrTagName):
		status, key = http.StatusConflict, "name_unavailable"
	case errors.Is(err, inventory.ErrTagUsed):
		status, key = http.StatusConflict, "used"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "organization_tags."+key))
}

func (h *Handler) tagInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	id, err := strconv.Atoi(c.Param("tenant"))
	if err != nil || id <= 0 || strconv.Itoa(id) != c.Param("tenant") || c.Param("site") != "" {
		return nil, access.Scope{}, tagFailure(c, inventory.ErrNotFound)
	}
	scope := access.Scope{TenantID: id}
	p, err := h.currentPrincipal(c)
	if err != nil {
		return nil, scope, err
	}
	capability, ok := tagCapability(c.Request().Method, c.Path())
	if !ok || !p.Can(capability, scope) {
		return nil, scope, tagFailure(c, access.ErrDenied)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if info.TenantID != c.Param("tenant") {
		return nil, scope, tagFailure(c, inventory.ErrNotFound)
	}
	info.SiteID = "-1"
	visible := info.Tenants[:0]
	for _, tenant := range info.Tenants {
		if p.Can(access.ReadDevices, access.Scope{TenantID: tenant.ID}) {
			visible = append(visible, tenant)
		}
	}
	info.Tenants = visible
	return info, scope, nil
}

func tagID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != raw {
		return 0, inventory.ErrTagInvalid
	}
	return id, nil
}

func (h *Handler) TagManager(c echo.Context) error {
	if c.Request().Method == http.MethodPost {
		return h.SaveOrganizationTag(c)
	}
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, scope, err := h.tagInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopReportFilter(c.Request().URL.RawQuery)
	if err != nil {
		return tagFailure(c, err)
	}
	page, err := inventory.ListOrganizationTags(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, filter)
	if err != nil {
		return tagFailure(c, err)
	}
	path := mdm_views.OrganizationTagsPath(info)
	paging := mdm_views.DevicePagination{}
	if filter.After > 0 {
		paging.First = path + "?" + url.Values{"q": {filter.Search}}.Encode()
	}
	if page.Next > 0 {
		paging.Next = path + "?" + url.Values{"q": {filter.Search}, "after": {strconv.FormatInt(page.Next, 10)}}.Encode()
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, mdm_views.OrganizationTags(c, info, page, filter, paging))
}

func (h *Handler) OrganizationTag(c echo.Context) error {
	info, scope, err := h.tagInfo(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return tagFailure(c, inventory.ErrTagInvalid)
	}
	id, err := tagID(c.Param("tag"))
	if err != nil {
		return tagFailure(c, err)
	}
	tag, err := inventory.ReadOrganizationTag(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id)
	if err != nil {
		return tagFailure(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, mdm_views.OrganizationTag(c, info, tag))
}

func (h *Handler) SaveOrganizationTag(c echo.Context) error {
	info, scope, err := h.tagInfo(c)
	if err != nil {
		return err
	}
	f, err := deviceManagementForm(c, "organization_tags.invalid", []string{"csrf", "name", "description", "color", "revision"})
	if err != nil {
		return err
	}
	var id int64
	if c.Param("tag") != "" {
		id, err = tagID(c.Param("tag"))
		if err != nil {
			return tagFailure(c, err)
		}
	}
	tag, err := inventory.SaveOrganizationTag(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, f.Get("revision"), inventory.TagDefinition{Name: f.Get("name"), Description: f.Get("description"), Color: f.Get("color")})
	if err != nil {
		return tagFailure(c, err)
	}
	return c.Redirect(http.StatusSeeOther, mdm_views.OrganizationTagsPath(info)+"/"+strconv.FormatInt(tag.ID, 10))
}

func (h *Handler) DeleteOrganizationTag(c echo.Context) error {
	info, scope, err := h.tagInfo(c)
	if err != nil {
		return err
	}
	f, err := deviceManagementForm(c, "organization_tags.invalid", []string{"csrf", "revision", "confirm"})
	if err != nil {
		return err
	}
	if f.Get("confirm") != "delete" {
		return tagFailure(c, inventory.ErrTagInvalid)
	}
	id, err := tagID(c.Param("tag"))
	if err != nil {
		return tagFailure(c, err)
	}
	if err = inventory.DeleteOrganizationTag(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, f.Get("revision")); err != nil {
		return tagFailure(c, err)
	}
	return c.Redirect(http.StatusSeeOther, mdm_views.OrganizationTagsPath(info))
}
