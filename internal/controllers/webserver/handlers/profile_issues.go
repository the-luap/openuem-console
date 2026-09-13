package handlers

import (
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func (h *Handler) ProfileIssues(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileReadFailure(err)
	}
	values, err := profileReadQuery(c, false)
	if err != nil {
		return profileReadFailure(err)
	}
	page, err := profilePage(values, "page", 1, 1000000)
	if err != nil {
		return profileReadFailure(err)
	}
	size, err := profilePage(values, "pageSize", 25, 100)
	if err != nil {
		return profileReadFailure(err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileReadFailure(err)
	}
	result, err := inventory.ReadLegacyProfileIssues(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, page, size)
	if err != nil {
		return profileReadFailure(err)
	}
	return RenderView(c, profiles_views.ProfilesIndex("| Profile reports", profiles_views.ProfilesIssues(c, result, info), info))
}

func profileIssueReportQuery(c echo.Context) (url.Values, error) {
	r := c.Request()
	if r.Method != http.MethodGet || r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 512 {
		return nil, inventory.ErrProfileInvalid
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, inventory.ErrProfileInvalid
	}
	for key, v := range values {
		if len(v) != 1 || len(v[0]) > 16 {
			return nil, inventory.ErrProfileInvalid
		}
		switch key {
		case "page", "issuePage", "issuePageSize":
		default:
			return nil, inventory.ErrProfileInvalid
		}
	}
	return values, nil
}

func (h *Handler) ProfileIssueReports(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileReadFailure(err)
	}
	issue, err := tagID(c.Param("issue"))
	if err != nil {
		return profileReadFailure(err)
	}
	values, err := profileIssueReportQuery(c)
	if err != nil {
		return profileReadFailure(err)
	}
	page, err := profilePage(values, "page", 1, 1000000)
	if err != nil {
		return profileReadFailure(err)
	}
	sourcePage, err := profilePage(values, "issuePage", 1, 1000000)
	if err != nil {
		return profileReadFailure(err)
	}
	sourceSize, err := profilePage(values, "issuePageSize", 25, 100)
	if err != nil {
		return profileReadFailure(err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileReadFailure(err)
	}
	result, err := inventory.ReadLegacyProfileIssueReports(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, issue, page)
	if err != nil {
		return profileReadFailure(err)
	}
	return RenderView(c, profiles_views.ProfilesIndex("| Task reports", profiles_views.ProfileIssueReports(c, result, sourcePage, sourceSize, info), info))
}
