package handlers

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func profileReadFailure(err error) error {
	status, message := http.StatusServiceUnavailable, "The profile could not be read. Reload and try again."
	switch {
	case errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, message = http.StatusBadRequest, "Invalid profile read request."
	case errors.Is(err, inventory.ErrNotFound):
		status, message = http.StatusNotFound, "Profile not found in the selected scope."
	case errors.Is(err, access.ErrDenied):
		status, message = http.StatusForbidden, "Only current server administrators can read legacy profiles."
	}
	return echo.NewHTTPError(status, message)
}

func profileEditorRedirect(c echo.Context, info *partials.CommonInfo, id int64) error {
	c.Response().Header().Set("HX-Redirect", partials.GetNavigationUrl(info, fmt.Sprintf("/profiles/%d", id)))
	return c.NoContent(http.StatusNoContent)
}

func profileReadQuery(c echo.Context, tags bool) (url.Values, error) {
	r := c.Request()
	if r.Method != http.MethodGet || r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 8192 {
		return nil, inventory.ErrProfileInvalid
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, inventory.ErrProfileInvalid
	}
	for key, v := range values {
		if len(v) != 1 {
			return nil, inventory.ErrProfileInvalid
		}
		if tags {
			if key != "page" && key != "q" {
				return nil, inventory.ErrProfileInvalid
			}
		} else {
			switch key {
			case "page", "pageSize", "sortBy", "sortOrder", "currentSortBy":
			default:
				return nil, inventory.ErrProfileInvalid
			}
		}
		limit := 128
		if key == "q" {
			limit = 256
		}
		if len(v[0]) > limit || !utf8.ValidString(v[0]) || strings.ContainsRune(v[0], 0) {
			return nil, inventory.ErrProfileInvalid
		}
	}
	return values, nil
}

func profilePage(values url.Values, key string, fallback, limit int) (int, error) {
	raw, present := values[key]
	if !present {
		return fallback, nil
	}
	if len(raw) != 1 {
		return 0, inventory.ErrProfileInvalid
	}
	n, err := strconv.Atoi(raw[0])
	if err != nil || n <= 0 || n > limit || strconv.Itoa(n) != raw[0] {
		return 0, inventory.ErrProfileInvalid
	}
	return n, nil
}

func (h *Handler) EditProfile(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileReadFailure(err)
	}
	values, err := profileReadQuery(c, false)
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
	defaultSize, err := h.Model.GetDefaultItemsPerPage()
	if err != nil || defaultSize <= 0 || defaultSize > 1000 {
		defaultSize = 5
	}
	page, err := profilePage(values, "page", 1, 1000000)
	if err != nil {
		return profileReadFailure(err)
	}
	size, err := profilePage(values, "pageSize", defaultSize, 1000)
	if err != nil {
		return profileReadFailure(err)
	}
	review, err := inventory.ReadProfileEditor(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, page, size, inventory.ProfileTagQuery{Page: 1})
	if err != nil {
		return profileReadFailure(err)
	}
	p := partials.PaginationAndSort{CurrentPage: review.Tasks.Page, PageSize: review.Tasks.PageSize, NItems: review.Tasks.Total}
	return RenderView(c, profiles_views.ProfilesIndex("| Profiles", profiles_views.EditProfile(c, p, review, defaultSize, info), info))
}

func (h *Handler) ReadProfileTags(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileReadFailure(err)
	}
	values, err := profileReadQuery(c, true)
	if err != nil {
		return profileReadFailure(inventory.ErrTagInvalid)
	}
	page, err := profilePage(values, "page", 1, 1000000)
	if err != nil {
		return profileReadFailure(inventory.ErrTagInvalid)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileReadFailure(err)
	}
	panel, err := inventory.ReadProfileTagPanel(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, inventory.ProfileTagQuery{Page: page, Search: values.Get("q")})
	if err != nil {
		return profileReadFailure(err)
	}
	return RenderView(c, profiles_views.ProfileTagPanelView(panel, info, ""))
}

// DELETE parameters are in the query, matching native HTMX forms. POST accepts
// only its bounded body, avoiding precedence between duplicate query/body IDs.
func profileTagForm(c echo.Context) (int64, inventory.ProfileTagQuery, error) {
	r := c.Request()
	invalid := func() (int64, inventory.ProfileTagQuery, error) {
		return 0, inventory.ProfileTagQuery{}, inventory.ErrTagInvalid
	}
	if r.Header.Get("Content-Encoding") != "" {
		return invalid()
	}
	var values url.Values
	if r.Method == http.MethodDelete {
		if r.ContentLength != 0 || len(r.URL.RawQuery) > 8192 {
			return invalid()
		}
		var err error
		values, err = url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return invalid()
		}
	} else if r.Method == http.MethodPost {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 8192 {
			return invalid()
		}
		r.Body = http.MaxBytesReader(c.Response(), r.Body, 8192)
		if r.ParseForm() != nil || len(r.PostForm.Encode()) > 8192 {
			return invalid()
		}
		values = r.PostForm
	} else {
		return invalid()
	}
	for key, v := range values {
		if len(v) != 1 {
			return invalid()
		}
		limit := 128
		switch key {
		case "agentId", "tagId", "page", "pageSize", "sortBy", "sortOrder", "csrf":
		case "q":
			limit = 256
		default:
			return invalid()
		}
		if len(v[0]) > limit || !utf8.ValidString(v[0]) || strings.ContainsRune(v[0], 0) {
			return invalid()
		}
	}
	if values.Get("agentId") != c.Param("uuid") {
		return invalid()
	}
	tag, err := tagID(values.Get("tagId"))
	if err != nil {
		return invalid()
	}
	page, err := profilePage(values, "page", 1, 1000000)
	if err != nil {
		return invalid()
	}
	if _, err = profilePage(values, "pageSize", 5, 1000); err != nil {
		return invalid()
	}
	return tag, inventory.ProfileTagQuery{Page: page, Search: values.Get("q")}, nil
}
