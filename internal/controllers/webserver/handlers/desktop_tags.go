package handlers

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func desktopTagFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "desktop_tags."+key))
}

// HTMX uses a POST form to add and DELETE query parameters to remove a tag.
// Never merge the two sources when deciding which membership to change.
func tagMembershipForm(c echo.Context) (device string, id int64, change bool, err error) {
	r := c.Request()
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		return
	}
	invalid := func() (string, int64, bool, error) { return "", 0, false, inventory.ErrTagInvalid }
	if len(r.URL.RawQuery) > 64<<10 || r.ContentLength > 64<<10 {
		return invalid()
	}
	query, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		return invalid()
	}
	var values url.Values
	if r.Method == http.MethodPost {
		mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/x-www-form-urlencoded" {
			return invalid()
		}
		r.Body = http.MaxBytesReader(c.Response(), r.Body, 64<<10)
		if r.ParseForm() != nil || len(query["tagId"]) != 0 || len(query["agentId"]) != 0 {
			return invalid()
		}
		values = r.PostForm
	} else {
		// DELETE forms have no body, including no second hidden identity source.
		if r.ContentLength != 0 || len(r.PostForm) != 0 {
			return invalid()
		}
		values = query
	}
	if r.Method == http.MethodPost && len(values["tagId"]) == 0 && len(values["agentId"]) == 0 {
		return // Ordinary pagination/filter POST; it does not change tags.
	}
	if len(values["tagId"]) != 1 || len(values["agentId"]) != 1 || !inventory.ValidReportDeviceID(values.Get("agentId")) {
		return invalid()
	}
	id, err = tagID(values.Get("tagId"))
	if err != nil {
		return invalid()
	}
	return values.Get("agentId"), id, true, nil
}

func (h *Handler) changeDesktopTag(c echo.Context, info *partials.CommonInfo, device string, id int64, assigned bool) error {
	tenant, err := strconv.Atoi(info.TenantID)
	if err != nil || tenant <= 0 || strconv.Itoa(tenant) != info.TenantID {
		return desktopTagFailure(c, inventory.ErrNotFound)
	}
	site, err := strconv.Atoi(info.SiteID)
	if err != nil || site < -1 || strconv.Itoa(site) != info.SiteID {
		return desktopTagFailure(c, inventory.ErrNotFound)
	}
	if site == -1 {
		site = 0
	}
	if err = inventory.ChangeDesktopTag(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, access.Scope{TenantID: tenant, SiteID: site}, device, id, assigned); err != nil {
		return desktopTagFailure(c, err)
	}
	return nil
}

func (h *Handler) applyDesktopTagForm(c echo.Context, info *partials.CommonInfo) error {
	device, id, change, err := tagMembershipForm(c)
	if err != nil {
		return desktopTagFailure(c, err)
	}
	if !change {
		return nil
	}
	return h.changeDesktopTag(c, info, device, id, c.Request().Method == http.MethodPost)
}
