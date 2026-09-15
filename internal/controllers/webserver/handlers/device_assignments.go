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
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func assignmentInteger(value string) (int, bool) {
	n, err := strconv.Atoi(value)
	return n, err == nil && n > 0 && strconv.Itoa(n) == value
}

func assignmentForm(c echo.Context, field string) (string, error) {
	if c.Request().URL.RawQuery != "" || c.Request().ParseForm() != nil {
		return "", echo.NewHTTPError(400, i18n.T(c.Request().Context(), "device_assignment.invalid"))
	}
	form := c.Request().PostForm
	for key, values := range form {
		if len(values) != 1 || key != "csrf" && key != field {
			return "", echo.NewHTTPError(400, i18n.T(c.Request().Context(), "device_assignment.invalid"))
		}
	}
	if len(form[field]) != 1 {
		return "", echo.NewHTTPError(400, i18n.T(c.Request().Context(), "device_assignment.invalid"))
	}
	return form.Get(field), nil
}

func assignmentFailure(c echo.Context, err error) error {
	code, key := 503, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		code, key = 404, "not_found"
	case errors.Is(err, access.ErrDenied):
		code, key = 403, "denied"
	case errors.Is(err, inventory.ErrAssignmentInvalid):
		code, key = 400, "invalid"
	case errors.Is(err, inventory.ErrAssignmentChanged):
		code, key = 409, "changed"
	case errors.Is(err, inventory.ErrAssignmentIdentity):
		code, key = 409, "individual"
	}
	return echo.NewHTTPError(code, i18n.T(c.Request().Context(), "device_assignment."+key))
}

func (h *Handler) DesktopAssignment(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, selected, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	if len(c.Request().URL.RawQuery) > 16<<10 {
		return assignmentFailure(c, inventory.ErrAssignmentInvalid)
	}
	query, err := url.ParseQuery(c.Request().URL.RawQuery)
	if err != nil {
		return assignmentFailure(c, inventory.ErrAssignmentInvalid)
	}
	for key, values := range query {
		if len(values) != 1 || key != "q" && key != "after" {
			return assignmentFailure(c, inventory.ErrAssignmentInvalid)
		}
	}
	after := 0
	if value := query.Get("after"); value != "" {
		var ok bool
		after, ok = assignmentInteger(value)
		if !ok {
			return assignmentFailure(c, inventory.ErrAssignmentInvalid)
		}
	}
	page, err := inventory.ReadDeviceAssignmentChoices(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}, c.Param("uuid"), query.Get("q"), after)
	if err != nil {
		return assignmentFailure(c, err)
	}
	return renderApple(c, desktop_views.AssignmentChoices(c, info, page, query.Get("q"), after))
}

func (h *Handler) DesktopAssignmentReview(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, selected, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	value, err := assignmentForm(c, "destination_site")
	if err != nil {
		return err
	}
	destination, ok := assignmentInteger(value)
	if !ok {
		return assignmentFailure(c, inventory.ErrAssignmentInvalid)
	}
	r, err := inventory.ReviewDeviceAssignment(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}, c.Param("uuid"), destination)
	if err != nil {
		return assignmentFailure(c, err)
	}
	return c.Redirect(http.StatusSeeOther, partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(r.DeviceID)+"/assignment/"+r.ID))
}

func (h *Handler) DesktopAssignmentReceipt(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, selected, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	commit := c.Request().Method == http.MethodPost
	if commit {
		value, err := assignmentForm(c, "confirm")
		if err != nil {
			return err
		}
		if value != "yes" {
			return assignmentFailure(c, inventory.ErrAssignmentInvalid)
		}
	} else if c.Request().URL.RawQuery != "" {
		return assignmentFailure(c, inventory.ErrAssignmentInvalid)
	}
	r, err := inventory.DeviceAssignmentReceipt(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}, c.Param("uuid"), c.Param("review"), commit)
	if errors.Is(err, inventory.ErrAssignmentChanged) || errors.Is(err, inventory.ErrAssignmentIdentity) {
		c.Response().Status = http.StatusConflict
		key := "device_assignment.changed"
		if errors.Is(err, inventory.ErrAssignmentIdentity) {
			key = "device_assignment.individual"
		}
		return renderApple(c, desktop_views.AssignmentConflict(c, info, c.Param("uuid"), i18n.T(c.Request().Context(), key)))
	}
	if err != nil {
		return assignmentFailure(c, err)
	}
	if commit {
		return c.Redirect(http.StatusSeeOther, partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(r.DeviceID)+"/assignment/"+r.ID))
	}
	return renderApple(c, desktop_views.AssignmentReview(c, info, r))
}
