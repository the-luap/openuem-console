package handlers

import (
	"errors"
	"mime"
	"net/http"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func profileStatusFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "profile_status."+key))
}

// Status and target come only from the registered route. The body may preserve
// list context; the production CSRF middleware validates header or form tokens.
func profileStatusForm(c echo.Context) error {
	r := c.Request()
	invalid := func() error { return profileStatusFailure(c, inventory.ErrProfileInvalid) }
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 8192 {
		return invalid()
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 8192)
	if r.ParseForm() != nil || len(r.PostForm.Encode()) > 8192 {
		return invalid()
	}
	for key, values := range r.PostForm {
		if len(values) != 1 || len(values[0]) > 128 {
			return invalid()
		}
		switch key {
		case "csrf", "page", "pageSize", "sortBy", "sortOrder":
		default:
			return invalid()
		}
	}
	return nil
}

func (h *Handler) EnableProfile(c echo.Context, enable bool) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileStatusFailure(c, err)
	}
	if err = profileStatusForm(c); err != nil {
		return err
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileStatusFailure(c, err)
	}
	if err = inventory.SetProfileEnabled(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, enable); err != nil {
		return profileStatusFailure(c, err)
	}
	message := "profiles.profile_disabled"
	if enable {
		message = "profiles.profile_enabled"
	}
	return h.Profiles(c, i18n.T(c.Request().Context(), message))
}
