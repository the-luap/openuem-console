package handlers

import (
	"errors"
	"net/http"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func profileDeletionFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "profile_deletion."+key))
}

func (h *Handler) ConfirmDeleteProfile(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileDeletionFailure(c, err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileDeletionFailure(c, err)
	}
	review, err := inventory.ReviewProfileDeletion(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id)
	if err != nil {
		return profileDeletionFailure(c, err)
	}
	return RenderView(c, profiles_views.ProfilesIndex("| Delete profile", profiles_views.ProfileDeletion(c, review, info), info))
}

// Bundled HTMX sends this route-only DELETE without a body. Empty requests do
// not require a content type; the production middleware verifies the CSRF header.
func profileDeletionForm(c echo.Context) error {
	r := c.Request()
	if r.ContentLength != 0 || len(r.PostForm) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Encoding") != "" {
		return profileDeletionFailure(c, inventory.ErrProfileInvalid)
	}
	return nil
}

func (h *Handler) DeleteLegacyProfile(c echo.Context) error {
	if c.Request().Method != http.MethodDelete {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileDeletionFailure(c, err)
	}
	if err = profileDeletionForm(c); err != nil {
		return err
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileDeletionFailure(c, err)
	}
	if err = inventory.DeleteLegacyProfile(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id); err != nil {
		return profileDeletionFailure(c, err)
	}
	return h.Profiles(c, i18n.T(c.Request().Context(), "profiles.edit.deleted"))
}
