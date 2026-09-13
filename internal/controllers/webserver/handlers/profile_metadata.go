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

func profileMetadataFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "profile_metadata."+key))
}

func profileMetadataForm(c echo.Context) (inventory.ProfileMetadata, error) {
	definition, err := profileDefinitionForm(c, false)
	if err != nil {
		return definition, profileMetadataFailure(c, err)
	}
	return definition, nil
}

func profileDefinitionForm(c echo.Context, creation bool) (inventory.ProfileMetadata, error) {
	r := c.Request()
	invalid := func() (inventory.ProfileMetadata, error) {
		return inventory.ProfileMetadata{}, inventory.ErrProfileInvalid
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 8192 {
		return invalid()
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 8192)
	if r.ParseForm() != nil || len(r.PostForm.Encode()) > 8192 {
		return invalid()
	}
	for key, values := range r.PostForm {
		if len(values) != 1 {
			return invalid()
		}
		switch key {
		case "profile-description":
		case "profile-assignment":
			if creation {
				return invalid()
			}
		case "csrf", "page", "pageSize", "sortBy", "sortOrder":
			if len(values[0]) > 128 {
				return invalid()
			}
		default:
			return invalid()
		}
	}
	definition := inventory.ProfileMetadata{Name: r.PostForm.Get("profile-description"), Assignment: r.PostForm.Get("profile-assignment")}
	if creation {
		definition.Assignment = "dontApplyToAll"
	}
	if !definition.Valid() {
		return invalid()
	}
	return definition, nil
}

func (h *Handler) SaveProfileMetadata(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileMetadataFailure(c, err)
	}
	definition, err := profileMetadataForm(c)
	if err != nil {
		return err
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileMetadataFailure(c, err)
	}
	if err = inventory.SaveProfileMetadata(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, definition); err != nil {
		return profileMetadataFailure(c, err)
	}
	return h.EditProfile(c, http.MethodGet, c.Param("uuid"), i18n.T(c.Request().Context(), "profiles.edit.saved"))
}
