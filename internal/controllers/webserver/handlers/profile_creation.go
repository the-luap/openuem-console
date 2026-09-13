package handlers

import (
	"errors"
	"net/http"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func profileCreationFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrProfileInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "profile_creation."+key))
}

func (h *Handler) CreateLegacyProfile(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	definition, err := profileDefinitionForm(c, true)
	if err != nil {
		return profileCreationFailure(c, err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileCreationFailure(c, err)
	}
	id, err := inventory.CreateLegacyProfile(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, definition.Name)
	if err != nil {
		return profileCreationFailure(c, err)
	}
	return profileEditorRedirect(c, info, id)
}
