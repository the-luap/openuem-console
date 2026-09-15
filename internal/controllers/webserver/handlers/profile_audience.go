package handlers

import (
	"errors"
	"net/http"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func profileAudienceFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "profile_audience."+key))
}

func (h *Handler) SetProfileAsGlobal(c echo.Context) error {
	return h.promoteProfileAudience(c, true)
}

func (h *Handler) SetProfileAsTenantProfile(c echo.Context) error {
	return h.promoteProfileAudience(c, false)
}

func (h *Handler) promoteProfileAudience(c echo.Context, global bool) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileAudienceFailure(c, err)
	}
	if err = profileStatusForm(c); err != nil {
		return profileAudienceFailure(c, inventory.ErrProfileInvalid)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileAudienceFailure(c, err)
	}
	if err = inventory.PromoteProfileAudience(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, global); err != nil {
		return profileAudienceFailure(c, err)
	}
	message := "profiles.set_tenant_success"
	if global {
		message = "profiles.set_global_success"
	}
	return h.Profiles(c, i18n.T(c.Request().Context(), message))
}
