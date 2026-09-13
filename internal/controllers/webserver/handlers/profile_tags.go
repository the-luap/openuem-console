package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func profileTagFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "profile_tags."+key))
}

func legacyProfileScope(info *partials.CommonInfo) (access.Scope, error) {
	if info.TenantID == "-1" && info.SiteID == "-1" {
		return access.Scope{}, nil
	}
	tenant, err := strconv.Atoi(info.TenantID)
	if err != nil || tenant <= 0 || strconv.Itoa(tenant) != info.TenantID {
		return access.Scope{}, inventory.ErrNotFound
	}
	site := 0
	if info.SiteID != "-1" {
		site, err = strconv.Atoi(info.SiteID)
		if err != nil || site <= 0 || strconv.Itoa(site) != info.SiteID {
			return access.Scope{}, inventory.ErrNotFound
		}
	}
	return access.Scope{TenantID: tenant, SiteID: site}, nil
}

func (h *Handler) ProfileTags(c echo.Context) error {
	if c.Request().Method != http.MethodPost && c.Request().Method != http.MethodDelete {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	profile, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileTagFailure(c, err)
	}
	tag, query, err := profileTagForm(c)
	if err != nil {
		return profileTagFailure(c, inventory.ErrTagInvalid)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return profileTagFailure(c, err)
	}
	assigned := c.Request().Method == http.MethodPost
	if c.Request().Header.Get("HX-Target") != "profile-tag-panel" {
		if err = inventory.ChangeProfileTag(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, profile, tag, assigned); err != nil {
			return profileTagFailure(c, err)
		}
		return profileEditorRedirect(c, info, profile)
	}
	panel, err := inventory.ChangeProfileTagAndRead(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, profile, tag, assigned, query)
	if err != nil {
		return profileTagFailure(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	message := "profiles.edit.tag_removed"
	if assigned {
		message = "profiles.edit.tag_added"
	}
	return RenderView(c, profiles_views.ProfileTagMutation(panel, info, i18n.T(c.Request().Context(), message)))
}
