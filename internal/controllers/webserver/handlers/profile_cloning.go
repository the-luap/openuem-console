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
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func profileCloningFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	case errors.Is(err, inventory.ErrProfileCloneProviderScope):
		status, key = http.StatusConflict, "provider_scope"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "profile_cloning."+key))
}

func profileCloneValues(c echo.Context, sitesOnly bool) (url.Values, access.Scope, error) {
	r := c.Request()
	invalid := func() (url.Values, access.Scope, error) { return nil, access.Scope{}, inventory.ErrProfileInvalid }
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
		case "tenant-id", "csrf":
			if len(values[0]) > 128 {
				return invalid()
			}
		case "profile-description", "site-id":
			if sitesOnly {
				return invalid()
			}
		default:
			return invalid()
		}
	}
	// An explicit empty organization means global; a missing field is invalid.
	if !r.PostForm.Has("tenant-id") {
		return invalid()
	}
	scope := access.Scope{}
	for key, target := range map[string]*int{"tenant-id": &scope.TenantID, "site-id": &scope.SiteID} {
		if raw := r.PostForm.Get(key); raw != "" {
			id, err := strconv.Atoi(raw)
			if err != nil || id <= 0 || strconv.Itoa(id) != raw {
				return invalid()
			}
			*target = id
		}
	}
	if scope.TenantID == 0 && scope.SiteID != 0 {
		return invalid()
	}
	if !sitesOnly && !(inventory.ProfileMetadata{Name: r.PostForm.Get("profile-description"), Assignment: "dontApplyToAll"}).Valid() {
		return invalid()
	}
	return r.PostForm, scope, nil
}

func (h *Handler) CloneProfile(c echo.Context) error {
	method := c.Request().Method
	if method != http.MethodGet && method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return profileCloningFailure(c, err)
	}
	var values url.Values
	var destination access.Scope
	if method == http.MethodPost {
		values, destination, err = profileCloneValues(c, false)
		if err != nil {
			return profileCloningFailure(c, err)
		}
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	source, err := legacyProfileScope(info)
	if err != nil {
		return profileCloningFailure(c, err)
	}
	if method == http.MethodPost {
		newID, err := inventory.CloneLegacyProfile(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, source, destination, id, values.Get("profile-description"))
		if err != nil {
			return profileCloningFailure(c, err)
		}
		// Navigate to the destination, where the new unassigned profile is visible.
		path := "/profiles/" + strconv.FormatInt(newID, 10)
		if destination.SiteID != 0 {
			path = "/site/" + strconv.Itoa(destination.SiteID) + path
		}
		if destination.TenantID != 0 {
			path = "/tenant/" + strconv.Itoa(destination.TenantID) + path
		}
		c.Response().Header().Set("HX-Redirect", path)
		return c.NoContent(http.StatusOK)
	}
	p, err := inventory.ReviewProfileClone(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, source, id)
	if err != nil {
		return profileCloningFailure(c, err)
	}
	tenants, err := h.Model.GetTenants()
	if err != nil {
		return profileCloningFailure(c, err)
	}
	return RenderView(c, profiles_views.ProfilesIndex("| Profiles", profiles_views.CloneProfile(c, p, tenants, info), info))
}

func (h *Handler) GetTenantSites(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	_, scope, err := profileCloneValues(c, true)
	if err != nil {
		return profileCloningFailure(c, err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	sites, err := inventory.ProfileCloneSites(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope)
	if err != nil {
		return profileCloningFailure(c, err)
	}
	if scope.TenantID == 0 {
		return RenderView(c, profiles_views.EmptySitesSelect())
	}
	return RenderView(c, profiles_views.SitesSelect(sites))
}
