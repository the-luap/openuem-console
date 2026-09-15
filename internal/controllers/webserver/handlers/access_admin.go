package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/access_views"
)

func (h *Handler) RegisterAccess(e *echo.Echo) {
	e.GET("/admin/oidc-accounts", h.OIDCAccountBindings, h.IsAuthenticated)
	e.POST("/admin/oidc-accounts", h.ChangeOIDCAccountBinding, h.IsAuthenticated, h.AppleCSRF)
	e.GET("/admin/access", h.AccessPermissions, h.IsAuthenticated)
	e.POST("/admin/access", h.SaveAccessPermissions, h.IsAuthenticated, h.AppleCSRF)
	e.GET("/admin/access/audit", h.AccessAudit, h.IsAuthenticated)
}

func accessFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Permission denied")
	case errors.Is(err, access.ErrConflict):
		return echo.NewHTTPError(409, err.Error())
	case errors.Is(err, access.ErrLastAdministrator):
		return echo.NewHTTPError(409, err.Error())
	default:
		return echo.NewHTTPError(400, "Unable to save permissions. Check the user, role and organization/site selection.")
	}
}

func (h *Handler) AccessPermissions(c echo.Context) error {
	actor, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	if !actor.IsAdministrator() {
		return echo.NewHTTPError(403, "Server administrator required")
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	subject := c.QueryParam("user_id")
	if subject == "" {
		subject = actor.UserID
	}
	target, err := h.Access.Principal(c.Request().Context(), subject)
	if err != nil {
		return echo.NewHTTPError(404, "User not found")
	}
	person, err := h.Model.GetUserById(subject)
	if err != nil {
		return echo.NewHTTPError(404, "User not found")
	}
	sites := []access_views.SiteOption{}
	for _, tenant := range info.Tenants {
		tenantSites, err := h.Model.GetAssociatedSites(tenant)
		if err != nil {
			return err
		}
		for _, site := range tenantSites {
			sites = append(sites, access_views.SiteOption{ID: site.ID, TenantID: tenant.ID, Name: site.Description})
		}
	}
	return renderApple(c, access_views.Permissions(c, info, target, person.Name, sites))
}

func (h *Handler) SaveAccessPermissions(c echo.Context) error {
	actor, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	if !actor.IsAdministrator() {
		return echo.NewHTTPError(403, "Server administrator required")
	}
	if c.FormValue("confirm") != "yes" {
		return echo.NewHTTPError(400, "Confirm the permission change for this user")
	}
	expected, err := strconv.Atoi(c.FormValue("revision"))
	if err != nil || expected < 0 {
		return echo.NewHTTPError(400, "Invalid permission revision")
	}
	subject := c.FormValue("user_id")
	target, err := h.Access.Principal(c.Request().Context(), subject)
	if err != nil {
		return echo.NewHTTPError(404, "User not found")
	}
	if target.Revision != expected {
		return accessFailure(access.ErrConflict)
	}
	tenant, err := strconv.Atoi(c.FormValue("tenant_id"))
	if err != nil || tenant < 0 {
		return echo.NewHTTPError(400, "Select an organization scope")
	}
	site, err := strconv.Atoi(c.FormValue("site_id"))
	if err != nil || site < 0 {
		return echo.NewHTTPError(400, "Select a site scope")
	}
	scope := access.Scope{TenantID: tenant, SiteID: site}
	next := []access.Grant{}
	for _, grant := range target.Grants {
		if grant.Scope != scope {
			next = append(next, grant)
		}
	}
	switch c.FormValue("action") {
	case "grant":
		next = append(next, access.Grant{Role: access.Role(c.FormValue("role")), Scope: scope})
	case "revoke":
	default:
		return echo.NewHTTPError(400, "Unknown permission action")
	}
	if err = h.Access.ReplaceGrants(c.Request().Context(), actor.UserID, subject, expected, next); err != nil {
		return accessFailure(err)
	}
	return c.Redirect(http.StatusSeeOther, "/admin/access?user_id="+url.QueryEscape(subject))
}

func (h *Handler) AccessAudit(c echo.Context) error {
	actor, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	before := int64(0)
	if value := c.QueryParam("before"); value != "" {
		before, err = strconv.ParseInt(value, 10, 64)
		if err != nil || before < 0 {
			return echo.NewHTTPError(400, "Invalid audit cursor")
		}
	}
	events, err := h.Access.Audit(c.Request().Context(), actor.UserID, before)
	if err != nil {
		return accessFailure(err)
	}
	return renderApple(c, access_views.Audit(c, info, events))
}
