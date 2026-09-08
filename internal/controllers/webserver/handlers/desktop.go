package handlers

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func desktopCapability(method, path string) (access.Capability, bool) {
	route := appleRoute(path)
	if method == http.MethodGet && route == "/desktop/enrollment" {
		return access.ReadDevices, true
	}
	if method == http.MethodPost {
		switch route {
		case "/desktop/setup":
			return access.ManageCertificates, true
		case "/desktop/invitations/:id/revoke":
			return access.EnrollDevices, true
		case "/desktop/identities/:id/revoke":
			return access.RevokeDevices, true
		}
	}
	return "", false
}

func (h *Handler) RegisterDesktop(e *echo.Echo) {
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		g := e.Group(prefix, h.IsAuthenticated, h.AppleCSRF)
		g.GET("/desktop/enrollment", h.DesktopEnrollment)
		g.POST("/desktop/setup", h.DesktopAuthority)
		g.POST("/desktop/invitations/:id/revoke", h.DesktopRevokeInvitation)
		g.POST("/desktop/identities/:id/revoke", h.DesktopRevokeIdentity)
	}
}

func (h *Handler) desktopInfo(c echo.Context) (*partials.CommonInfo, registry.Scope, error) {
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return nil, registry.Scope{}, err
	}
	tenant, err := strconv.Atoi(info.TenantID)
	if err != nil || tenant <= 0 {
		return nil, registry.Scope{}, echo.NewHTTPError(400, "Select an organization")
	}
	site, err := strconv.Atoi(info.SiteID)
	if err != nil {
		return nil, registry.Scope{}, echo.NewHTTPError(400, "Select a site")
	}
	if site == -1 {
		site = 0
	}
	if site < 0 {
		return nil, registry.Scope{}, echo.NewHTTPError(404, "Site not found")
	}
	if requested := c.Param("tenant"); requested != "" && requested != info.TenantID {
		return nil, registry.Scope{}, echo.NewHTTPError(404, "Organization not found")
	}
	if requested := c.Param("site"); requested != "" && requested != info.SiteID {
		return nil, registry.Scope{}, echo.NewHTTPError(404, "Site not found")
	}
	principal, err := h.currentPrincipal(c)
	if err != nil {
		return nil, registry.Scope{}, err
	}
	capability, ok := desktopCapability(c.Request().Method, c.Path())
	requestedScope := access.Scope{TenantID: tenant, SiteID: site}
	if capability == access.ManageCertificates {
		requestedScope.SiteID = 0
	}
	if !ok || !principal.Can(capability, requestedScope) {
		return nil, registry.Scope{}, echo.NewHTTPError(403, "Permission denied for this organization or site")
	}
	return info, registry.Scope{TenantID: tenant, SiteID: site}, nil
}

func desktopFailure(err error) error {
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return echo.NewHTTPError(404, "Desktop enrollment resource not found")
	case errors.Is(err, registry.ErrDenied):
		return echo.NewHTTPError(403, "This enrollment action is not permitted")
	case errors.Is(err, registry.ErrInvalid):
		return echo.NewHTTPError(400, "Invalid enrollment settings or conflicting existing configuration")
	default:
		return echo.NewHTTPError(503, "Desktop enrollment is unavailable. Try again later.")
	}
}

func (h *Handler) DesktopEnrollment(c echo.Context) error {
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	data := desktop_views.EnrollmentData{SetupError: h.DesktopSetupError, PublicOrigin: h.PublicOrigin}
	for _, tenant := range info.Tenants {
		if strconv.Itoa(tenant.ID) == info.TenantID {
			data.Organization = tenant.Description
		}
	}
	if h.Desktop != nil {
		actor := h.appleActor(c)
		data.Authority, err = h.Desktop.Authority(c.Request().Context(), scope, actor)
		if err != nil && !errors.Is(err, registry.ErrNotFound) {
			return desktopFailure(err)
		}
		data.Invitations, err = h.Desktop.Invitations(c.Request().Context(), scope, actor, c.QueryParam("invitations_before"), 25)
		if err != nil {
			return desktopFailure(err)
		}
		data.Identities, err = h.Desktop.Identities(c.Request().Context(), scope, actor, c.QueryParam("identities_before"), 25)
		if err != nil {
			return desktopFailure(err)
		}
	} else if data.SetupError == "" {
		data.SetupError = "Desktop enrollment is not available. Contact a server administrator."
	}
	return renderApple(c, desktop_views.Enrollment(c, info, data))
}

func (h *Handler) DesktopAuthority(c echo.Context) error {
	defer func() {
		if c.Request().MultipartForm != nil {
			_ = c.Request().MultipartForm.RemoveAll()
		}
	}()
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	if h.Desktop == nil {
		return desktopFailure(registry.ErrUnavailable)
	}
	origin, err := gateway.ParseOrigin(h.PublicOrigin)
	if err != nil {
		return echo.NewHTTPError(503, "A server administrator must configure the public enrollment address before setup.")
	}
	source := c.FormValue("authority_source")
	var certificate, private []byte
	if source == "enterprise" {
		read := func(name string, limit int64) ([]byte, error) {
			file, err := c.FormFile(name)
			if err != nil || file.Size > limit {
				return nil, registry.ErrInvalid
			}
			content, err := file.Open()
			if err != nil {
				return nil, registry.ErrInvalid
			}
			defer content.Close()
			data, err := io.ReadAll(io.LimitReader(content, limit+1))
			if err != nil || len(data) == 0 || int64(len(data)) > limit {
				clear(data)
				return nil, registry.ErrInvalid
			}
			return data, nil
		}
		certificate, err = read("authority_certificate", 64<<10)
		if err != nil {
			return desktopFailure(err)
		}
		private, err = read("authority_key", 32<<10)
		if err != nil {
			return desktopFailure(err)
		}
		defer clear(private)
	} else if source != "automatic" {
		return desktopFailure(registry.ErrInvalid)
	}
	_, err = h.Desktop.Registry.EnsureAuthority(c.Request().Context(), scope.TenantID, c.FormValue("organization"), origin.String(), h.appleActor(c), certificate, private)
	if err != nil {
		return desktopFailure(err)
	}
	return appleRedirect(c, info, "/desktop/enrollment")
}

func (h *Handler) revokeDesktop(c echo.Context, identity bool) error {
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	if h.Desktop == nil {
		return desktopFailure(registry.ErrUnavailable)
	}
	id := c.Param("id")
	if !enrollment.ValidDeviceID(id) {
		return desktopFailure(registry.ErrNotFound)
	}
	if c.FormValue("confirm_revoke") != "yes" {
		return echo.NewHTTPError(400, "Confirm revocation before continuing")
	}
	if identity {
		err = h.Desktop.Registry.RevokeIdentity(c.Request().Context(), scope, id, h.appleActor(c))
	} else {
		err = h.Desktop.Registry.RevokeInvitation(c.Request().Context(), scope, id, h.appleActor(c))
	}
	if err != nil {
		return desktopFailure(err)
	}
	return appleRedirect(c, info, "/desktop/enrollment")
}

func (h *Handler) DesktopRevokeInvitation(c echo.Context) error { return h.revokeDesktop(c, false) }
func (h *Handler) DesktopRevokeIdentity(c echo.Context) error   { return h.revokeDesktop(c, true) }
