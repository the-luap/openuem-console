package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const accessContextKey = "openuem.access.principal"

func (h *Handler) currentPrincipal(c echo.Context) (access.Principal, error) {
	if p, ok := c.Get(accessContextKey).(access.Principal); ok {
		return p, nil
	}
	if h.Access == nil {
		return access.Principal{}, echo.NewHTTPError(http.StatusServiceUnavailable, "Access control is not initialized")
	}
	uid := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	p, err := h.Access.Principal(c.Request().Context(), uid)
	if err != nil {
		if errors.Is(err, access.ErrDenied) {
			return p, echo.NewHTTPError(http.StatusForbidden, "Access is not assigned to this account")
		}
		return p, echo.NewHTTPError(http.StatusServiceUnavailable, "Unable to verify access permissions")
	}
	c.Set(accessContextKey, p)
	return p, nil
}

func appleRoute(path string) string {
	path = strings.TrimPrefix(path, "/tenant/:tenant/site/:site")
	return strings.TrimPrefix(path, "/tenant/:tenant")
}

// appleCapability is explicit: new routes do not inherit mutation authority
// merely because they share a prefix or use GET instead of POST.
func appleCapability(method, path string) (access.Capability, bool) {
	route := appleRoute(path)
	if method == http.MethodGet {
		switch route {
		case "/software/catalog/windows/new":
			return access.ManageSoftware, true
		case "/software/catalog/:version/windows-requests":
			return access.ReadSoftware, true
		case "/devices", "/ios", "/ios/setup", "/ios/:id", "/mac/:id", "/ios/:id/users/:user":
			return access.ReadDevices, true
		case "/software/catalog", "/software/catalog/:version", "/ios/:id/applications", "/ios/:id/applications/:assignment/history", "/ios/:id/setup/applications/:requirement/history":
			return access.ReadSoftware, true
		case "/ios/configurations", "/ios/configurations/history", "/ios/configurations/:id/history", "/ios/:id/setup/platform-sso/repairs", "/ios/:id/setup/platform-sso/history":
			return access.ReadProfiles, true
		case "/ios/:id/applications/previous", "/ios/ade", "/ios/ade/software", "/ios/ade/platform-sso/profiles", "/ios/:id/setup/platform-sso/profiles", "/ios/ade/servers/:id/certificate", "/ios/setup/requests/:id/csr", "/ios/setup/requests/:id/portal":
			return access.ManageCertificates, true
		case "/ios/configurations/:id/download", "/ios/configurations/:id/revisions/:revision/download", "/ios/configurations/acme-history":
			return access.ManageProfiles, true
		}
	}
	if method == http.MethodPost {
		switch route {
		case "/ios/:id/applications/previous/:attempt/resolve", "/ios/:id/setup/applications/:requirement/replace", "/ios/:id/setup/platform-sso/repair", "/ios/:id/setup/platform-sso/correct":
			return access.ManageCertificates, true
		case "/software/catalog", "/software/catalog/windows", "/software/catalog/:version/withdraw":
			return access.ManageSoftware, true
		case "/software/catalog/:version/install", "/ios/:id/applications/:assignment/action":
			return access.AssignSoftware, true
		case "/software/catalog/:version/windows-requests", "/software/catalog/:version/windows-requests/:request/cancel":
			return access.AssignSoftware, true
		case "/ios/ade/servers", "/ios/ade/servers/:id/token", "/ios/ade/servers/:id/action", "/ios/ade/servers/:id/profiles", "/ios/ade/servers/:id/profiles/:profile/action", "/ios/ade/servers/:id/targets", "/ios/ade/servers/:id/targets/:serial/rearm", "/ios/setup", "/ios/setup/requests", "/ios/setup/requests/:id/revoke", "/ios/setup/requests/:id/certificate", "/ios/setup/requests/:id/vendor":
			return access.ManageCertificates, true
		case "/ios/enroll":
			return access.EnrollDevices, true
		case "/ios/configurations", "/ios/configurations/:id/delete", "/ios/configurations/:id/revisions/:revision/restore", "/ios/configurations/acme-history/:legacy/review":
			return access.ManageProfiles, true
		case "/ios/configurations/:id/assign", "/ios/:id/users/:user/profiles", "/ios/:id/users/:user/commands/:command/retry":
			return access.AssignProfiles, true
		case "/ios/:id/refresh", "/ios/:id/users/:user/refresh":
			return access.RefreshDevices, true
		case "/ios/:id/mac-binding", "/ios/:id/mac-binding/cancel", "/ios/:id/users/:user/resume", "/ios/:id/setup/retry":
			return access.EnrollDevices, true
		case "/ios/:id/revoke", "/ios/:id/users/:user/pause":
			return access.RevokeDevices, true
		case "/ios/:id/mac-admin", "/ios/:id/filevault", "/ios/:id/filevault/keys/:key/verify", "/ios/:id/filevault/keys/:key/rotate", "/ios/:id/recovery-lock":
			return access.ManageDeviceSecurity, true
		case "/ios/:id/mac-admin/passwords/:key/reveal", "/ios/:id/filevault/keys/:key/reveal", "/ios/:id/recovery-lock/passwords/:key/reveal":
			return access.RetrieveRecoveryKeys, true
		case "/ios/:id/update":
			return access.ManageUpdates, true
		// A retry can redeliver a previously authorized configuration or update.
		case "/ios/:id/commands/:command/retry":
			return access.AssignProfiles, true
		}
	}
	return "", false
}

func (h *Handler) authorizeConsoleRequest(c echo.Context, next echo.HandlerFunc) error {
	p, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	if p.IsAdministrator() {
		return next(c)
	}
	route := appleRoute(c.Path())
	if c.Request().Method == http.MethodGet && (route == "" || route == "/" || route == "/dashboard") {
		prefix := ""
		if tenant := c.Param("tenant"); tenant != "" {
			prefix = "/tenant/" + url.PathEscape(tenant)
		}
		if site := c.Param("site"); site != "" {
			prefix += "/site/" + url.PathEscape(site)
		}
		return c.Redirect(http.StatusSeeOther, prefix+"/devices")
	}
	if _, ok := appleCapability(c.Request().Method, c.Path()); ok {
		// appleInfo resolves the selected organization/site and checks the action
		// before any domain call. No legacy resource handler is implicitly admitted.
		return next(c)
	}
	if _, ok := desktopCapability(c.Request().Method, c.Path()); ok {
		// Desktop handlers resolve and authorize the exact selected scope before
		// reading registry metadata or performing enrollment actions.
		return next(c)
	}
	if _, ok := windowsCapability(c.Request().Method, c.Path()); ok {
		// Native Windows handlers and store transactions resolve live scope.
		return next(c)
	}
	if _, ok := auditCapability(c.Request().Method, c.Path()); ok {
		// Audit handlers and their database transactions authorize the exact URL scope.
		return next(c)
	}
	if c.Path() == "/myaccount" && c.Request().Method == http.MethodGet {
		return next(c)
	}
	if c.Request().Method == http.MethodPost {
		switch c.Path() {
		case "/myaccount/info", "/myaccount/password", "/myaccount/enable2fa", "/myaccount/disable2fa", "/myaccount/register2fa":
			return next(c)
		}
	}
	return echo.NewHTTPError(http.StatusForbidden, "This action requires a server administrator")
}

func permissionScope(tenant, site string) access.Scope {
	tenantID, _ := strconv.Atoi(tenant)
	siteID, _ := strconv.Atoi(site)
	if tenantID < 0 {
		tenantID = 0
	}
	if siteID < 0 {
		siteID = 0
	}
	return access.Scope{TenantID: tenantID, SiteID: siteID}
}

func (h *Handler) requireApplePermission(c echo.Context, scope access.Scope) error {
	p, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	capability, ok := appleCapability(c.Request().Method, c.Path())
	if !ok {
		return echo.NewHTTPError(http.StatusForbidden, "Action is not authorized")
	}
	// Profile contents and APNs configuration affect an entire organization.
	// A site URL cannot reduce their authorization scope.
	if capability == access.ManageProfiles || capability == access.ManageCertificates || capability == access.ManageSoftware {
		scope.SiteID = 0
	}
	if !p.Can(capability, scope) {
		return echo.NewHTTPError(http.StatusForbidden, "Permission denied for this organization or site")
	}
	return nil
}
