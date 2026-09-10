package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsCapability(method, path string) (access.Capability, bool) {
	route := appleRoute(path)
	if method == http.MethodGet {
		switch route {
		case "/windows/:id/disconnections", "/windows/:id/disconnections/new", "/windows/:id/disconnections/:request":
			return access.RevokeDevices, true
		case "/windows/certificate-reminders", "/windows/certificate-health", "/windows/:id/renewals", "/windows/:id/renewals/:renewal":
			return access.ManageCertificates, true
		case "/windows/:id/commands", "/windows/:id/commands/:command", "/windows/:id/commands/new", "/windows/:id/commands/:command/observations", "/windows/:id/commands/:command/observations/:message":
			return access.ManageWindowsCSP, true
		case "/windows", "/windows/:id":
			return access.ReadDevices, true
		case "/windows/:id/updates", "/windows/:id/updates/:run", "/windows/:id/updates/new",
			"/windows/update-rings", "/windows/update-rings/new", "/windows/update-rings/:ring", "/windows/update-rings/:ring/edit",
			"/windows/update-rings/:ring/assign", "/windows/update-rollouts/:rollout",
			"/windows/update-rings/:ring/schedule", "/windows/update-schedules", "/windows/update-schedules/:schedule":
			return access.ManageUpdates, true
		}
	}
	if method == http.MethodPost {
		switch route {
		case "/windows/:id/commands/:command/cancel", "/windows/:id/commands/:command/abandon", "/windows/:id/commands/preview", "/windows/:id/commands/create":
			return access.ManageWindowsCSP, true
		case "/windows/setup", "/windows/:id/renewals/:renewal/cancel":
			return access.ManageCertificates, true
		case "/windows/invitations", "/windows/invitations/:id/revoke":
			return access.EnrollDevices, true
		case "/windows/:id/revoke", "/windows/:id/disconnections/preview", "/windows/:id/disconnections/create", "/windows/:id/disconnections/:request/cancel", "/windows/:id/disconnections/:request/release":
			return access.RevokeDevices, true
		case "/windows/:id/updates/:run/cancel", "/windows/:id/updates/preview", "/windows/:id/updates/create", "/windows/update-rings/preview", "/windows/update-rings/save", "/windows/update-rings/:ring/assign/preview", "/windows/update-rings/:ring/assign/create", "/windows/update-rings/:ring/schedule/preview", "/windows/update-rings/:ring/schedule/create", "/windows/update-schedules/:schedule/cancel":
			return access.ManageUpdates, true
		}
	}
	return "", false
}

func (h *Handler) RegisterWindows(e *echo.Echo) {
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		g := e.Group(prefix, h.IsAuthenticated, h.WindowsCSRF)
		g.GET("/windows", h.WindowsEnrollment)
		g.GET("/windows/certificate-health", h.WindowsCertificateHealth)
		g.GET("/windows/certificate-reminders", h.WindowsCertificateReminders)
		g.GET("/windows/update-rings", h.WindowsUpdateRings)
		g.GET("/windows/update-rings/new", h.WindowsEditUpdateRing)
		g.GET("/windows/update-rings/:ring", h.WindowsUpdateRingHistory)
		g.GET("/windows/update-rings/:ring/edit", h.WindowsEditUpdateRing)
		g.POST("/windows/update-rings/preview", h.WindowsPreviewUpdateRing)
		g.POST("/windows/update-rings/save", h.WindowsSaveUpdateRing)
		g.GET("/windows/update-rings/:ring/assign", h.WindowsNewUpdateAssignment)
		g.POST("/windows/update-rings/:ring/assign/preview", h.WindowsPreviewUpdateAssignment)
		g.POST("/windows/update-rings/:ring/assign/create", h.WindowsCreateUpdateAssignment)
		g.GET("/windows/update-rollouts/:rollout", h.WindowsUpdateRollout)
		g.GET("/windows/update-rings/:ring/schedule", h.WindowsNewUpdateSchedule)
		g.POST("/windows/update-rings/:ring/schedule/preview", h.WindowsPreviewUpdateSchedule)
		g.POST("/windows/update-rings/:ring/schedule/create", h.WindowsCreateUpdateSchedule)
		g.GET("/windows/update-schedules", h.WindowsUpdateSchedules)
		g.GET("/windows/update-schedules/:schedule", h.WindowsUpdateSchedule)
		g.POST("/windows/update-schedules/:schedule/cancel", h.WindowsCancelUpdateSchedule)
		g.GET("/windows/:id", h.WindowsDevice)
		g.GET("/windows/:id/disconnections", h.WindowsUnenrollmentRequests)
		g.GET("/windows/:id/disconnections/new", h.WindowsNewUnenrollmentRequest)
		g.GET("/windows/:id/disconnections/:request", h.WindowsUnenrollmentRequest)
		g.POST("/windows/:id/disconnections/preview", h.WindowsPreviewUnenrollmentRequest)
		g.POST("/windows/:id/disconnections/create", h.WindowsCreateUnenrollmentRequest)
		g.POST("/windows/:id/disconnections/:request/cancel", h.WindowsCancelUnenrollmentRequest)
		g.POST("/windows/:id/disconnections/:request/release", h.WindowsReleaseUnenrollmentRequest)
		g.GET("/windows/:id/renewals", h.WindowsCertificateRenewals)
		g.GET("/windows/:id/renewals/:renewal", h.WindowsCertificateRenewal)
		g.POST("/windows/:id/renewals/:renewal/cancel", h.WindowsCancelCertificateRenewal)
		g.GET("/windows/:id/commands", h.WindowsCSPCommands)
		g.GET("/windows/:id/commands/new", h.WindowsNewCSPCommand)
		g.POST("/windows/:id/commands/preview", h.WindowsPreviewCSPCommand)
		g.POST("/windows/:id/commands/create", h.WindowsCreateCSPCommand)
		g.GET("/windows/:id/commands/:command", h.WindowsCSPCommand)
		g.GET("/windows/:id/commands/:command/observations", h.WindowsCSPObservations)
		g.GET("/windows/:id/commands/:command/observations/:message", h.WindowsCSPObservation)
		g.POST("/windows/:id/commands/:command/cancel", h.WindowsCancelCSPCommand)
		g.POST("/windows/:id/commands/:command/abandon", h.WindowsAbandonCSPCommand)
		g.POST("/windows/setup", h.WindowsAuthority)
		g.POST("/windows/invitations", h.WindowsInvitation)
		g.POST("/windows/invitations/:id/revoke", h.WindowsRevokeInvitation)
		g.POST("/windows/:id/revoke", h.WindowsRevokeDevice)
		g.GET("/windows/:id/updates", h.WindowsUpdateRuns)
		g.GET("/windows/:id/updates/new", h.WindowsNewUpdatePolicy)
		g.POST("/windows/:id/updates/preview", h.WindowsPreviewUpdatePolicy)
		g.POST("/windows/:id/updates/create", h.WindowsCreateUpdatePolicy)
		g.GET("/windows/:id/updates/:run", h.WindowsUpdateRun)
		g.POST("/windows/:id/updates/:run/cancel", h.WindowsCancelUpdateRun)
	}
}

func (h *Handler) WindowsCSRF(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 30*time.Second)
		defer cancel()
		c.SetRequest(c.Request().WithContext(ctx))
		c.Response().Header().Set("Cache-Control", "no-store")
		c.Response().Header().Set("Referrer-Policy", "strict-origin")
		if c.Request().Method == http.MethodPost {
			r := c.Request()
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" {
				return echo.NewHTTPError(415, "Use a native Windows form")
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery {
				return echo.NewHTTPError(400, "Form actions do not accept query parameters")
			}
			limit := windowsFormByteLimit(c.Path())
			if r.ContentLength > limit {
				return echo.NewHTTPError(413, "Windows form is too large")
			}
			r.Body = http.MaxBytesReader(c.Response(), r.Body, limit)
			if err := r.ParseForm(); err != nil {
				var oversized *http.MaxBytesError
				if errors.As(err, &oversized) {
					return echo.NewHTTPError(413, "Windows form is too large")
				}
				return echo.NewHTTPError(400, "Invalid Windows form")
			}
			if int64(len(r.PostForm.Encode())) > limit || len(r.PostForm) > 24 {
				return echo.NewHTTPError(413, "Windows form is too large")
			}
			expected, _ := c.Get("csrf").(string)
			if expected == "" || len(r.PostForm["csrf"]) != 1 || subtle.ConstantTimeCompare([]byte(expected), []byte(r.PostForm.Get("csrf"))) != 1 {
				return echo.NewHTTPError(403, "Invalid CSRF token")
			}
		}
		return next(c)
	}
}

func windowsForm(c echo.Context, names ...string) (url.Values, error) {
	f := c.Request().PostForm
	allowed := map[string]bool{"csrf": true}
	for _, name := range names {
		allowed[name] = true
	}
	for name, values := range f {
		if !allowed[name] || len(values) != 1 {
			return nil, echo.NewHTTPError(400, "Unexpected or repeated Windows form field")
		}
	}
	return f, nil
}

func (h *Handler) windowsInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return nil, access.Scope{}, err
	}
	tenant, err := strconv.Atoi(info.TenantID)
	if err != nil || tenant <= 0 {
		return nil, access.Scope{}, echo.NewHTTPError(400, "Select an organization")
	}
	site, err := strconv.Atoi(info.SiteID)
	if site == -1 {
		site = 0
	}
	if err != nil || site < 0 {
		return nil, access.Scope{}, echo.NewHTTPError(400, "Select a site")
	}
	for _, param := range []struct{ name, value string }{{"tenant", info.TenantID}, {"site", info.SiteID}} {
		if requested := c.Param(param.name); requested != "" && requested != param.value {
			return nil, access.Scope{}, echo.NewHTTPError(404, "Organization or site not found")
		}
	}
	p, err := h.currentPrincipal(c)
	if err != nil {
		return nil, access.Scope{}, err
	}
	scope := access.Scope{TenantID: tenant, SiteID: site}
	needed := scope
	capability, ok := windowsCapability(c.Request().Method, c.Path())
	if capability == access.ManageCertificates && appleRoute(c.Path()) == "/windows/setup" {
		needed.SiteID = 0
	}
	if !ok || !p.Can(capability, needed) {
		return nil, access.Scope{}, echo.NewHTTPError(403, "Permission denied for this organization or site")
	}
	if site == 0 && appleRoute(c.Path()) != "/windows/certificate-reminders" && appleRoute(c.Path()) != "/windows/certificate-health" && appleRoute(c.Path()) != "/windows" && appleRoute(c.Path()) != "/windows/setup" {
		return nil, access.Scope{}, echo.NewHTTPError(400, "Select a concrete site")
	}
	return info, scope, nil
}

func windowsFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "This Windows action is not permitted")
	case errors.Is(err, windows.ErrNotFound):
		return echo.NewHTTPError(404, "Windows resource not found")
	case errors.Is(err, windows.ErrAuthorityExists):
		return echo.NewHTTPError(409, "The organization already has a Windows enrollment authority")
	case errors.Is(err, windows.ErrCSPAlreadySent):
		return echo.NewHTTPError(409, "This run has no cancelable undelivered steps, or a step is already sent or uncertain")
	case errors.Is(err, windows.ErrUpdateRingConflict):
		return echo.NewHTTPError(409, "The ring or request has changed. Open the latest revision and review your changes again.")
	case errors.Is(err, windows.ErrUpdateRing):
		return echo.NewHTTPError(400, "Invalid Windows update ring request")
	case errors.Is(err, windows.ErrCSPConflict):
		return echo.NewHTTPError(409, "This request was already used with different settings. Start a new policy run.")
	case errors.Is(err, windows.ErrCSPQueueFull):
		return echo.NewHTTPError(409, "This device has no room for another policy run. Review its outstanding work first.")
	case errors.Is(err, windows.ErrManagementIdentity):
		return echo.NewHTTPError(409, "The device identity is unavailable for new policy work")
	case errors.Is(err, windows.ErrUpdatePolicy):
		return echo.NewHTTPError(400, "Invalid Windows update request")
	case errors.Is(err, windows.ErrConsoleInput), errors.Is(err, windows.ErrInvitation), errors.Is(err, windows.ErrAuthority):
		return echo.NewHTTPError(400, "Invalid Windows enrollment settings")
	default:
		return echo.NewHTTPError(503, "Native Windows management is unavailable. Try again later.")
	}
}

func (h *Handler) windowsReady() error {
	if h.Windows == nil {
		return echo.NewHTTPError(503, "Native Windows management is not configured")
	}
	return nil
}

func windowsOffset(c echo.Context, name string) (int, error) {
	if len(c.QueryParams()[name]) > 1 {
		return 0, echo.NewHTTPError(400, "Invalid Windows page")
	}
	raw := c.QueryParam(name)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 100000 || strconv.Itoa(n) != raw || len(c.QueryParams()[name]) != 1 {
		return 0, echo.NewHTTPError(400, "Invalid Windows page")
	}
	return n, nil
}

func (h *Handler) windowsEnrollmentData(c echo.Context, info *partials.CommonInfo, scope access.Scope) (windows_views.EnrollmentData, error) {
	data := windows_views.EnrollmentData{SetupError: h.WindowsSetupError, PublicOrigin: strings.TrimSuffix(h.WindowsOptions.ManagementURL, "/mdm/windows/syncml"), Search: c.QueryParam("q")}
	if h.Windows == nil {
		if data.SetupError == "" {
			data.SetupError = "A server administrator must configure native Windows management."
		}
		return data, nil
	}
	var err error
	data.DeviceOffset, err = windowsOffset(c, "devices_offset")
	if err != nil {
		return data, err
	}
	data.InvitationOffset, err = windowsOffset(c, "invitations_offset")
	if err != nil {
		return data, err
	}
	if len(data.Search) > 128 || len(c.QueryParams()["q"]) > 1 {
		return data, echo.NewHTTPError(400, "Invalid Windows search")
	}
	actor := h.appleActor(c)
	if info.Can(access.ManageCertificates) {
		data.Authority, err = h.Windows.EnrollmentAuthority(c.Request().Context(), actor, scope.TenantID)
		if err != nil && !errors.Is(err, windows.ErrNotFound) {
			return data, windowsFailure(err)
		}
	}
	if scope.SiteID > 0 {
		data.Devices, err = h.Windows.Devices(c.Request().Context(), actor, scope, data.Search, data.DeviceOffset, 26)
		if err != nil {
			return data, windowsFailure(err)
		}
		if len(data.Devices) > 25 {
			data.MoreDevices = true
			data.Devices = data.Devices[:25]
		}
		if info.Can(access.EnrollDevices) {
			data.Available, err = h.Windows.EnrollmentAvailable(c.Request().Context(), actor, scope)
			if err != nil {
				return data, windowsFailure(err)
			}
			data.Invitations, err = h.Windows.EnrollmentInvitations(c.Request().Context(), actor, scope, data.InvitationOffset, 26)
			if err != nil {
				return data, windowsFailure(err)
			}
			if len(data.Invitations) > 25 {
				data.MoreInvitations = true
				data.Invitations = data.Invitations[:25]
			}
		}
	}
	return data, nil
}

func (h *Handler) WindowsEnrollment(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	data, err := h.windowsEnrollmentData(c, info, scope)
	if err != nil {
		return err
	}
	return renderApple(c, windows_views.Enrollment(c, info, data))
}

func (h *Handler) WindowsAuthority(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	f, err := windowsForm(c, "organization", "key_bits", "validity_days", "confirm_setup")
	if err != nil {
		return err
	}
	bits, e1 := strconv.Atoi(f.Get("key_bits"))
	days, e2 := strconv.Atoi(f.Get("validity_days"))
	if e1 != nil || e2 != nil || days < 1 || days > 365 || f.Get("confirm_setup") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm the certificate authority settings")
	}
	_, err = h.Windows.InitializeAuthority(c.Request().Context(), h.appleActor(c), scope.TenantID, windows.AuthorityOptions{Organization: f.Get("organization"), MinimumKeyBits: bits, ValiditySeconds: int64(days) * 86400, RenewalSeconds: int64(days) * 21600})
	if err != nil {
		return windowsFailure(err)
	}
	return appleRedirect(c, info, "/windows")
}

func (h *Handler) WindowsInvitation(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	f, err := windowsForm(c, "username", "hours")
	if err != nil {
		return err
	}
	hours, err := strconv.Atoi(f.Get("hours"))
	if err != nil || hours < 1 || hours > 24 {
		return echo.NewHTTPError(400, "Choose an invitation lifetime from 1 to 24 hours")
	}
	data, err := h.windowsEnrollmentData(c, info, scope)
	if err != nil {
		return err
	}
	if !data.Available {
		return echo.NewHTTPError(409, "Set up an available Windows certificate authority first")
	}
	data.Created, data.Credential, err = h.Windows.CreateEnrollmentInvitation(c.Request().Context(), h.appleActor(c), scope, f.Get("username"), time.Duration(hours)*time.Hour)
	if err != nil {
		return windowsFailure(err)
	}
	// The credential exists only in this POST response, never in a URL, session
	// cookie, persistent page cache or a later GET response.
	data.Invitations = append([]windows.EnrollmentInvitation{*data.Created}, data.Invitations...)
	if len(data.Invitations) > 25 {
		data.MoreInvitations = true
		data.Invitations = data.Invitations[:25]
	}
	return renderApple(c, windows_views.Enrollment(c, info, data))
}

func (h *Handler) WindowsRevokeInvitation(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	f, err := windowsForm(c, "confirm_revoke")
	if err != nil {
		return err
	}
	if f.Get("confirm_revoke") != "yes" {
		return echo.NewHTTPError(400, "Confirm invitation revocation")
	}
	if err := h.Windows.RevokeEnrollmentInvitation(c.Request().Context(), h.appleActor(c), scope, c.Param("id")); err != nil {
		return windowsFailure(err)
	}
	return appleRedirect(c, info, "/windows")
}

func (h *Handler) WindowsDevice(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsFailure(err)
	}
	return renderApple(c, windows_views.Device(c, info, *device))
}

func (h *Handler) WindowsRevokeDevice(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	f, err := windowsForm(c, "confirm_revoke")
	if err != nil {
		return err
	}
	if f.Get("confirm_revoke") != "yes" {
		return echo.NewHTTPError(400, "Confirm device access revocation")
	}
	if err := h.Windows.RevokeDevice(c.Request().Context(), h.appleActor(c), scope, c.Param("id")); err != nil {
		return windowsFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+c.Param("id"))
}
