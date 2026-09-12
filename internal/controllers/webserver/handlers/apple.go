package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) RegisterApple(e *echo.Echo) {
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		g := e.Group(prefix, h.IsAuthenticated, h.AppleCSRF)
		g.GET("/software/catalog", h.SoftwareCatalog)
		g.POST("/software/catalog", h.PublishMacAppPackage)
		g.GET("/software/catalog/windows/new", h.WindowsSoftwareApproval)
		g.POST("/software/catalog/windows", h.PublishWindowsSoftware)
		g.GET("/software/catalog/:version", h.SoftwareVersion)
		g.GET("/software/catalog/:version/sources", h.WindowsSoftwareSources)
		g.POST("/software/catalog/:version/sources", h.ResolveWindowsSoftwareSource)
		g.GET("/software/catalog/:version/sources/:source", h.WindowsSoftwareSource)
		g.GET("/software/catalog/:version/sources/:source/review", h.ReviewWindowsSoftwareSource)
		g.POST("/software/catalog/:version/sources/:source/approve", h.ApproveWindowsSoftwareSource)
		g.GET("/software/catalog/:version/windows-requests", h.WindowsSoftwareRequests)
		g.POST("/software/catalog/:version/windows-requests", h.PrepareWindowsSoftware)
		g.POST("/software/catalog/:version/windows-requests/:request/cancel", h.CancelWindowsSoftwarePreparation)
		g.GET("/software/catalog/:version/windows-requests/:request/dispatch", h.ReviewWindowsSoftwareDispatch)
		g.POST("/software/catalog/:version/windows-requests/:request/dispatch", h.DispatchWindowsSoftware)
		g.POST("/software/catalog/:version/windows-requests/:request/dispatch/cancel", h.CancelWindowsSoftwareDispatch)
		g.GET("/software/catalog/:version/windows-requests/:request/dispatch/reconcile", h.ReviewWindowsSoftwareReconciliation)
		g.POST("/software/catalog/:version/windows-requests/:request/dispatch/reconcile", h.QueueWindowsSoftwareReconciliation)
		g.GET("/software/catalog/:version/windows-requests/:request/dispatch/reconciliations", h.WindowsSoftwareReconciliations)
		g.POST("/software/catalog/:version/windows-requests/:request/dispatch/reconciliations/:reconciliation/cancel", h.CancelWindowsSoftwareReconciliation)
		g.POST("/software/catalog/:version/withdraw", h.WithdrawSoftwareVersion)
		g.POST("/software/catalog/:version/install", h.InstallMacApp)
		g.GET("/ios/:id/applications", h.MacApplications)
		g.GET("/ios/:id/applications/previous", h.MacAppPreviousEnrollments)
		g.POST("/ios/:id/applications/previous/:attempt/resolve", h.RecordMacAppStoppingEvidence)
		g.GET("/ios/:id/applications/:assignment/history", h.MacApplicationHistory)
		g.GET("/ios/ade/software", h.ADESoftwareOptions)
		g.GET("/ios/ade/platform-sso/profiles", h.ADEPlatformSSOChoices)
		g.GET("/ios/:id/setup/applications/:requirement/history", h.ADEApplicationHistory)
		g.POST("/ios/:id/setup/applications/:requirement/replace", h.ReplaceADEApplication)
		g.GET("/ios/:id/setup/platform-sso/repairs", h.ADEPlatformSSORepairs)
		g.POST("/ios/:id/setup/platform-sso/repair", h.RepairADEPlatformSSO)
		g.GET("/ios/:id/setup/platform-sso/profiles", h.ADEPlatformSSORevisionChoices)
		g.GET("/ios/:id/setup/platform-sso/history", h.ADEPlatformSSORevisions)
		g.POST("/ios/:id/setup/platform-sso/correct", h.CorrectADEPlatformSSO)
		g.POST("/ios/:id/applications/:assignment/action", h.ChangeMacApp)
		g.GET("/devices", h.UnifiedDevices)
		g.GET("/device-groups", h.DeviceGroups)
		g.POST("/device-groups", h.SaveDeviceGroup)
		g.GET("/device-groups/:group", h.DeviceGroup)
		g.POST("/device-groups/:group", h.SaveDeviceGroup)
		g.Any("/devices/export", h.ExportDeviceInventory)
		g.GET("/ios", h.UnifiedDevices)
		g.GET("/ios/setup", h.AppleSettings)
		g.GET("/ios/ade", h.AppleADE)
		g.POST("/ios/ade/servers", h.AppleCreateADEServer)
		g.GET("/ios/ade/servers/:id/certificate", h.AppleADECertificate)
		g.POST("/ios/ade/servers/:id/token", h.AppleImportADEToken)
		g.POST("/ios/ade/servers/:id/action", h.AppleChangeADEServer)
		g.POST("/ios/ade/servers/:id/profiles", h.AppleCreateADEProfile)
		g.POST("/ios/ade/servers/:id/profiles/:profile/action", h.AppleChangeADEProfile)
		g.POST("/ios/ade/servers/:id/targets", h.AppleSetADETargets)
		g.POST("/ios/ade/servers/:id/targets/:serial/rearm", h.AppleRearmADETarget)
		g.POST("/ios/:id/setup/retry", h.AppleRetryADESetup)
		g.POST("/ios/:id/mac-admin", h.AppleMacAdmin)
		g.POST("/ios/:id/mac-admin/passwords/:key/reveal", h.AppleMacAdminPassword)
		g.POST("/ios/:id/recovery-lock", h.AppleRecoveryLock)
		g.POST("/ios/:id/recovery-lock/passwords/:key/reveal", h.AppleRecoveryLockPassword)
		g.POST("/ios/setup", h.AppleSettings)
		g.POST("/ios/setup/requests", h.AppleCreatePushRequest)
		g.GET("/ios/setup/requests/:id/csr", h.ApplePushRequestCSR)
		g.POST("/ios/setup/requests/:id/vendor", h.AppleAttachVendorRequest)
		g.GET("/ios/setup/requests/:id/portal", h.AppleVendorPortalRequest)
		g.POST("/ios/setup/requests/:id/revoke", h.AppleRevokePushRequest)
		g.POST("/ios/setup/requests/:id/certificate", h.AppleImportPushCertificate)
		g.POST("/ios/enroll", h.AppleInvite)
		g.GET("/ios/configurations", h.AppleProfiles)
		g.GET("/ios/configurations/history", h.AppleProfileRevisionHistory)
		g.GET("/ios/configurations/acme-history", h.AppleACMEHistory)
		g.POST("/ios/configurations/acme-history/:legacy/review", h.AppleReviewACMEHistory)
		g.GET("/ios/configurations/:id/history", h.AppleProfileRevisionHistory)
		g.GET("/ios/configurations/:id/revisions/:revision/download", h.AppleDownloadProfileRevision)
		g.POST("/ios/configurations/:id/revisions/:revision/restore", h.AppleRestoreProfileRevision)
		g.POST("/ios/configurations", h.AppleSaveProfile)
		g.GET("/ios/configurations/:id/download", h.AppleDownloadProfile)
		g.POST("/ios/configurations/:id/assign", h.AppleAssignProfile)
		g.GET("/ios/configurations/:id/groups", h.AppleProfileGroups)
		g.GET("/ios/configurations/:id/groups/:group/preview", h.ApplePreviewProfileGroup)
		g.POST("/ios/configurations/:id/group-assignments", h.AppleAssignProfileGroup)
		g.GET("/ios/configurations/:id/group-assignments", h.AppleProfileGroupAssignments)
		g.GET("/ios/configurations/:id/group-assignments/:assignment", h.AppleProfileGroupAssignment)
		g.POST("/ios/configurations/:id/delete", h.AppleDeleteProfile)
		g.GET("/ios/:id", h.AppleDevice)
		g.GET("/ios/:id/users/:user", h.AppleUser)
		g.POST("/ios/:id/users/:user/refresh", h.AppleUserAction)
		g.POST("/ios/:id/users/:user/profiles", h.AppleUserAction)
		g.POST("/ios/:id/users/:user/commands/:command/retry", h.AppleUserAction)
		g.POST("/ios/:id/users/:user/pause", h.AppleUserAction)
		g.POST("/ios/:id/users/:user/resume", h.AppleUserAction)
		g.GET("/mac/:id", h.MacDevice)
		g.POST("/ios/:id/mac-binding", h.AppleMacBinding)
		g.POST("/ios/:id/mac-binding/cancel", h.AppleMacBinding)
		g.POST("/ios/:id/refresh", h.AppleRefresh)
		g.POST("/ios/:id/revoke", h.AppleRevoke)
		g.GET("/ios/:id/update-exceptions/review", h.AppleReviewUpdateException)
		g.GET("/ios/:id/update-exceptions", h.AppleUpdateExceptions)
		g.POST("/ios/:id/update-exceptions", h.AppleRecordUpdateException)
		g.GET("/ios/:id/update-exceptions/:exception", h.AppleUpdateException)
		g.GET("/ios/update-alerts", h.AppleUpdateEscalations)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment/escalation", h.AppleReviewUpdateEscalation)
		g.POST("/ios/update-plans/:plan/group-assignments/:assignment/escalation", h.AppleConfigureUpdateEscalation)
		g.POST("/ios/update-plans/:plan/group-assignments/:assignment/escalation/acknowledge", h.AppleAcknowledgeUpdateEscalation)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment/escalation/events", h.AppleUpdateEscalationEvents)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment/escalation/events/:event", h.AppleUpdateEscalationEvent)
		g.GET("/ios/update-plans", h.AppleUpdatePlans)
		g.POST("/ios/update-plans", h.AppleSaveUpdatePlan)
		g.GET("/ios/update-plans/:plan/groups", h.AppleUpdatePlanGroups)
		g.GET("/ios/update-plans/:plan/groups/:group/preview", h.ApplePreviewUpdatePlanGroup)
		g.POST("/ios/update-plans/:plan/group-assignments", h.AppleAssignUpdatePlanGroup)
		g.GET("/ios/update-plans/:plan/group-assignments", h.AppleUpdatePlanGroupAssignments)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment", h.AppleUpdatePlanGroupAssignment)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment/progress", h.AppleUpdatePlanGroupProgress)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment/removal", h.ApplePreviewUpdateGroupRemoval)
		g.POST("/ios/update-plans/:plan/group-assignments/:assignment/removals", h.AppleRemoveUpdateGroupPolicies)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment/removals", h.AppleUpdateGroupRemovals)
		g.GET("/ios/update-plans/:plan/group-assignments/:assignment/removals/:removal", h.AppleUpdateGroupRemoval)
		g.POST("/ios/update-plans/:plan/schedules", h.AppleScheduleUpdatePlan)
		g.GET("/ios/update-plans/:plan/schedules", h.AppleUpdateSchedules)
		g.GET("/ios/update-plans/:plan/schedules/:schedule", h.AppleUpdateSchedule)
		g.POST("/ios/update-plans/:plan/schedules/:schedule/cancel", h.AppleCancelUpdateSchedule)
		g.GET("/ios/update-plans/:plan", h.AppleUpdatePlan)
		g.POST("/ios/update-plans/:plan", h.AppleSaveUpdatePlan)
		g.POST("/ios/:id/update", h.AppleUpdate)
		g.POST("/ios/:id/filevault", h.AppleFileVault)
		g.POST("/ios/:id/filevault/keys/:key/reveal", h.AppleFileVaultKey)
		g.POST("/ios/:id/filevault/keys/:key/verify", h.AppleFileVaultValidate)
		g.POST("/ios/:id/filevault/keys/:key/rotate", h.AppleFileVaultRotate)
		g.POST("/ios/:id/commands/:command/retry", h.AppleRetryCommand)
	}
}

func (h *Handler) AppleCSRF(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if appleRoute(c.Path()) == "/devices/export" || strings.HasPrefix(appleRoute(c.Path()), "/device-groups") {
			c.Response().Header().Set("Cache-Control", "no-store")
			c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		}
		if c.Request().Method == http.MethodPost {
			limit := int64(4 << 20)
			switch appleRoute(c.Path()) {
			case "/ios/update-plans/:plan/group-assignments", "/ios/update-plans/:plan/schedules":
				limit = 16 << 10
			case "/ios/configurations/:id/assign":
				limit = 64 << 10
			case "/ios/update-plans/:plan/group-assignments/:assignment/escalation", "/ios/update-plans/:plan/group-assignments/:assignment/escalation/acknowledge", "/ios/update-plans/:plan/schedules/:schedule/cancel", "/ios/configurations/:id/group-assignments", "/ios/:id/update", "/ios/update-plans", "/ios/update-plans/:plan":
				limit = 8192
			case "/devices/export", "/device-groups", "/device-groups/:group", "/admin/oidc-accounts", "/myaccount/language", "/software/catalog/:version/sources", "/software/catalog/:version/sources/:source/approve":
				limit = 8192
			case "/software/catalog/:version/windows-requests/:request/dispatch/reconcile", "/software/catalog/:version/windows-requests/:request/dispatch/reconciliations/:reconciliation/cancel":
				limit = 8192
			case "/software/catalog/:version/windows-requests", "/software/catalog/:version/windows-requests/:request/cancel", "/software/catalog/:version/windows-requests/:request/dispatch", "/software/catalog/:version/windows-requests/:request/dispatch/cancel":
				limit = 8192
			case "/software/catalog/windows":
				limit = 128 << 10
			case "/ios/:id/setup/platform-sso/correct", "/ios/:id/setup/platform-sso/repair", "/ios/configurations/:id/revisions/:revision/restore", "/ios/:id/applications/previous/:attempt/resolve", "/ios/:id/setup/applications/:requirement/replace", "/software/catalog", "/software/catalog/:version/withdraw", "/software/catalog/:version/install", "/ios/:id/applications/:assignment/action", "/ios/:id/mac-admin", "/ios/:id/mac-admin/passwords/:key/reveal", "/ios/ade/servers/:id/profiles", "/ios/ade/servers/:id/profiles/:profile/action", "/ios/ade/servers/:id/targets", "/ios/ade/servers/:id/targets/:serial/rearm", "/ios/:id/setup/retry":
				// CSRF reads the form before the endpoint. Apply its bound here
				// as well so a cached PostForm cannot bypass the endpoint limit.
				limit = 128 << 10
			}
			if appleRoute(c.Path()) == "/desktop/invitations" || strings.Contains(appleRoute(c.Path()), "/recovery-lock") {
				limit = 8192
			}
			c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, limit)
			expected, _ := c.Get("csrf").(string)
			if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(c.FormValue("csrf"))) != 1 {
				return echo.NewHTTPError(http.StatusForbidden, "Invalid CSRF token")
			}
		}
		return next(c)
	}
}

func (h *Handler) appleInfo(c echo.Context) (*partials.CommonInfo, apple.Scope, error) {
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return nil, apple.Scope{}, err
	}
	tenant, err := strconv.Atoi(info.TenantID)
	if err != nil || tenant <= 0 {
		return nil, apple.Scope{}, echo.NewHTTPError(400, "Select an organization")
	}
	site, err := strconv.Atoi(info.SiteID)
	if err != nil {
		return nil, apple.Scope{}, err
	}
	if site == -1 {
		site = 0
	}
	// GetCommonInfo falls back to defaults on an unknown URL scope. Mutation
	// endpoints must reject such URLs instead of silently changing another scope.
	if requested := c.Param("tenant"); requested != "" && requested != info.TenantID {
		return nil, apple.Scope{}, echo.NewHTTPError(404, "Organization not found")
	}
	if requested := c.Param("site"); requested != "" && requested != info.SiteID {
		return nil, apple.Scope{}, echo.NewHTTPError(404, "Site not found")
	}
	if err := h.requireApplePermission(c, access.Scope{TenantID: tenant, SiteID: site}); err != nil {
		return nil, apple.Scope{}, err
	}
	return info, apple.Scope{TenantID: tenant, SiteID: site}, nil
}

func (h *Handler) appleReady() error {
	if h.Apple == nil {
		message := h.AppleSetupError
		if message == "" {
			message = "Apple management is not configured"
		}
		return echo.NewHTTPError(503, message)
	}
	return nil
}
func (h *Handler) appleActor(c echo.Context) string {
	return h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
}
func appleID(c echo.Context) (string, error) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		return "", echo.NewHTTPError(404, "Resource not found")
	}
	return id, nil
}
func appleFailure(c echo.Context, err error) error {
	if errors.Is(err, apple.ErrNotFound) {
		return echo.NewHTTPError(404, "Resource not found")
	}
	if errors.Is(err, apple.ErrConflict) {
		return echo.NewHTTPError(409, "This resource changed. Reload and try again.")
	}
	return echo.NewHTTPError(400, appleErrorText(c, "apple_errors.request"))
}

func appleRedirect(c echo.Context, info *partials.CommonInfo, path string) error {
	return c.Redirect(http.StatusSeeOther, partials.GetNavigationUrl(info, path))
}

func renderApple(c echo.Context, component templ.Component) error {
	if c.Response().Header().Get("Referrer-Policy") == "" {
		c.Response().Header().Set("Referrer-Policy", "strict-origin")
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("X-Content-Type-Options", "nosniff")
	if c.Request().Header.Get("HX-Request") == "true" {
		c.Response().Header().Set("HX-Retarget", "body")
		c.Response().Header().Set("HX-Reswap", "outerHTML")
	}
	return component.Render(c.Request().Context(), c.Response())
}

func (h *Handler) UnifiedDevices(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if len(c.Request().URL.RawQuery) > 16<<10 {
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "mdm.devices.invalid_filter"))
	}
	query, err := url.ParseQuery(c.Request().URL.RawQuery)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "mdm.devices.invalid_filter"))
	}
	for key, values := range query {
		if (key != "q" && key != "platform" && key != "sort" && key != "after") || len(values) != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "mdm.devices.invalid_filter"))
		}
	}
	filter := inventory.DeviceFilter{Platform: query.Get("platform"), Search: strings.TrimSpace(query.Get("q")), Sort: query.Get("sort"), After: query.Get("after")}
	if strings.HasSuffix(c.Path(), "/ios") && filter.Platform == "" {
		filter.Platform = "apple"
	}
	page, err := inventory.ReadDevices(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c),
		access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, inventory.DeviceSources{Apple: h.Apple != nil, Windows: h.Windows != nil}, filter)
	switch {
	case errors.Is(err, inventory.ErrReportFilter):
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "mdm.devices.invalid_filter"))
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "mdm.devices.permission_denied"))
	case err != nil:
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "mdm.devices.unavailable"))
	}
	rows := deviceViewRows(c.Request().Context(), page.Entries)
	pageURL := func(after string) string {
		q := url.Values{"q": {filter.Search}, "platform": {filter.Platform}, "sort": {filter.Sort}}
		if after != "" {
			q.Set("after", after)
		}
		return partials.GetNavigationUrl(info, "/devices") + "?" + q.Encode()
	}
	paging := mdm_views.DevicePagination{}
	if filter.After != "" {
		paging.First = pageURL("")
	}
	if page.Next != "" {
		paging.Next = pageURL(page.Next)
	}
	return renderApple(c, mdm_views.Devices(c, info, rows, filter.Platform, filter.Search, filter.Sort, h.AppleSetupError, paging))
}

func (h *Handler) AppleSettings(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	message := ""
	setupError := h.AppleSetupError
	if c.Request().Method == http.MethodPost {
		if err = h.appleReady(); err != nil {
			return err
		}
		cert, err := readAppleUpload(c, "push_certificate", 64<<10)
		if err != nil {
			return appleFailure(c, err)
		}
		key, err := readAppleUpload(c, "push_key", 64<<10)
		if err != nil {
			return appleFailure(c, err)
		}
		err = h.Apple.Configure(c.Request().Context(), apple.Settings{TenantID: scope.TenantID, Organization: c.FormValue("organization"), PublicURL: c.FormValue("public_url"), PushCertificate: cert, PushKey: key}, h.appleActor(c))
		if err != nil {
			setupError = appleSetupMessage(c, err)
		} else {
			message = "APNs connection verified and Apple push credentials saved. You can now create an enrollment invitation."
		}
	}
	var settings *apple.Settings
	if h.Apple != nil {
		settings, err = h.Apple.SettingsMetadata(c.Request().Context(), scope.TenantID)
		if err != nil && !errors.Is(err, apple.ErrNotFound) {
			return err
		}
		if errors.Is(err, apple.ErrNotFound) {
			settings = nil
		}
	}
	var requests []apple.PushRequest
	canManage := info.Principal.Can(access.ManageCertificates, access.Scope{TenantID: scope.TenantID})
	if h.Apple != nil && canManage {
		requests, err = h.Apple.PushRequests(c.Request().Context(), scope.TenantID)
		if err != nil {
			return err
		}
		if settings != nil {
			settings.PushReminders, err = h.Apple.PushReminderHistory(c.Request().Context(), scope.TenantID)
			if err != nil {
				return err
			}
		}
	} else if settings != nil {
		settings.AppleAccount = ""
		settings.PushCheckedAt = nil
		settings.PushFingerprint = ""
	}
	return renderApple(c, mdm_views.Setup(c, info, settings, requests, canManage, h.Apple != nil && h.Apple.VendorConfigured(), setupError, message, os.Getenv("APPLE_MDM_LISTEN_ADDR") != ""))
}

func readAppleUpload(c echo.Context, name string, limit int64) ([]byte, error) {
	file, err := c.FormFile(name)
	if err != nil {
		return nil, fmt.Errorf("select a %s file", strings.ReplaceAll(name, "_", " "))
	}
	if file.Size > limit {
		return nil, errors.New("file exceeds the permitted size")
	}
	r, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds the permitted size")
	}
	return data, nil
}

func (h *Handler) AppleInvite(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	if err = c.Request().ParseForm(); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid enrollment form")
	}
	for _, key := range []string{"name", "site_id", "allow_mac_device_lock"} {
		if len(c.Request().PostForm[key]) > 1 || len(c.QueryParams()[key]) != 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Ambiguous enrollment setting")
		}
	}
	lockValues := c.Request().PostForm["allow_mac_device_lock"]
	if len(lockValues) == 1 && lockValues[0] != "yes" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid device lock option")
	}
	if scope.SiteID == 0 || c.FormValue("site_id") != "" {
		site, err := strconv.Atoi(c.FormValue("site_id"))
		if err != nil {
			return appleFailure(c, errors.New("select a site"))
		}
		if c.Param("site") != "" && site != scope.SiteID {
			return echo.NewHTTPError(403, "Enrollment site does not match the selected scope")
		}
		if _, err = h.Model.GetSiteById(scope.TenantID, site); err != nil {
			return appleFailure(c, apple.ErrNotFound)
		}
		scope.SiteID = site
	}
	if err := h.requireApplePermission(c, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		return err
	}
	invite, err := h.Apple.InviteWithOptions(c.Request().Context(), scope, c.FormValue("name"), h.appleActor(c), apple.EnrollmentOptions{AllowMacDeviceLock: len(lockValues) == 1}, h.Access)
	if err != nil {
		if errors.Is(err, access.ErrDenied) {
			return echo.NewHTTPError(http.StatusForbidden, "Enrollment or device security management permission denied")
		}
		return appleFailure(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return renderApple(c, mdm_views.Invitation(c, info, invite))
}

func (h *Handler) AppleDevice(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	entity, err := h.Apple.MacForMDM(c.Request().Context(), scope, id)
	if err != nil {
		return appleFailure(c, err)
	}
	if entity != "" {
		return appleRedirect(c, info, "/mac/"+entity)
	}
	return h.renderAppleDevice(c, info, scope, id, nil)
}

func (h *Handler) renderAppleDevice(c echo.Context, info *partials.CommonInfo, scope apple.Scope, id string, mac *apple.MacDevice) error {
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return appleFailure(c, err)
	}
	detail := mdm_views.Detail{Device: d, Mac: mac}
	detail.ADE, err = h.Apple.ADEDeviceEnrollment(c.Request().Context(), scope, id)
	if err != nil {
		return appleFailure(c, err)
	}
	if detail.ADE != nil && info.Can(access.ReadSoftware) {
		detail.ADEApplications, err = h.Apple.ADEApplications(c.Request().Context(), scope, id)
		if err != nil {
			return appleFailure(c, err)
		}
	}
	if detail.ADE != nil && info.Can(access.ReadProfiles) {
		detail.ADEPlatformSSO, err = h.Apple.ADEPlatformSSOStatus(c.Request().Context(), scope, id)
		if err != nil {
			return appleFailure(c, err)
		}
	}
	if mac != nil && info.Can(access.ReadDevices) {
		var available bool
		if err = h.Model.DB.QueryRowContext(c.Request().Context(), `SELECT EXISTS(SELECT 1 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id WHERE a.oid=$1 AND sa.site_id=$2 AND s.tenant_sites=$3 AND a.agent_status<>'WaitingForAdmission' AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1)`, mac.AgentID, d.SiteID, scope.TenantID).Scan(&available); err != nil {
			return err
		}
		if available && info.Principal.IsAdministrator() {
			available, err = h.Model.Client.Agent.Query().Where(agent.ID(mac.AgentID), agent.HasComputer(), agent.HasOperatingsystem(), agent.HasRelease()).Exist(c.Request().Context())
			if err != nil {
				return err
			}
		}
		if available {
			detail.AgentURL = partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(mac.AgentID))
		}
	}
	if d.Family() == apple.PlatformMacOS {
		detail.MacAdmin, err = h.Apple.MacAdmin(c.Request().Context(), scope, id)
		if err != nil {
			return err
		}
		if info.Can(access.RetrieveRecoveryKeys) {
			detail.MacAdminKeys, err = h.Apple.MacAdminKeys(c.Request().Context(), scope, id)
			if err != nil {
				return err
			}
		}
		detail.RecoveryLock, err = h.Apple.RecoveryLock(c.Request().Context(), scope, id)
		if err != nil {
			return err
		}
		if info.Can(access.RetrieveRecoveryKeys) {
			detail.RecoveryLockKeys, err = h.Apple.RecoveryLockKeys(c.Request().Context(), scope, id)
			if err != nil {
				return err
			}
		}
		detail.FileVault, err = h.Apple.FileVault(c.Request().Context(), scope, id)
		if err != nil {
			return err
		}
		if info.Can(access.RetrieveRecoveryKeys) {
			detail.FileVaultKeys, err = h.Apple.FileVaultKeyHistory(c.Request().Context(), scope, id)
			if err != nil {
				return err
			}
		}
		detail.Users, err = h.Apple.Users(c.Request().Context(), scope, id)
		if err != nil {
			return err
		}
		detail.MacBindingReady = h.Desktop != nil && h.Apple.MacLinksReady(c.Request().Context())
		detail.MacBinding, err = h.Apple.MacBinding(c.Request().Context(), scope, id)
		if err != nil {
			return err
		}
	}
	detail.IdentityRenewals, err = h.Apple.IdentityRenewals(c.Request().Context(), scope, id)
	if err != nil {
		return err
	}
	detail.Commands, err = h.Apple.Commands(c.Request().Context(), scope, id)
	if err != nil {
		return err
	}
	detail.Assignments, err = h.Apple.Assignments(c.Request().Context(), scope, id)
	if err != nil {
		return err
	}
	detail.Profiles, err = h.Apple.Profiles(c.Request().Context(), scope.TenantID)
	if err != nil {
		return err
	}
	detail.UpdateAssessment, err = h.Apple.AssessDeviceUpdate(c.Request().Context(), h.appleActor(c), h.Access, scope, id)
	if err != nil {
		if errors.Is(err, access.ErrDenied) {
			return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "updates.assessment_permission"))
		}
		if errors.Is(err, apple.ErrNotFound) {
			return appleFailure(c, err)
		}
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "updates.assessment_unavailable"))
	}
	detail.Policy, detail.Compliance = detail.UpdateAssessment.Policy, detail.UpdateAssessment.Compliance
	catalog, fetched, err := h.Apple.Catalog(c.Request().Context())
	if err != nil {
		return err
	}
	detail.CatalogAt = fetched
	if fetched != nil && time.Since(*fetched) < 48*time.Hour {
		detail.Releases = catalog.DeviceReleases(*d, time.Now())
	}
	if err := h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "inventory.read", id); err != nil {
		return err
	}
	return renderApple(c, mdm_views.DeviceDetails(c, info, detail))
}

func (h *Handler) AppleRefresh(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	if err = h.Apple.RefreshInventory(c.Request().Context(), scope, id, h.appleActor(c)); err != nil {
		return appleFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) AppleRevoke(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	if c.FormValue("confirm_revoke") != "yes" {
		return echo.NewHTTPError(400, "Confirm that this enrollment should lose server access")
	}
	if err = h.Apple.RevokeEnrollment(c.Request().Context(), scope, id, h.appleActor(c)); err != nil {
		return appleFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) appleScopeInUse(c echo.Context, tenant, site int) (bool, error) {
	if h.Apple == nil {
		return false, nil
	}
	return h.Apple.ScopeInUse(c.Request().Context(), apple.Scope{TenantID: tenant, SiteID: site})
}

func (h *Handler) AppleProfiles(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	profiles, err := h.Apple.Profiles(c.Request().Context(), scope.TenantID)
	if err != nil {
		return err
	}
	devices, err := h.Apple.Devices(c.Request().Context(), scope)
	if err != nil {
		return err
	}
	return renderApple(c, mdm_views.Profiles(c, info, profiles, devices))
}

func (h *Handler) AppleSaveProfile(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	var data []byte
	if c.FormValue("editor") == "wifi-eap-tls" {
		if err = h.appleCreateWiFiEAPTLS(c, scope.TenantID); err != nil {
			return err
		}
		return appleRedirect(c, info, "/ios/configurations")
	} else if c.FormValue("editor") == "vpn-ikev2-certificate" {
		if err = h.appleCreateIKEv2Certificate(c, scope.TenantID); err != nil {
			return err
		}
		return appleRedirect(c, info, "/ios/configurations")
	} else if c.FormValue("editor") == "upload" {
		data, err = readAppleUpload(c, "profile", apple.MaxProfileBytes)
	} else if c.FormValue("editor") == "apple-pkcs12" {
		data, err = applePKCS12Data(c)
	} else if c.FormValue("editor") == "apple-certificates" {
		data, err = applePublicCertificateData(c)
	} else {
		settings := map[string]any{"SSID_STR": c.FormValue("ssid"), "EncryptionType": c.FormValue("wifi_security"), "Password": c.FormValue("wifi_password")}
		if scope := c.FormValue("payload_scope"); scope != "" {
			settings["PayloadScope"] = scope
		}
		length, _ := strconv.Atoi(c.FormValue("min_length"))
		settings["minLength"] = length
		settings["requireAlphanumeric"] = c.FormValue("alphanumeric") == "on"
		for _, key := range []string{"allowCamera", "allowScreenShot", "allowCloudBackup", "allowAppInstallation", "allowAirDrop"} {
			if c.FormValue(key) != "" {
				settings[key] = c.FormValue(key) == "true"
			}
		}
		if c.FormValue("editor") == "macos-firewall" {
			if err = appleFirewallSettings(c, settings); err != nil {
				return err
			}
		}
		if c.FormValue("editor") == "apple-scep" {
			if err = appleSCEPSettings(c, settings); err != nil {
				return err
			}
		}
		if c.FormValue("editor") == "apple-ad-certificate" {
			if err = appleADCertificateSettings(c, settings); err != nil {
				return err
			}
		}
		if c.FormValue("editor") == "apple-acme" {
			if err = appleACMESettings(c, settings); err != nil {
				return err
			}
		}
		if c.FormValue("editor") == "macos-privacy" {
			if err = applePrivacySettings(c, settings); err != nil {
				return err
			}
		}
		if c.FormValue("editor") == "macos-system-extensions" {
			if err = appleSystemExtensionsSettings(c, settings); err != nil {
				return err
			}
		}
		if c.FormValue("editor") == "macos-gatekeeper" {
			if err = appleGatekeeperSettings(c, settings); err != nil {
				return err
			}
		}
		if c.FormValue("editor") == "macos-platform-sso" {
			if err = applePlatformSSOSettings(c, settings); err != nil {
				return err
			}
		}
		data, err = apple.BuildProfile(c.FormValue("name"), c.FormValue("identifier"), c.FormValue("editor"), settings)
	}
	if err != nil {
		return appleFailure(c, err)
	}
	id := c.FormValue("profile_id")
	revision, _ := strconv.Atoi(c.FormValue("revision"))
	if id != "" {
		if _, err = uuid.Parse(id); err != nil {
			return appleFailure(c, apple.ErrNotFound)
		}
	}
	if _, err = h.Apple.SaveProfile(c.Request().Context(), scope.TenantID, id, revision, data, h.appleActor(c)); err != nil {
		return appleFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/configurations")
}

func (h *Handler) AppleDownloadProfile(c echo.Context) error {
	_, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	p, err := h.Apple.Profile(c.Request().Context(), scope.TenantID, id)
	if err != nil {
		return appleFailure(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	if err := h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.download", id); err != nil {
		return err
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="profile.mobileconfig"`)
	return c.Blob(200, "application/x-apple-aspen-config", p.Payload)
}

func (h *Handler) AppleAssignProfile(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	revision, ids, desired, err := appleProfileAssignmentForm(c)
	if err != nil {
		return err
	}
	if err = h.Apple.AssignProfileWithAccess(c.Request().Context(), scope, id, revision, ids, desired, h.appleActor(c), h.Access); err != nil {
		if errors.Is(err, access.ErrDenied) {
			return echo.NewHTTPError(http.StatusForbidden, appleErrorText(c, "apple_errors.assignment_permission"))
		}
		return appleFailure(c, err)
	}
	if len(ids) == 1 {
		return appleRedirect(c, info, "/ios/"+ids[0])
	}
	return appleRedirect(c, info, "/ios/configurations")
}

func (h *Handler) AppleDeleteProfile(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	if err = h.Apple.DeleteProfile(c.Request().Context(), scope.TenantID, id, h.appleActor(c)); err != nil {
		return appleFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/configurations")
}

func (h *Handler) AppleUpdate(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	submission, err := appleUpdateForm(c)
	if err != nil {
		return err
	}
	if err = h.Apple.SetReviewedDeviceUpdatePolicy(c.Request().Context(), scope, id, submission.expectedPolicy, submission.policy, h.appleActor(c), h.Access); err != nil {
		if errors.Is(err, access.ErrDenied) {
			return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "updates.permission_denied"))
		}
		if errors.Is(err, apple.ErrUpdatePolicyReview) {
			return echo.NewHTTPError(http.StatusConflict, i18n.T(c.Request().Context(), "updates.review_changed"))
		}
		if errors.Is(err, apple.ErrUpdateExceptionActive) {
			return echo.NewHTTPError(http.StatusConflict, i18n.T(c.Request().Context(), "updates.exception_blocks_assignment"))
		}
		if errors.Is(err, apple.ErrUpdatePlanGroupIntegrity) || errors.Is(err, apple.ErrUpdateExceptionIntegrity) {
			return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "updates.assessment_unavailable"))
		}
		return appleFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) AppleRetryCommand(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	command := c.Param("command")
	if _, err = uuid.Parse(command); err != nil {
		return appleFailure(c, apple.ErrNotFound)
	}
	if err = h.Apple.RetryCommand(c.Request().Context(), scope, id, command, h.appleActor(c)); err != nil {
		return appleFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func deviceViewRows(ctx context.Context, entries []inventory.DeviceEntry) []mdm_views.DeviceRow {
	rows := make([]mdm_views.DeviceRow, 0, len(entries))
	for _, d := range entries {
		path := "/computers/" + url.PathEscape(d.ID)
		state := d.Status
		switch d.Kind {
		case "apple":
			path = "/ios/" + d.ID
		case "mac":
			path = "/mac/" + d.ID
			state = i18n.T(ctx, "mdm.devices.mac_channels", mdm_views.StateLabel(ctx, d.Status), mdm_views.StateLabel(ctx, d.AgentStatus))
		case "windows":
			path = "/windows/" + d.ID
			state = i18n.T(ctx, "mdm.devices."+d.Status)
		}
		platform := i18n.T(ctx, "mdm.devices.platform_"+d.Platform)
		if d.Kind == "apple" && d.Platform == "unknown" {
			platform = i18n.T(ctx, "mdm.devices.platform_apple_unknown")
		}
		rows = append(rows, mdm_views.DeviceRow{ID: d.ID, Name: d.Name, Platform: platform, OSVersion: d.OSVersion, Model: d.Model, Serial: d.Serial, Status: state, LastSeen: d.LastSeen, URL: fmt.Sprintf("/tenant/%d/site/%d%s", d.TenantID, d.SiteID, path)})
	}
	return rows
}
