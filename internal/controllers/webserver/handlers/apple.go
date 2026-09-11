package handlers

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func (h *Handler) RegisterApple(e *echo.Echo) {
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		g := e.Group(prefix, h.IsAuthenticated, h.AppleCSRF)
		g.GET("/software/catalog", h.SoftwareCatalog)
		g.POST("/software/catalog", h.PublishMacAppPackage)
		g.GET("/software/catalog/windows/new", h.WindowsSoftwareApproval)
		g.POST("/software/catalog/windows", h.PublishWindowsSoftware)
		g.GET("/software/catalog/:version", h.SoftwareVersion)
		g.GET("/software/catalog/:version/windows-requests", h.WindowsSoftwareRequests)
		g.POST("/software/catalog/:version/windows-requests", h.PrepareWindowsSoftware)
		g.POST("/software/catalog/:version/windows-requests/:request/cancel", h.CancelWindowsSoftwarePreparation)
		g.GET("/software/catalog/:version/windows-requests/:request/dispatch", h.ReviewWindowsSoftwareDispatch)
		g.POST("/software/catalog/:version/windows-requests/:request/dispatch", h.DispatchWindowsSoftware)
		g.POST("/software/catalog/:version/windows-requests/:request/dispatch/cancel", h.CancelWindowsSoftwareDispatch)
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
		if c.Request().Method == http.MethodPost {
			limit := int64(4 << 20)
			switch appleRoute(c.Path()) {
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
func appleFailure(err error) error {
	if errors.Is(err, apple.ErrNotFound) {
		return echo.NewHTTPError(404, "Resource not found")
	}
	if errors.Is(err, apple.ErrConflict) {
		return echo.NewHTTPError(409, "This resource changed. Reload and try again.")
	}
	return echo.NewHTTPError(400, err.Error())
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

func desktopPlatform(os string) string {
	switch strings.ToLower(strings.TrimSpace(os)) {
	case "windows":
		return "windows"
	case "darwin", "macos", "mac os x":
		return "macos"
	case "linux":
		return "linux"
	default:
		return "unknown"
	}
}

func (h *Handler) UnifiedDevices(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	rows := []mdm_views.DeviceRow{}
	nativeWindowsLimited := false
	platform := c.QueryParam("platform")
	if strings.HasSuffix(c.Path(), "/ios") && platform == "" {
		platform = "apple"
	}
	switch platform {
	case "", "apple", "ios", "ipados", "macos", "windows", "linux", "unknown":
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid platform filter")
	}
	search := strings.ToLower(strings.TrimSpace(c.QueryParam("q")))
	mdmAliases, agentAliases := map[string]string{}, map[string]string{}
	if h.Apple != nil && (platform == "" || platform == "apple" || platform == "macos") {
		mdmAliases, agentAliases, err = h.Apple.MacAliases(c.Request().Context(), scope)
		if err != nil {
			return err
		}
		macs, e := h.Apple.MacDevices(c.Request().Context(), scope)
		if e != nil {
			return e
		}
		for _, m := range macs {
			state := "MDM: " + mdm_views.StateLabel(m.MDMStatus) + " · Agent: " + mdm_views.StateLabel(m.AgentStatus)
			seen := m.LastSeen
			if m.AgentSeen != nil && (seen == nil || m.AgentSeen.After(*seen)) {
				seen = m.AgentSeen
			}
			rows = append(rows, mdm_views.DeviceRow{ID: m.ID, Name: m.Name, Platform: "macOS", OSVersion: m.OSVersion, Model: m.Model, Serial: m.Serial, Status: state, LastSeen: seen, URL: partials.GetNavigationUrl(info, "/mac/"+m.ID)})
		}
	}
	if platform == "" || platform == "windows" || platform == "macos" || platform == "linux" || platform == "unknown" {
		p := partials.PaginationAndSort{SortBy: "nickname", SortOrder: "asc"}
		computers, err := h.Model.GetComputersByPage(p, filters.AgentFilter{}, info)
		if err != nil {
			return err
		}
		for _, d := range computers {
			if agentAliases[d.ID] != "" {
				continue
			}
			if platform != "" && platform != desktopPlatform(d.OS) {
				continue
			}
			name := d.Nickname
			if name == "" {
				name = d.Hostname
			}
			seen := d.LastContact
			deviceURL := partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(d.ID))
			rows = append(rows, mdm_views.DeviceRow{ID: d.ID, Name: name, Platform: d.OS, OSVersion: d.Version, Serial: d.Serial, Model: d.Model, Status: "agent", LastSeen: &seen, URL: deviceURL})
		}
	}
	if h.Apple != nil && platform != "windows" && platform != "linux" {
		devices, err := h.Apple.Devices(c.Request().Context(), scope)
		if err != nil {
			return err
		}
		for _, d := range devices {
			if mdmAliases[d.ID] != "" {
				continue
			}
			if platform != "" && platform != "apple" && platform != string(d.Family()) {
				continue
			}
			rows = append(rows, mdm_views.DeviceRow{ID: d.ID, Name: d.Name, Platform: d.Platform(), OSVersion: d.OSVersion, Serial: d.SerialNumber, Model: d.Model, Status: d.Status, LastSeen: d.LastSeen, URL: partials.GetNavigationUrl(info, "/ios/"+d.ID)})
		}
	}
	if h.Windows != nil && (platform == "" || platform == "windows") {
		devices, err := h.Windows.Devices(c.Request().Context(), h.appleActor(c), access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, "", 0, 100)
		if err != nil {
			return windowsFailure(err)
		}
		nativeWindowsLimited = len(devices) == 100
		for _, d := range devices {
			// Native MDM and agent identities remain separate until a verified
			// association exists. Enrollment hints cannot merge their authority.
			rows = append(rows, mdm_views.DeviceRow{ID: d.ID, Name: d.Name, Platform: "windows", OSVersion: d.OSVersion, Status: "Native MDM: " + windows_views.DeviceStatus(d), URL: fmt.Sprintf("/tenant/%d/site/%d/windows/%s", d.TenantID, d.SiteID, d.ID)})
		}
	}
	filtered := rows[:0]
	for _, r := range rows {
		if search == "" || strings.Contains(strings.ToLower(r.Name+" "+r.Serial+" "+r.Model+" "+r.OSVersion), search) {
			filtered = append(filtered, r)
		}
	}
	rows = filtered
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
	if h.Apple != nil {
		if err := h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "inventory.list", "devices"); err != nil {
			return err
		}
	}
	return renderApple(c, mdm_views.Devices(c, info, rows, platform, search, h.AppleSetupError, nativeWindowsLimited))
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
			return appleFailure(err)
		}
		key, err := readAppleUpload(c, "push_key", 64<<10)
		if err != nil {
			return appleFailure(err)
		}
		err = h.Apple.Configure(c.Request().Context(), apple.Settings{TenantID: scope.TenantID, Organization: c.FormValue("organization"), PublicURL: c.FormValue("public_url"), PushCertificate: cert, PushKey: key}, h.appleActor(c))
		if err != nil {
			setupError = err.Error()
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
			return appleFailure(errors.New("select a site"))
		}
		if c.Param("site") != "" && site != scope.SiteID {
			return echo.NewHTTPError(403, "Enrollment site does not match the selected scope")
		}
		if _, err = h.Model.GetSiteById(scope.TenantID, site); err != nil {
			return appleFailure(apple.ErrNotFound)
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
		return appleFailure(err)
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
		return appleFailure(err)
	}
	if entity != "" {
		return appleRedirect(c, info, "/mac/"+entity)
	}
	return h.renderAppleDevice(c, info, scope, id, nil)
}

func (h *Handler) renderAppleDevice(c echo.Context, info *partials.CommonInfo, scope apple.Scope, id string, mac *apple.MacDevice) error {
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return appleFailure(err)
	}
	detail := mdm_views.Detail{Device: d, Mac: mac}
	detail.ADE, err = h.Apple.ADEDeviceEnrollment(c.Request().Context(), scope, id)
	if err != nil {
		return appleFailure(err)
	}
	if detail.ADE != nil && info.Can(access.ReadSoftware) {
		detail.ADEApplications, err = h.Apple.ADEApplications(c.Request().Context(), scope, id)
		if err != nil {
			return appleFailure(err)
		}
	}
	if detail.ADE != nil && info.Can(access.ReadProfiles) {
		detail.ADEPlatformSSO, err = h.Apple.ADEPlatformSSOStatus(c.Request().Context(), scope, id)
		if err != nil {
			return appleFailure(err)
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
	detail.Policy, err = h.Apple.UpdatePolicy(c.Request().Context(), scope, id)
	if err != nil && !errors.Is(err, apple.ErrNotFound) {
		return err
	}
	if detail.Policy != nil {
		detail.Compliance = apple.UpdateCompliance(*d, *detail.Policy, time.Now())
	}
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
		return appleFailure(err)
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
		return appleFailure(err)
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
		return appleFailure(err)
	}
	id := c.FormValue("profile_id")
	revision, _ := strconv.Atoi(c.FormValue("revision"))
	if id != "" {
		if _, err = uuid.Parse(id); err != nil {
			return appleFailure(apple.ErrNotFound)
		}
	}
	if _, err = h.Apple.SaveProfile(c.Request().Context(), scope.TenantID, id, revision, data, h.appleActor(c)); err != nil {
		return appleFailure(err)
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
		return appleFailure(err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	if err := h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.download", id); err != nil {
		return err
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="profile.mobileconfig"`)
	return c.Blob(200, "application/x-apple-aspen-config", p.Payload)
}

func selectedAppleIDs(c echo.Context) ([]string, error) {
	if err := c.Request().ParseForm(); err != nil {
		return nil, err
	}
	ids := c.Request().PostForm["device_id"]
	for _, id := range ids {
		if _, err := uuid.Parse(id); err != nil {
			return nil, errors.New("invalid selected device")
		}
	}
	return ids, nil
}

func (h *Handler) AppleAssignProfile(c echo.Context) error {
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
	ids, err := selectedAppleIDs(c)
	if err != nil {
		return appleFailure(err)
	}
	if err = h.Apple.AssignProfile(c.Request().Context(), scope, id, ids, c.FormValue("desired"), h.appleActor(c)); err != nil {
		return appleFailure(err)
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
		return appleFailure(err)
	}
	return appleRedirect(c, info, "/ios/configurations")
}

func (h *Handler) AppleUpdate(c echo.Context) error {
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
	var policy *apple.UpdatePolicy
	if c.FormValue("remove") != "true" {
		version, build, selected := strings.Cut(c.FormValue("target_release"), "/")
		if !selected || version == "" || build == "" {
			return echo.NewHTTPError(400, "Select an available Apple release and build")
		}
		deadline := c.FormValue("deadline")
		if len(deadline) == 16 {
			deadline += ":00"
		}
		policy = &apple.UpdatePolicy{TargetVersion: version, TargetBuild: build, Deadline: deadline, DetailsURL: c.FormValue("details_url")}
	}
	if err = h.Apple.SetUpdatePolicy(c.Request().Context(), scope, []string{id}, policy, h.appleActor(c)); err != nil {
		return appleFailure(err)
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
		return appleFailure(apple.ErrNotFound)
	}
	if err = h.Apple.RetryCommand(c.Request().Context(), scope, id, command, h.appleActor(c)); err != nil {
		return appleFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}
