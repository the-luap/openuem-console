package handlers

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) RegisterApple(e *echo.Echo) {
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		g := e.Group(prefix, h.IsAuthenticated, h.AppleCSRF)
		g.GET("/devices", h.UnifiedDevices)
		g.GET("/ios", h.UnifiedDevices)
		g.GET("/ios/setup", h.AppleSettings)
		g.POST("/ios/setup", h.AppleSettings)
		g.POST("/ios/enroll", h.AppleInvite)
		g.GET("/ios/configurations", h.AppleProfiles)
		g.POST("/ios/configurations", h.AppleSaveProfile)
		g.GET("/ios/configurations/:id/download", h.AppleDownloadProfile)
		g.POST("/ios/configurations/:id/assign", h.AppleAssignProfile)
		g.POST("/ios/configurations/:id/delete", h.AppleDeleteProfile)
		g.GET("/ios/:id", h.AppleDevice)
		g.POST("/ios/:id/refresh", h.AppleRefresh)
		g.POST("/ios/:id/revoke", h.AppleRevoke)
		g.POST("/ios/:id/update", h.AppleUpdate)
		g.POST("/ios/:id/commands/:command/retry", h.AppleRetryCommand)
	}
}

func (h *Handler) AppleCSRF(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Request().Method == http.MethodPost {
			c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 4<<20)
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
	c.Response().Header().Set("Referrer-Policy", "strict-origin")
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
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	rows := []mdm_views.DeviceRow{}
	platform := c.QueryParam("platform")
	if strings.HasSuffix(c.Path(), "/ios") {
		platform = "ios"
	}
	search := strings.ToLower(strings.TrimSpace(c.QueryParam("q")))
	if platform != "ios" {
		p := partials.PaginationAndSort{SortBy: "nickname", SortOrder: "asc"}
		computers, err := h.Model.GetComputersByPage(p, filters.AgentFilter{}, info)
		if err != nil {
			return err
		}
		for _, d := range computers {
			if platform == "windows" && !strings.EqualFold(d.OS, "windows") {
				continue
			}
			name := d.Nickname
			if name == "" {
				name = d.Hostname
			}
			seen := d.LastContact
			deviceURL := ""
			if info.Principal.IsAdministrator() {
				deviceURL = partials.GetNavigationUrl(info, "/computers/"+d.ID)
			}
			rows = append(rows, mdm_views.DeviceRow{ID: d.ID, Name: name, Platform: d.OS, OSVersion: d.Version, Serial: d.Serial, Model: d.Model, Status: "agent", LastSeen: &seen, URL: deviceURL})
		}
	}
	if h.Apple != nil && platform != "windows" {
		devices, err := h.Apple.Devices(c.Request().Context(), scope)
		if err != nil {
			return err
		}
		for _, d := range devices {
			rows = append(rows, mdm_views.DeviceRow{ID: d.ID, Name: d.Name, Platform: d.Platform(), OSVersion: d.OSVersion, Serial: d.SerialNumber, Model: d.Model, Status: d.Status, LastSeen: d.LastSeen, URL: partials.GetNavigationUrl(info, "/ios/"+d.ID)})
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
	return renderApple(c, mdm_views.Devices(c, info, rows, platform, search, h.AppleSetupError))
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
			message = "Apple push credentials saved. You can now create an enrollment invitation."
		}
	}
	var settings *apple.Settings
	if h.Apple != nil {
		settings, err = h.Apple.Settings(c.Request().Context(), scope.TenantID)
		if err != nil && !errors.Is(err, apple.ErrNotFound) {
			return err
		}
	}
	return renderApple(c, mdm_views.Setup(c, info, settings, setupError, message, os.Getenv("APPLE_MDM_LISTEN_ADDR") != ""))
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
	invite, err := h.Apple.Invite(c.Request().Context(), scope, c.FormValue("name"), h.appleActor(c))
	if err != nil {
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
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return appleFailure(err)
	}
	detail := mdm_views.Detail{Device: d}
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
		detail.Releases = catalog.Releases(d.Model, time.Now())
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
	if c.FormValue("editor") == "upload" {
		data, err = readAppleUpload(c, "profile", apple.MaxProfileBytes)
	} else {
		settings := map[string]any{"SSID_STR": c.FormValue("ssid"), "EncryptionType": c.FormValue("wifi_security"), "Password": c.FormValue("wifi_password")}
		length, _ := strconv.Atoi(c.FormValue("min_length"))
		settings["minLength"] = length
		settings["requireAlphanumeric"] = c.FormValue("alphanumeric") == "on"
		for _, key := range []string{"allowCamera", "allowScreenShot", "allowCloudBackup", "allowAppInstallation", "allowAirDrop"} {
			if c.FormValue(key) != "" {
				settings[key] = c.FormValue(key) == "true"
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
