package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func adeWorkflowFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Automated enrollment permission denied for this organization or site")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(404, "Automated enrollment record not found in this scope")
	case errors.Is(err, apple.ErrADEProfile), errors.Is(err, apple.ErrConflict), errors.Is(err, apple.ErrADE):
		return echo.NewHTTPError(409, "The automated enrollment action is unavailable. Check the selected profile, connection, site, current device state and APNs certificate. Each connection retains up to 256 profile versions.")
	default:
		return echo.NewHTTPError(503, "Automated enrollment could not be updated. Reload the page to check the recorded state before retrying.")
	}
}

func adeEnrollmentForm(c echo.Context, fields ...string) (url.Values, error) {
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 128<<10)
	if c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery || c.Request().ParseForm() != nil {
		return nil, echo.NewHTTPError(400, "Invalid automated enrollment form")
	}
	f := c.Request().PostForm
	allowed := map[string]bool{"csrf": true, "confirmed": true}
	for _, k := range fields {
		allowed[k] = true
	}
	for k, v := range f {
		if !allowed[k] || len(v) != 1 {
			return nil, echo.NewHTTPError(400, "Ambiguous automated enrollment form")
		}
	}
	if len(f["csrf"]) != 1 || f.Get("confirmed") != "yes" {
		return nil, echo.NewHTTPError(400, "Confirm the automated enrollment action")
	}
	return f, nil
}

func adeProfileOptions(f url.Values, site int) (apple.ADEProfileOptions, error) {
	if site == 0 {
		var err error
		site, err = strconv.Atoi(f.Get("site_id"))
		if err != nil || site <= 0 {
			return apple.ADEProfileOptions{}, echo.NewHTTPError(400, "Select a site for automated enrollment")
		}
	} else if value := f.Get("site_id"); value != "" && value != strconv.Itoa(site) {
		return apple.ADEProfileOptions{}, echo.NewHTTPError(400, "The selected site must match this page")
	}
	for _, k := range []string{"await_configuration", "allow_device_lock", "auto_advance", "ignore_backup_profile"} {
		if f.Get(k) != "" && f.Get(k) != "yes" {
			return apple.ADEProfileOptions{}, echo.NewHTTPError(400, "Invalid automated enrollment option")
		}
	}
	if f.Get("removal") != "allowed" && f.Get("removal") != "disallowed" {
		return apple.ADEProfileOptions{}, echo.NewHTTPError(400, "Choose whether users may remove management")
	}
	return apple.ADEProfileOptions{SiteID: site, Platform: apple.Platform(f.Get("platform")), Name: f.Get("name"), Department: f.Get("department"), SupportEmail: f.Get("support_email"), SupportPhone: f.Get("support_phone"), Removable: f.Get("removal") == "allowed", AwaitConfiguration: f.Get("await_configuration") == "yes", AllowDeviceLock: f.Get("allow_device_lock") == "yes", AutoAdvance: f.Get("auto_advance") == "yes", IgnoreBackupProfile: f.Get("ignore_backup_profile") == "yes", SkipSetupItems: strings.FieldsFunc(f.Get("skip_setup_items"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })}, nil
}

func (h *Handler) AppleCreateADEProfile(c echo.Context) error {
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
	f, err := adeEnrollmentForm(c, "site_id", "platform", "name", "department", "support_email", "support_phone", "removal", "await_configuration", "allow_device_lock", "auto_advance", "ignore_backup_profile", "skip_setup_items")
	if err != nil {
		return err
	}
	o, err := adeProfileOptions(f, scope.SiteID)
	if err != nil {
		return err
	}
	if _, err = h.Apple.CreateADEProfile(c.Request().Context(), scope.TenantID, id, o, h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/ade?server="+url.QueryEscape(id))
}

func (h *Handler) AppleChangeADEProfile(c echo.Context) error {
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
	p, err := uuid.Parse(c.Param("profile"))
	if err != nil || p.String() != c.Param("profile") {
		return echo.NewHTTPError(404, "Enrollment profile not found")
	}
	f, err := adeEnrollmentForm(c, "operation")
	if err != nil {
		return err
	}
	if err = h.Apple.ChangeADEProfile(c.Request().Context(), scope.TenantID, id, p.String(), f.Get("operation"), h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/ade?server="+url.QueryEscape(id))
}

func (h *Handler) AppleSetADETargets(c echo.Context) error {
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
	f, err := adeEnrollmentForm(c, "profile_id", "serials")
	if err != nil {
		return err
	}
	profile := f.Get("profile_id")
	if profile == "clear" {
		profile = ""
	} else {
		p, err := uuid.Parse(profile)
		if err != nil || p.String() != profile {
			return echo.NewHTTPError(400, "Select a published profile or clear the assignment")
		}
	}
	serials := strings.FieldsFunc(strings.ToUpper(f.Get("serials")), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
	if err = h.Apple.SetADETargets(c.Request().Context(), scope.TenantID, id, profile, serials, h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/ade?server="+url.QueryEscape(id))
}

func (h *Handler) AppleRearmADETarget(c echo.Context) error {
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
	if _, err = adeEnrollmentForm(c); err != nil {
		return err
	}
	if err = h.Apple.RearmADETarget(c.Request().Context(), scope.TenantID, id, c.Param("serial"), h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/ade?server="+url.QueryEscape(id))
}

func (h *Handler) AppleRetryADESetup(c echo.Context) error {
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
	if _, err = adeEnrollmentForm(c); err != nil {
		return err
	}
	if err = h.Apple.RetryADESetup(c.Request().Context(), scope, id, h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}
