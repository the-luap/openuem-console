package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func softwareFailure(err error) error {
	switch {
	case errors.Is(err, apple.ErrWindowsSoftware):
		return echo.NewHTTPError(400, "Check the Windows package type, exact version, architecture, detection rule, HTTPS sources, SHA-256 values and argument formats")
	case errors.Is(err, apple.ErrMacAppPriorEnrollment):
		return echo.NewHTTPError(409, "An earlier enrollment has an unresolved application operation or an active duplicate identity. Review previous enrollments on the Mac's managed applications page before requesting another mutation.")
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Software permission denied")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(404, "Software or device record not found in this scope")
	case errors.Is(err, apple.ErrMacApp):
		return echo.NewHTTPError(400, "Check the package identity, bundle version, architecture, minimum OS, lowercase SHA-256 and encoded HTTPS package URL")
	case errors.Is(err, apple.ErrConflict):
		return echo.NewHTTPError(409, "The application action is unavailable. Check approval, device compatibility, current inventory and unresolved operations.")
	default:
		return echo.NewHTTPError(503, "Software management is temporarily unavailable")
	}
}

func softwareID(value string) (string, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return "", echo.NewHTTPError(400, "Invalid software or device identifier")
	}
	return value, nil
}

func softwareCheckbox(form url.Values, name string) (bool, error) {
	value := form.Get(name)
	if value != "" && value != "yes" {
		return false, echo.NewHTTPError(400, "Invalid software option")
	}
	return value == "yes", nil
}

func (h *Handler) SoftwareCatalog(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	query, platform := c.QueryParam("q"), c.QueryParam("platform")
	if len(strings.TrimSpace(query)) > 128 || (platform != "" && platform != "macos" && platform != "windows") {
		return echo.NewHTTPError(http.StatusBadRequest, "Choose a listed platform and use at most 128 bytes for the package search")
	}
	items, next, err := h.Apple.ReadSoftwareCatalog(c.Request().Context(), scope, c.QueryParam("before"), query, platform, h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.SoftwareCatalog(c, info, items, next, scope.SiteID == 0 && info.Can(access.ManageSoftware), mdm_views.SoftwareCatalogSearch{Query: query, Platform: platform}))
}

func (h *Handler) SoftwareVersion(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := softwareID(c.Param("version"))
	if err != nil {
		return err
	}
	v, err := h.Apple.ReadSoftwareVersion(c.Request().Context(), scope, id, h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	eligible := []apple.Device{}
	query, next := strings.TrimSpace(c.QueryParam("q")), ""
	if len(query) > 128 {
		return echo.NewHTTPError(http.StatusBadRequest, "Use at most 128 bytes for the device search")
	}
	if info.Can(access.AssignSoftware) && v.WithdrawnAt == nil && v.Platform == "macos" {
		eligible, next, err = h.Apple.MacAppDevices(c.Request().Context(), scope, *v, query, c.QueryParam("after"))
		if err != nil {
			return softwareFailure(err)
		}
	}
	return RenderView(c, mdm_views.SoftwareVersion(c, info, *v, eligible, scope.SiteID == 0 && info.Can(access.ManageSoftware), mdm_views.SoftwareDeviceSearch{Query: query, Next: next}))
}

func (h *Handler) PublishMacAppPackage(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "name", "identifier", "version", "architecture", "minimum_os", "sha256", "source_url", "single_app")
	if err != nil {
		return err
	}
	single, err := softwareCheckbox(f, "single_app")
	if err != nil {
		return err
	}
	p := apple.MacAppPackageInput{Name: f.Get("name"), Identifier: f.Get("identifier"), Version: f.Get("version"), Architecture: f.Get("architecture"), MinimumOS: f.Get("minimum_os"), SHA256: f.Get("sha256"), SourceURL: f.Get("source_url"), SingleApp: single}
	v, err := h.Apple.PublishMacAppPackage(c.Request().Context(), scope, p, h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+v.ID)
}

func (h *Handler) WithdrawSoftwareVersion(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := softwareID(c.Param("version"))
	if err != nil {
		return err
	}
	if _, err = adeEnrollmentForm(c); err != nil {
		return err
	}
	if err = h.Apple.WithdrawSoftwareVersion(c.Request().Context(), scope, id, h.appleActor(c), h.Access); err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+id)
}

func (h *Handler) InstallMacApp(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, err := softwareID(c.Param("version"))
	if err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "device", "remove_on_unenroll", "take_over")
	if err != nil {
		return err
	}
	device, err := softwareID(f.Get("device"))
	if err != nil {
		return err
	}
	remove, err := softwareCheckbox(f, "remove_on_unenroll")
	if err != nil {
		return err
	}
	takeOver, err := softwareCheckbox(f, "take_over")
	if err != nil {
		return err
	}
	if err = h.Apple.InstallMacApp(c.Request().Context(), scope, device, version, h.appleActor(c), apple.MacAppInstallOptions{RemoveOnUnenroll: remove, TakeOver: takeOver}, h.Access); err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+device+"/applications")
}

func (h *Handler) MacApplications(c echo.Context) error {
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
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return softwareFailure(err)
	}
	if d.Family() != apple.PlatformMacOS {
		return echo.NewHTTPError(http.StatusConflict, "Managed package installation requires a Mac")
	}
	items, next, err := h.Apple.MacApps(c.Request().Context(), scope, id, c.QueryParam("after"))
	if err != nil {
		return softwareFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "software.inventory.read", id); err != nil {
		return softwareFailure(err)
	}
	risk, err := h.Apple.MacAppEnrollmentRisk(c.Request().Context(), scope, id)
	if err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.MacApplications(c, info, d, items, next, risk))
}

func (h *Handler) MacApplicationHistory(c echo.Context) error {
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
	assignment, err := softwareID(c.Param("assignment"))
	if err != nil {
		return err
	}
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return softwareFailure(err)
	}
	items, next, err := h.Apple.MacAppHistory(c.Request().Context(), scope, id, assignment, c.QueryParam("before"))
	if err != nil {
		return softwareFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "software.inventory.read", id); err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.MacApplicationHistory(c, info, d, assignment, items, next))
}

func (h *Handler) ChangeMacApp(c echo.Context) error {
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
	assignment, err := softwareID(c.Param("assignment"))
	if err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "operation")
	if err != nil {
		return err
	}
	if err = h.Apple.ChangeMacApp(c.Request().Context(), scope, id, assignment, f.Get("operation"), h.appleActor(c), h.Access); err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id+"/applications")
}
