package handlers

import (
	"errors"
	"net/url"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsRenewalFailure(err error) error {
	switch {
	case errors.Is(err, windows.ErrRenewalConflict):
		return echo.NewHTTPError(409, "The renewal changed or is already complete. Open its current detail before taking another action.")
	case errors.Is(err, windows.ErrConsoleInput):
		return echo.NewHTTPError(400, "Invalid certificate renewal request")
	default:
		return windowsFailure(err)
	}
}

func (h *Handler) WindowsCertificateRenewals(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	query, err := url.ParseQuery(c.Request().URL.RawQuery)
	if err != nil || c.Request().URL.ForceQuery || len(query) > 1 || (len(query) == 1 && (!query.Has("offset") || len(query["offset"]) != 1 || query.Get("offset") == "")) {
		return echo.NewHTTPError(400, "Invalid renewal history page")
	}
	offset, err := windowsOffset(c, "offset")
	if err != nil {
		return err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsRenewalFailure(err)
	}
	history, err := h.Windows.CertificateRenewals(c.Request().Context(), h.appleActor(c), scope, device.ID, offset, 11)
	if err != nil {
		return windowsRenewalFailure(err)
	}
	more := len(history) > 10
	if more {
		history = history[:10]
	}
	return renderApple(c, windows_views.CertificateRenewals(c, info, *device, history, offset, more))
}

func (h *Handler) WindowsCertificateRenewal(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	if c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery {
		return echo.NewHTTPError(400, "Renewal details do not accept query parameters")
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return windowsRenewalFailure(err)
	}
	detail, err := h.Windows.CertificateRenewalDetails(c.Request().Context(), h.appleActor(c), scope, device.ID, c.Param("renewal"))
	if err != nil {
		return windowsRenewalFailure(err)
	}
	return renderApple(c, windows_views.CertificateRenewal(c, info, *device, *detail))
}

func (h *Handler) WindowsCancelCertificateRenewal(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	form, err := windowsForm(c, "expected_revision", "resolution", "confirm_cancel")
	if err != nil {
		return err
	}
	revision, err := strconv.ParseInt(form.Get("expected_revision"), 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != form.Get("expected_revision") {
		return echo.NewHTTPError(400, "Review the current renewal revision")
	}
	if form.Get("confirm_cancel") != "yes" {
		return echo.NewHTTPError(400, "Confirm cancellation of this pending certificate replacement")
	}
	if !validWindowsCSPResolution(form.Get("resolution")) {
		return echo.NewHTTPError(400, "Enter a short, single-line cancellation reason without leading or trailing spaces")
	}
	if err := h.Windows.CancelCertificateRenewal(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), c.Param("renewal"), revision, form.Get("resolution")); err != nil {
		return windowsRenewalFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+c.Param("id")+"/renewals/"+c.Param("renewal"))
}
