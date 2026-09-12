package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

// Database and cryptographic errors may carry implementation details. New push
// request routes return fixed messages instead of displaying underlying errors.
func applePushRequestFailure(c echo.Context, err error) error {
	if errors.Is(err, apple.ErrPushConnection) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, apple.ErrPushConnection.Error())
	}
	if errors.Is(err, apple.ErrPushCertificate) {
		return echo.NewHTTPError(http.StatusBadRequest, apple.ErrPushCertificate.Error())
	}
	if errors.Is(err, apple.ErrVendorNotConfigured) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, apple.ErrVendorNotConfigured.Error())
	}
	if errors.Is(err, apple.ErrVendorRequest) {
		return echo.NewHTTPError(http.StatusBadRequest, apple.ErrVendorRequest.Error())
	}
	if errors.Is(err, apple.ErrNotFound) || errors.Is(err, apple.ErrConflict) {
		return appleFailure(c, err)
	}
	return echo.NewHTTPError(http.StatusBadRequest, "The push request could not be processed. Check the organization, request status and certificate. Revoke unused requests if five are already pending.")
}

func (h *Handler) AppleAttachVendorRequest(c echo.Context) error {
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
	data, err := readAppleUpload(c, "vendor_request", apple.MaxVendorPortalRequest)
	if err != nil {
		return applePushRequestFailure(c, err)
	}
	if err = h.Apple.AttachVendorRequest(c.Request().Context(), scope.TenantID, id, data, h.appleActor(c)); err != nil {
		return applePushRequestFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/setup")
}

func (h *Handler) AppleVendorPortalRequest(c echo.Context) error {
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
	data, err := h.Apple.VendorPortalRequest(c.Request().Context(), scope.TenantID, id, h.appleActor(c))
	if err != nil {
		return applePushRequestFailure(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("X-Content-Type-Options", "nosniff")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	c.Response().Header().Set("Content-Disposition", `attachment; filename="openuem-apple-push-`+id+`.plist"`)
	return c.Blob(http.StatusOK, "application/octet-stream", data)
}

func (h *Handler) AppleCreatePushRequest(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	if c.FormValue("confirmed") != "yes" {
		return echo.NewHTTPError(http.StatusBadRequest, "Confirm the organization, public management URL and authorized vendor before creating a CSR.")
	}
	_, err = h.Apple.CreatePushRequest(c.Request().Context(), scope.TenantID, c.FormValue("organization"), c.FormValue("public_url"), c.FormValue("apple_account"), h.appleActor(c))
	if err != nil {
		return applePushRequestFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/setup")
}

func (h *Handler) ApplePushRequestCSR(c echo.Context) error {
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
	csr, err := h.Apple.PushRequestCSR(c.Request().Context(), scope.TenantID, id, h.appleActor(c))
	if err != nil {
		return applePushRequestFailure(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("X-Content-Type-Options", "nosniff")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	c.Response().Header().Set("Content-Disposition", `attachment; filename="openuem-vendor-input-`+id+`.csr"`)
	return c.Blob(http.StatusOK, "application/pkcs10", csr)
}

func (h *Handler) AppleRevokePushRequest(c echo.Context) error {
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
	if err = h.Apple.RevokePushRequest(c.Request().Context(), scope.TenantID, id, h.appleActor(c)); err != nil {
		return applePushRequestFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/setup")
}

func (h *Handler) AppleImportPushCertificate(c echo.Context) error {
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
	cert, err := readAppleUpload(c, "push_certificate", 64<<10)
	if err != nil {
		return applePushRequestFailure(c, err)
	}
	if err = h.Apple.ImportPushCertificate(c.Request().Context(), scope.TenantID, id, cert, h.appleActor(c)); err != nil {
		return applePushRequestFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/setup")
}
