package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func recoveryLockFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, "Recovery Lock permission denied")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "Recovery Lock record not found")
	case errors.Is(err, apple.ErrConflict):
		return echo.NewHTTPError(http.StatusConflict, "Recovery Lock state changed or another operation remains unresolved. Refresh the device page.")
	case errors.Is(err, apple.ErrRecoveryLock):
		return echo.NewHTTPError(http.StatusBadRequest, "Recovery Lock is unavailable. Check enrollment permissions, current device inventory and the selected password.")
	default:
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Recovery Lock is temporarily unavailable")
	}
}

func (h *Handler) AppleRecoveryLock(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
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
	if err = c.Request().ParseForm(); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid Recovery Lock form")
	}
	f := c.Request().PostForm
	defer func() { f.Del("password"); c.Request().Form.Del("password") }()
	for _, key := range []string{"operation", "key_id", "password", "confirm_recovery_lock"} {
		if len(f[key]) > 1 || len(c.QueryParams()[key]) != 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Ambiguous Recovery Lock form")
		}
	}
	if len(f["operation"]) != 1 {
		return echo.NewHTTPError(http.StatusBadRequest, "Choose a Recovery Lock action")
	}
	op := f.Get("operation")
	if op != "verify" && op != "recheck" && (len(f["confirm_recovery_lock"]) != 1 || f.Get("confirm_recovery_lock") != "yes") {
		return echo.NewHTTPError(http.StatusBadRequest, "Confirm the Recovery Lock action")
	}
	password := []byte(f.Get("password"))
	defer clear(password)
	f.Del("password")
	c.Request().Form.Del("password")
	if err = h.Apple.RequestRecoveryLock(c.Request().Context(), scope, id, op, f.Get("key_id"), password, h.appleActor(c), h.Access); err != nil {
		return recoveryLockFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) AppleRecoveryLockPassword(c echo.Context) error {
	header := c.Response().Header()
	header.Set("Cache-Control", "no-store, max-age=0")
	header.Set("Pragma", "no-cache")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
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
	password, err := h.Apple.RevealRecoveryLockPassword(c.Request().Context(), scope, id, c.Param("key"), h.appleActor(c), h.Access)
	if err != nil {
		return recoveryLockFailure(err)
	}
	defer clear(password)
	return c.Blob(http.StatusOK, "text/plain; charset=utf-8", password)
}
