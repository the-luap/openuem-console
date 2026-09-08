package handlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func (h *Handler) AppleFileVault(c echo.Context) error {
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
	if err = h.Apple.SetFileVault(c.Request().Context(), scope, id, c.FormValue("desired"), h.appleActor(c), h.Access); err != nil {
		if errors.Is(err, access.ErrDenied) {
			return echo.NewHTTPError(http.StatusForbidden, "FileVault management permission denied")
		}
		return appleFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) AppleFileVaultValidate(c echo.Context) error {
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
	key, err := uuid.Parse(c.Param("key"))
	if err != nil {
		return appleFailure(apple.ErrNotFound)
	}
	if err = h.Apple.RequestFileVaultValidation(c.Request().Context(), scope, id, key.String(), h.appleActor(c), h.Access); err != nil {
		if errors.Is(err, access.ErrDenied) {
			return echo.NewHTTPError(http.StatusForbidden, "FileVault validation permission denied")
		}
		return appleFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) AppleFileVaultKey(c echo.Context) error {
	// No console layout, scripts, assets or referrers in a secret response.
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
	keyID, err := uuid.Parse(c.Param("key"))
	if err != nil {
		return appleFailure(apple.ErrNotFound)
	}
	key, err := h.Apple.RevealFileVaultKey(c.Request().Context(), scope, id, keyID.String(), h.appleActor(c), h.Access)
	if err != nil {
		if errors.Is(err, access.ErrDenied) {
			return echo.NewHTTPError(http.StatusForbidden, "Recovery retrieval permission denied")
		}
		return appleFailure(err)
	}
	defer clear(key)
	return c.Blob(http.StatusOK, "text/plain; charset=utf-8", key)
}
