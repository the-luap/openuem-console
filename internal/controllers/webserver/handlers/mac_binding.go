package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func (h *Handler) AppleMacBinding(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	if h.Desktop == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Individual agent enrollment is unavailable")
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	if strings.HasSuffix(c.Path(), "/cancel") {
		err = h.Apple.CancelMacBinding(c.Request().Context(), scope, id, h.appleActor(c))
	} else {
		err = h.Apple.RequestMacBinding(c.Request().Context(), scope, id, h.appleActor(c))
	}
	if err != nil {
		return macBindingFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) MacDevice(c echo.Context) error {
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
	mac, err := h.Apple.MacDevice(c.Request().Context(), scope, id)
	if err != nil {
		return macBindingFailure(err)
	}
	return h.renderAppleDevice(c, info, scope, mac.MDMID, mac)
}

func macBindingFailure(err error) error {
	if errors.Is(err, apple.ErrNotFound) || errors.Is(err, apple.ErrConflict) || errors.Is(err, apple.ErrMacBinding) {
		return appleFailure(err)
	}
	return echo.NewHTTPError(http.StatusInternalServerError, "Mac management channels are unavailable. Try again later.")
}
