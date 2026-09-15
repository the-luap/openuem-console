package handlers

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func netbirdValues(c echo.Context, keys ...string) (url.Values, error) {
	r := c.Request()
	if r.Header.Get("Content-Encoding") != "" {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	var values url.Values
	var err error
	if r.Method == http.MethodGet {
		if r.ContentLength != 0 || len(r.URL.RawQuery) > 2048 {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
		values, err = url.ParseQuery(r.URL.RawQuery)
	} else if r.Method == http.MethodPost {
		media, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if parseErr != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.ContentLength > 8<<10 {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
		r.Body = http.MaxBytesReader(c.Response(), r.Body, 8<<10)
		err = r.ParseForm()
		values = r.PostForm
		keys = append(keys, "csrf", "confirmed")
		if values.Get("confirmed") != "yes" {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
	} else {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key, v := range values {
		if !allowed[key] || len(v) != 1 || len(v[0]) > 256 || !utf8.ValidString(v[0]) || strings.ContainsRune(v[0], 0) {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
	}
	return values, nil
}

func (h *Handler) netbirdInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return nil, access.Scope{}, err
	}
	if scope.SiteID <= 0 {
		return nil, access.Scope{}, netbirdFailure(inventory.ErrNetbirdOperationInvalid)
	}
	if h.NetbirdOperations == nil {
		return nil, access.Scope{}, netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	return info, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, nil
}

func (h *Handler) NetbirdOperationReview(c echo.Context) error {
	v, err := netbirdValues(c, "operation", "profile")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	review, err := h.NetbirdOperations.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), v.Get("operation"), v.Get("profile"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird command", desktop_views.NetbirdReview(c, info, review, uuid.NewString()), info))
}

func (h *Handler) NetbirdOperationRequest(c echo.Context) error { return h.netbirdRequest(c, "") }

func (h *Handler) netbirdRequest(c echo.Context, expected string) error {
	v, err := netbirdValues(c, "request_id", "operation", "profile", "revision")
	if err != nil {
		return netbirdFailure(err)
	}
	if expected != "" && expected != v.Get("operation") {
		return netbirdFailure(inventory.ErrNetbirdOperationInvalid)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdOperations.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), v.Get("request_id"), v.Get("operation"), v.Get("profile"), v.Get("revision"))
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdOperationPath(info, r.DeviceID)+"/"+r.ID)
}

func netbirdRedirect(c echo.Context, location string) error {
	if c.Request().Header.Get("HX-Request") == "true" {
		c.Response().Header().Set("HX-Redirect", location)
		return c.NoContent(http.StatusNoContent)
	}
	return c.Redirect(http.StatusSeeOther, location)
}

func (h *Handler) NetbirdOperationReceipt(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdOperations.Read(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird command receipt", desktop_views.NetbirdReceipt(c, info, r), info))
}

func (h *Handler) NetbirdOperationHistory(c echo.Context) error {
	v, err := netbirdValues(c, "before")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	rows, err := h.NetbirdOperations.History(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), v.Get("before"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird command history", desktop_views.NetbirdHistory(c, info, c.Param("uuid"), rows), info))
}

func (h *Handler) NetbirdOperationCancel(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	if err = h.NetbirdOperations.Cancel(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request")); err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdOperationPath(info, c.Param("uuid"))+"/"+c.Param("request"))
}

func netbirdFailure(err error) error {
	status, message := http.StatusServiceUnavailable, "NetBird commands are unavailable. Check the agent and try reviewing the command again."
	switch {
	case errors.Is(err, access.ErrDenied):
		status, message = http.StatusForbidden, "NetBird management is not permitted for this organization and site."
	case errors.Is(err, inventory.ErrNotFound):
		status, message = http.StatusNotFound, "NetBird device or command not found."
	case errors.Is(err, inventory.ErrNetbirdOperationInvalid), errors.Is(err, inventory.ErrManualInvalid):
		status, message = http.StatusBadRequest, "Invalid NetBird request. Select an exact organization and site and review the command."
	case errors.Is(err, inventory.ErrNetbirdOperationChanged):
		status, message = http.StatusConflict, "The device, NetBird configuration or journal changed. Review the command again."
	case errors.Is(err, inventory.ErrNetbirdOperationConflict):
		status, message = http.StatusConflict, "This command conflicts with a retained request or an unresolved execution. Review its history."
	case errors.Is(err, inventory.ErrManualUnsupported):
		status, message = http.StatusUnprocessableEntity, "This device platform does not support managed NetBird commands."
	}
	return echo.NewHTTPError(status, message)
}
