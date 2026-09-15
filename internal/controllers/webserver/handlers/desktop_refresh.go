package handlers

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"sync"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

// Broker initialization may retry after the HTTP service starts. Keep the
// refresh worker's publisher independent of legacy mutable connection fields.
type inventoryPublisher struct {
	mu sync.RWMutex
	js jetstream.JetStream
}

func (h *Handler) setInventoryPublisher(js jetstream.JetStream) {
	h.inventoryPublisher.mu.Lock()
	defer h.inventoryPublisher.mu.Unlock()
	h.inventoryPublisher.js = js
}

func (h *Handler) PublishInventoryReport(ctx context.Context, deviceID, requestID string) error {
	request, err := uuid.Parse(requestID)
	if !inventory.ValidReportDeviceID(deviceID) || err != nil || request == uuid.Nil || request.String() != requestID {
		return inventory.ErrRefreshInvalid
	}
	h.inventoryPublisher.mu.RLock()
	js := h.inventoryPublisher.js
	h.inventoryPublisher.mu.RUnlock()
	if js == nil {
		return inventory.ErrRefreshNotReady
	}
	ack, err := js.Publish(ctx, "agent.report."+deviceID, nil, jetstream.WithMsgID(requestID), jetstream.WithExpectStream("AGENTS_STREAM"))
	if err != nil {
		return err
	}
	if ack == nil || ack.Stream != "AGENTS_STREAM" || ack.Sequence == 0 {
		return inventory.ErrRefreshNotReady
	}
	return nil
}

func readDesktopRefreshForm(c echo.Context) (string, error) {
	if c.Request().ContentLength > 8<<10 {
		return "", inventory.ErrRefreshInvalid
	}
	contentType, _, err := mime.ParseMediaType(c.Request().Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		return "", inventory.ErrRefreshInvalid
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 8<<10)
	if err = c.Request().ParseForm(); err != nil {
		return "", inventory.ErrRefreshInvalid
	}
	if len(c.Request().PostForm.Encode()) > 8<<10 {
		return "", inventory.ErrRefreshInvalid
	}
	for key, values := range c.Request().PostForm {
		if key != "csrf" && key != "request_id" || len(values) != 1 {
			return "", inventory.ErrRefreshInvalid
		}
	}
	id := c.Request().PostForm.Get("request_id")
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return "", inventory.ErrRefreshInvalid
	}
	return id, nil
}

func (h *Handler) DesktopRefresh(c echo.Context) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	requestID, err := readDesktopRefreshForm(c)
	if err != nil {
		return desktopRefreshFailure(err)
	}
	if h.InventoryRefresh == nil {
		return desktopRefreshFailure(inventory.ErrRefreshNotReady)
	}
	_, err = h.InventoryRefresh.Request(c.Request().Context(), info.Principal.UserID, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"), requestID)
	if err != nil {
		return desktopRefreshFailure(err)
	}
	location := string(partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(c.Param("uuid"))+"/inventory"))
	c.Response().Header().Set("Cache-Control", "no-store")
	if c.Request().Header.Get("HX-Request") == "true" {
		c.Response().Header().Set("HX-Redirect", location)
		return c.NoContent(http.StatusNoContent)
	}
	return c.Redirect(http.StatusSeeOther, location)
}

func desktopRefreshFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, "Inventory refresh is not permitted for this organization or site")
	case errors.Is(err, inventory.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "Computer not found")
	case errors.Is(err, inventory.ErrRefreshInvalid):
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid inventory refresh request")
	case errors.Is(err, inventory.ErrRefreshConflict):
		return echo.NewHTTPError(http.StatusConflict, "An inventory refresh is already pending or this request changed. Reload the computer inventory.")
	case errors.Is(err, inventory.ErrRefreshRecent):
		return echo.NewHTTPError(http.StatusTooManyRequests, "An inventory refresh was requested recently. Try again in one minute.")
	case errors.Is(err, inventory.ErrRefreshNotReady):
		return echo.NewHTTPError(http.StatusServiceUnavailable, "The agent's command channel is not ready for an inventory refresh.")
	default:
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Inventory refresh is unavailable. Try again later.")
	}
}
