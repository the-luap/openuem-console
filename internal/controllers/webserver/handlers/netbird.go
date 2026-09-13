package handlers

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

// Netbird reads scoped report data. Opening this page never publishes a command
// or contacts a provider. Generic navigation resolves to the device's exact site.
func (h *Handler) Netbird(c echo.Context, successMessage string) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdFailure(err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	if scope.SiteID == 0 {
		target, err := inventory.ReadDesktop(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, access.Scope{TenantID: scope.TenantID}, c.Param("uuid"))
		if err != nil {
			return netbirdFailure(err)
		}
		return netbirdRedirect(c, fmt.Sprintf("/tenant/%d/site/%d/computers/%s/netbird", target.TenantID, target.SiteID, target.ID))
	}
	if h.NetbirdOperations == nil {
		return netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	page, err := h.NetbirdOperations.Overview(c.Request().Context(), info.Principal.UserID, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird", desktop_views.NetbirdOverview(c, info, page, uuid.NewString()), info))
}

func (h *Handler) NetbirdConnect(c echo.Context) error { return h.netbirdRequest(c, "up") }
func (h *Handler) NetbirdDisconnect(c echo.Context, successMessage string) error {
	return h.netbirdRequest(c, "down")
}
func (h *Handler) NetbirdSwitchProfile(c echo.Context) error {
	return h.netbirdRequest(c, "switchprofile")
}
func (h *Handler) NetbirdRefresh(c echo.Context) error { return h.DesktopRefresh(c) }

// These legacy envelopes cannot be given durable identity by inventing a UUID.
// Their provider/device stages need their own reviewed admission and recovery.
func (h *Handler) netbirdLifecycleUnavailable(c echo.Context) error {
	if _, _, err := h.netbirdInfo(c); err != nil {
		return err
	}
	return echo.NewHTTPError(503, "NetBird installation and peer removal are not yet available through managed commands.")
}
func (h *Handler) NetbirdInstall(c echo.Context) error   { return h.netbirdLifecycleUnavailable(c) }
func (h *Handler) NetbirdUninstall(c echo.Context) error { return h.netbirdLifecycleUnavailable(c) }
func (h *Handler) NetbirdRegister(c echo.Context) error  { return h.NetbirdRegistrationRequest(c) }
func (h *Handler) NetbirdDeletePeer(c echo.Context, uninstalling bool) error {
	return h.netbirdLifecycleUnavailable(c)
}
