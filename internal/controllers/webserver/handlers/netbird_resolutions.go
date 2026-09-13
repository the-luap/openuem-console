package handlers

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func (h *Handler) NetbirdResolutionReview(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	if h.NetbirdResolutions == nil {
		return netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	v, err := h.NetbirdResolutions.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird resolution", desktop_views.NetbirdResolution(c, info, v, uuid.NewString()), info))
}

func (h *Handler) NetbirdResolutionRequest(c echo.Context) error {
	v, err := netbirdValues(c, "resolution_id", "revision")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	if h.NetbirdResolutions == nil {
		return netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	_, err = h.NetbirdResolutions.Resolve(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"), v.Get("resolution_id"), v.Get("revision"))
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdOperationPath(info, c.Param("uuid"))+"/"+c.Param("request")+"/resolution")
}

func (h *Handler) NetbirdResolutionReconcile(c echo.Context) error {
	v, err := netbirdValues(c, "resolution_id")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return err
	}
	if h.NetbirdResolutions == nil {
		return netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	_, err = h.NetbirdResolutions.Reconcile(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"), v.Get("resolution_id"))
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdOperationPath(info, c.Param("uuid"))+"/"+c.Param("request")+"/resolution")
}
