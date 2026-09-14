package handlers

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) netbirdRemovalStageCleanupInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if h.NetbirdRemovalStageCleanups == nil {
		return nil, scope, netbirdRemovalFailure(inventory.ErrNetbirdOperationNotReady)
	}
	return info, scope, nil
}

func (h *Handler) NetbirdRemovalStageCleanupReview(c echo.Context) error {
	values, err := netbirdValues(c, "original_id")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalStageCleanupInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalStageCleanups.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("original_id"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird staging cleanup", desktop_views.NetbirdRemovalStageCleanupReview(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalStageCleanupRequest(c echo.Context) error {
	values, err := netbirdValues(c, "original_id", "request_id", "stage_cleanup_digest", "revision")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalStageCleanupInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdRemovalStageCleanups.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("original_id"), values.Get("request_id"), values.Get("stage_cleanup_digest"), values.Get("revision"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalStageCleanupPath(info, r.DeviceID)+"/"+r.ID)
}
func (h *Handler) NetbirdRemovalStageCleanupReceipt(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalStageCleanupInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalStageCleanups.Status(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird staging cleanup", desktop_views.NetbirdRemovalStageCleanupReceipt(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalStageCleanupHistory(c echo.Context) error {
	values, err := netbirdValues(c, "before")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalStageCleanupInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalStageCleanups.History(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("before"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird staging cleanup history", desktop_views.NetbirdRemovalStageCleanupHistory(c, info, scope, c.Param("uuid"), v), info))
}
func (h *Handler) NetbirdRemovalStageCleanupResolutionReview(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalStageCleanupInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	status, err := h.NetbirdRemovalStageCleanups.Status(ctx, actor, scope, device, id)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	v, err := h.NetbirdRemovalStageCleanups.ReviewStageCleanupResolution(ctx, actor, scope, device, id, status.Request.Revision)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Resolve NetBird staging cleanup", desktop_views.NetbirdRemovalStageCleanupResolution(c, info, status, v), info))
}
func (h *Handler) NetbirdRemovalStageCleanupCancel(c echo.Context) error {
	return h.netbirdRemovalStageCleanupAction(c, "cancel")
}
func (h *Handler) NetbirdRemovalStageCleanupObserve(c echo.Context) error {
	return h.netbirdRemovalStageCleanupAction(c, "observe")
}
func (h *Handler) NetbirdRemovalStageCleanupResolve(c echo.Context) error {
	return h.netbirdRemovalStageCleanupAction(c, "resolve")
}
func (h *Handler) NetbirdRemovalStageCleanupReconcile(c echo.Context) error {
	return h.netbirdRemovalStageCleanupAction(c, "reconcile")
}
func (h *Handler) netbirdRemovalStageCleanupAction(c echo.Context, action string) error {
	keys := []string{"revision"}
	switch action {
	case "cancel":
		keys = append(keys, "cancellation_id")
	case "resolve":
		keys = append(keys, "resolution_id", "review_revision")
	case "reconcile":
		keys = append(keys, "resolution_id")
	}
	values, err := netbirdValues(c, keys...)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalStageCleanupInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	s := h.NetbirdRemovalStageCleanups
	switch action {
	case "cancel":
		_, err = s.Cancel(ctx, actor, scope, device, id, values.Get("revision"), values.Get("cancellation_id"))
	case "observe":
		_, err = s.ObserveStageCleanup(ctx, actor, scope, device, id, values.Get("revision"))
	case "resolve":
		_, err = s.ResolveStageCleanup(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"), values.Get("review_revision"))
	case "reconcile":
		_, err = s.ReconcileStageCleanupResolution(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"))
	default:
		err = inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalStageCleanupPath(info, device)+"/"+id)
}
