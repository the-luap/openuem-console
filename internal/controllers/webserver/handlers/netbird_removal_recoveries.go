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

func (h *Handler) netbirdRemovalRecoveryInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if h.NetbirdRemovalRecoveries == nil {
		return nil, scope, netbirdRemovalFailure(inventory.ErrNetbirdOperationNotReady)
	}
	return info, scope, nil
}

func (h *Handler) NetbirdRemovalRecoveryReview(c echo.Context) error {
	values, err := netbirdValues(c, "original_id")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalRecoveryInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalRecoveries.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("original_id"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird removal continuation", desktop_views.NetbirdRemovalRecoveryReview(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalRecoveryRequest(c echo.Context) error {
	values, err := netbirdValues(c, "original_id", "request_id", "recovery_digest", "revision")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalRecoveryInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdRemovalRecoveries.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("original_id"), values.Get("request_id"), values.Get("recovery_digest"), values.Get("revision"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalRecoveryPath(info, r.DeviceID)+"/"+r.ID)
}
func (h *Handler) NetbirdRemovalRecoveryReceipt(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalRecoveryInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalRecoveries.Status(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird removal continuation", desktop_views.NetbirdRemovalRecoveryReceipt(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalRecoveryHistory(c echo.Context) error {
	values, err := netbirdValues(c, "before")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalRecoveryInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalRecoveries.History(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("before"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird removal continuation history", desktop_views.NetbirdRemovalRecoveryHistory(c, info, scope, c.Param("uuid"), v), info))
}
func (h *Handler) NetbirdRemovalRecoveryResolutionReview(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalRecoveryInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	status, err := h.NetbirdRemovalRecoveries.Status(ctx, actor, scope, device, id)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	v, err := h.NetbirdRemovalRecoveries.ReviewRecoveryResolution(ctx, actor, scope, device, id, status.Request.Revision)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Resolve NetBird removal continuation", desktop_views.NetbirdRemovalRecoveryResolution(c, info, status, v), info))
}
func (h *Handler) NetbirdRemovalRecoveryCancel(c echo.Context) error {
	return h.netbirdRemovalRecoveryAction(c, "cancel")
}
func (h *Handler) NetbirdRemovalRecoveryObserve(c echo.Context) error {
	return h.netbirdRemovalRecoveryAction(c, "observe")
}
func (h *Handler) NetbirdRemovalRecoveryResolve(c echo.Context) error {
	return h.netbirdRemovalRecoveryAction(c, "resolve")
}
func (h *Handler) NetbirdRemovalRecoveryReconcile(c echo.Context) error {
	return h.netbirdRemovalRecoveryAction(c, "reconcile")
}
func (h *Handler) netbirdRemovalRecoveryAction(c echo.Context, action string) error {
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
	info, scope, err := h.netbirdRemovalRecoveryInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	s := h.NetbirdRemovalRecoveries
	switch action {
	case "cancel":
		_, err = s.Cancel(ctx, actor, scope, device, id, values.Get("revision"), values.Get("cancellation_id"))
	case "observe":
		_, err = s.ObserveRecovery(ctx, actor, scope, device, id, values.Get("revision"))
	case "resolve":
		_, err = s.ResolveRecovery(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"), values.Get("review_revision"))
	case "reconcile":
		_, err = s.ReconcileRecoveryResolution(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"))
	default:
		err = inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalRecoveryPath(info, device)+"/"+id)
}
