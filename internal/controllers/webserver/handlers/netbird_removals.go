package handlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func netbirdRemovalFailure(err error) error {
	if errors.Is(err, access.ErrDenied) {
		return echo.NewHTTPError(http.StatusForbidden, "You do not have the required software permission for this organization and site.")
	}
	return netbirdFailure(err)
}
func (h *Handler) netbirdRemovalInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if h.NetbirdRemovals == nil {
		return nil, scope, netbirdRemovalFailure(inventory.ErrNetbirdOperationNotReady)
	}
	return info, scope, nil
}

func (h *Handler) NetbirdRemovalReview(c echo.Context) error {
	_, err := netbirdValues(c)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovals.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird removal", desktop_views.NetbirdRemovalReview(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalRequest(c echo.Context) error {
	values, err := netbirdValues(c, "request_id", "descriptor_digest", "revision")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdRemovals.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("request_id"), values.Get("descriptor_digest"), values.Get("revision"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalPath(info, r.DeviceID)+"/"+r.ID)
}
func (h *Handler) NetbirdRemovalReceipt(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovals.Status(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird removal", desktop_views.NetbirdRemovalReceipt(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalHistory(c echo.Context) error {
	values, err := netbirdValues(c, "before")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovals.History(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("before"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird removal history", desktop_views.NetbirdRemovalHistory(c, info, scope, c.Param("uuid"), v), info))
}
func (h *Handler) NetbirdRemovalResolutionReview(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	status, err := h.NetbirdRemovals.Status(ctx, actor, scope, device, id)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	v, err := h.NetbirdRemovals.ReviewRemovalResolution(ctx, actor, scope, device, id, status.Request.Revision)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird removal recovery", desktop_views.NetbirdRemovalResolution(c, info, status, v), info))
}
func (h *Handler) NetbirdRemovalCancel(c echo.Context) error {
	return h.netbirdRemovalAction(c, "cancel")
}
func (h *Handler) NetbirdRemovalObserve(c echo.Context) error {
	return h.netbirdRemovalAction(c, "observe")
}
func (h *Handler) NetbirdRemovalResolve(c echo.Context) error {
	return h.netbirdRemovalAction(c, "resolve")
}
func (h *Handler) NetbirdRemovalReconcile(c echo.Context) error {
	return h.netbirdRemovalAction(c, "reconcile")
}
func (h *Handler) netbirdRemovalAction(c echo.Context, action string) error {
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
	info, scope, err := h.netbirdRemovalInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	s := h.NetbirdRemovals
	switch action {
	case "cancel":
		_, err = s.Cancel(ctx, actor, scope, device, id, values.Get("revision"), values.Get("cancellation_id"))
	case "observe":
		_, err = s.ObserveRemoval(ctx, actor, scope, device, id, values.Get("revision"))
	case "resolve":
		_, err = s.ResolveRemoval(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"), values.Get("review_revision"))
	case "reconcile":
		_, err = s.ReconcileRemovalResolution(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"))
	default:
		err = inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalPath(info, device)+"/"+id)
}
