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

func (h *Handler) netbirdRemovalAbsenceInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if h.NetbirdRemovalAbsences == nil {
		return nil, scope, netbirdRemovalFailure(inventory.ErrNetbirdOperationNotReady)
	}
	return info, scope, nil
}

func (h *Handler) NetbirdRemovalAbsenceReview(c echo.Context) error {
	values, err := netbirdValues(c, "original_id")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalAbsenceInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalAbsences.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("original_id"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird absence verification", desktop_views.NetbirdRemovalAbsenceReview(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalAbsenceRequest(c echo.Context) error {
	values, err := netbirdValues(c, "original_id", "request_id", "absence_digest", "revision")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalAbsenceInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdRemovalAbsences.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("original_id"), values.Get("request_id"), values.Get("absence_digest"), values.Get("revision"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalAbsencePath(info, r.DeviceID)+"/"+r.ID)
}
func (h *Handler) NetbirdRemovalAbsenceReceipt(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalAbsenceInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalAbsences.Status(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird absence verification", desktop_views.NetbirdRemovalAbsenceReceipt(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdRemovalAbsenceHistory(c echo.Context) error {
	values, err := netbirdValues(c, "before")
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalAbsenceInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRemovalAbsences.History(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("before"))
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird absence verification history", desktop_views.NetbirdRemovalAbsenceHistory(c, info, scope, c.Param("uuid"), v), info))
}
func (h *Handler) NetbirdRemovalAbsenceResolutionReview(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdRemovalFailure(err)
	}
	info, scope, err := h.netbirdRemovalAbsenceInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	status, err := h.NetbirdRemovalAbsences.Status(ctx, actor, scope, device, id)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	v, err := h.NetbirdRemovalAbsences.ReviewAbsenceResolution(ctx, actor, scope, device, id, status.Request.Revision)
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Resolve NetBird absence verification", desktop_views.NetbirdRemovalAbsenceResolution(c, info, status, v), info))
}
func (h *Handler) NetbirdRemovalAbsenceCancel(c echo.Context) error {
	return h.netbirdRemovalAbsenceAction(c, "cancel")
}
func (h *Handler) NetbirdRemovalAbsenceObserve(c echo.Context) error {
	return h.netbirdRemovalAbsenceAction(c, "observe")
}
func (h *Handler) NetbirdRemovalAbsenceResolve(c echo.Context) error {
	return h.netbirdRemovalAbsenceAction(c, "resolve")
}
func (h *Handler) NetbirdRemovalAbsenceReconcile(c echo.Context) error {
	return h.netbirdRemovalAbsenceAction(c, "reconcile")
}
func (h *Handler) netbirdRemovalAbsenceAction(c echo.Context, action string) error {
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
	info, scope, err := h.netbirdRemovalAbsenceInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	s := h.NetbirdRemovalAbsences
	switch action {
	case "cancel":
		_, err = s.Cancel(ctx, actor, scope, device, id, values.Get("revision"), values.Get("cancellation_id"))
	case "observe":
		_, err = s.ObserveAbsence(ctx, actor, scope, device, id, values.Get("revision"))
	case "resolve":
		_, err = s.ResolveAbsence(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"), values.Get("review_revision"))
	case "reconcile":
		_, err = s.ReconcileAbsenceResolution(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"))
	default:
		err = inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return netbirdRemovalFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRemovalAbsencePath(info, device)+"/"+id)
}
