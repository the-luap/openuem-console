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

func netbirdInstallationFailure(err error) error {
	if errors.Is(err, inventory.ErrNetbirdPackageInvalid) || errors.Is(err, inventory.ErrNetbirdPackageMissing) || errors.Is(err, inventory.ErrNetbirdPackageConflict) || errors.Is(err, inventory.ErrNetbirdPackageSecret) {
		return netbirdPackageFailure(err)
	}
	if errors.Is(err, access.ErrDenied) {
		return echo.NewHTTPError(http.StatusForbidden, "You do not have the required software permission for this organization and site.")
	}
	return netbirdFailure(err)
}
func (h *Handler) netbirdInstallationInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if h.NetbirdInstallations == nil {
		return nil, scope, netbirdInstallationFailure(inventory.ErrNetbirdOperationNotReady)
	}
	return info, scope, nil
}

func (h *Handler) NetbirdInstallationChoices(c echo.Context) error {
	values, err := netbirdValues(c, "after")
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	info, scope, err := h.netbirdInstallationInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdInstallations.Choices(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("after"))
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Choose NetBird package", desktop_views.NetbirdInstallationChoices(c, info, v), info))
}
func (h *Handler) NetbirdInstallationReview(c echo.Context) error {
	values, err := netbirdValues(c, "approval_id", "approval_digest")
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	info, scope, err := h.netbirdInstallationInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdInstallations.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("approval_id"), values.Get("approval_digest"))
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird installation", desktop_views.NetbirdInstallationReview(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdInstallationRequest(c echo.Context) error {
	values, err := netbirdValues(c, "request_id", "approval_id", "approval_digest", "revision")
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	info, scope, err := h.netbirdInstallationInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdInstallations.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("request_id"), values.Get("approval_id"), values.Get("approval_digest"), values.Get("revision"))
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdInstallationPath(info, r.DeviceID)+"/"+r.ID)
}
func (h *Handler) NetbirdInstallationReceipt(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdInstallationFailure(err)
	}
	info, scope, err := h.netbirdInstallationInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdInstallations.Status(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird installation", desktop_views.NetbirdInstallationReceipt(c, info, v, uuid.NewString()), info))
}
func (h *Handler) NetbirdInstallationHistory(c echo.Context) error {
	values, err := netbirdValues(c, "before")
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	info, scope, err := h.netbirdInstallationInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdInstallations.History(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("before"))
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird installation history", desktop_views.NetbirdInstallationHistory(c, info, scope, c.Param("uuid"), v), info))
}
func (h *Handler) NetbirdInstallationResolutionReview(c echo.Context) error {
	if _, err := netbirdValues(c); err != nil {
		return netbirdInstallationFailure(err)
	}
	info, scope, err := h.netbirdInstallationInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	status, err := h.NetbirdInstallations.Status(ctx, actor, scope, device, id)
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	v, err := h.NetbirdInstallations.ReviewInstallationResolution(ctx, actor, scope, device, id, status.Request.Revision)
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird installation recovery", desktop_views.NetbirdInstallationResolution(c, info, status, v), info))
}
func (h *Handler) NetbirdInstallationCancel(c echo.Context) error {
	return h.netbirdInstallationAction(c, "cancel")
}
func (h *Handler) NetbirdInstallationObserve(c echo.Context) error {
	return h.netbirdInstallationAction(c, "observe")
}
func (h *Handler) NetbirdInstallationResolve(c echo.Context) error {
	return h.netbirdInstallationAction(c, "resolve")
}
func (h *Handler) NetbirdInstallationReconcile(c echo.Context) error {
	return h.netbirdInstallationAction(c, "reconcile")
}
func (h *Handler) netbirdInstallationAction(c echo.Context, action string) error {
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
		return netbirdInstallationFailure(err)
	}
	info, scope, err := h.netbirdInstallationInfo(c)
	if err != nil {
		return err
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	s := h.NetbirdInstallations
	switch action {
	case "cancel":
		_, err = s.Cancel(ctx, actor, scope, device, id, values.Get("revision"), values.Get("cancellation_id"))
	case "observe":
		_, err = s.ObserveInstallation(ctx, actor, scope, device, id, values.Get("revision"))
	case "resolve":
		_, err = s.ResolveInstallation(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"), values.Get("review_revision"))
	case "reconcile":
		_, err = s.ReconcileInstallationResolution(ctx, actor, scope, device, id, values.Get("revision"), values.Get("resolution_id"))
	default:
		err = inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return netbirdInstallationFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdInstallationPath(info, device)+"/"+id)
}
