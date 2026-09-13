package handlers

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func (h *Handler) NetbirdRegistrationResolutionReview(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	if h.NetbirdRegistrationResolutions == nil {
		return netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	v, err := h.NetbirdRegistrationResolutions.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird registration resolution", desktop_views.NetbirdRegistrationResolution(c, info, v, uuid.NewString()), info))
}

func (h *Handler) NetbirdRegistrationResolutionRequest(c echo.Context) error {
	return h.netbirdRegistrationResolutionAction(c, "resolve")
}
func (h *Handler) NetbirdRegistrationResolutionContinue(c echo.Context) error {
	return h.netbirdRegistrationResolutionAction(c, "continue")
}
func (h *Handler) NetbirdRegistrationResolutionReconcile(c echo.Context) error {
	return h.netbirdRegistrationResolutionAction(c, "reconcile")
}

func (h *Handler) netbirdRegistrationResolutionAction(c echo.Context, action string) error {
	keys := []string{"resolution_id"}
	if action != "reconcile" {
		keys = append(keys, "revision")
	}
	values, err := netbirdRegistrationValues(c, keys...)
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	s := h.NetbirdRegistrationResolutions
	if s == nil {
		return netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	ctx, actor, device, id := c.Request().Context(), info.Principal.UserID, c.Param("uuid"), c.Param("request")
	switch action {
	case "resolve":
		_, err = s.Resolve(ctx, actor, scope, device, id, values.Get("resolution_id"), values.Get("revision"))
	case "continue":
		_, err = s.Continue(ctx, actor, scope, device, id, values.Get("resolution_id"), values.Get("revision"))
	case "reconcile":
		_, err = s.Reconcile(ctx, actor, scope, device, id, values.Get("resolution_id"))
	default:
		err = inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRegistrationPath(info, device)+"/"+id+"/resolution")
}
