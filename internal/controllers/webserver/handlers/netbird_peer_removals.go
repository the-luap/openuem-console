package handlers

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func (h *Handler) NetbirdPeerRemovalReview(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRegistrations.ReviewPeerRemoval(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird peer removal", desktop_views.NetbirdPeerRemovalReview(c, info, v, uuid.NewString()), info))
}

func (h *Handler) NetbirdPeerRemovalRequest(c echo.Context) error {
	values, err := netbirdRegistrationValues(c, "removal_id", "revision")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	_, err = h.NetbirdRegistrations.RemovePeer(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"), values.Get("removal_id"), values.Get("revision"))
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRegistrationPath(info, c.Param("uuid"))+"/"+c.Param("request")+"/peer/removal")
}

func (h *Handler) NetbirdPeerRemovalCheck(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	_, err = h.NetbirdRegistrations.ReconcilePeerRemoval(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRegistrationPath(info, c.Param("uuid"))+"/"+c.Param("request")+"/peer/removal")
}
