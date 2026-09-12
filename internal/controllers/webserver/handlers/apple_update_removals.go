package handlers

import (
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func (h *Handler) ApplePreviewUpdateGroupRemoval(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	p, err := h.Apple.PreviewUpdateGroupRemoval(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"))
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateGroupRemovalPreview(c, info, *p, uuid.NewString()))
}

func (h *Handler) AppleRemoveUpdateGroupPolicies(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	f, err := boundedDeviceManagementForm(c, "apple_update_groups.invalid", []string{"csrf", "request_key", "devices", "confirmed"}, 16<<10)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(f.Get("devices")), "\n")
	if f.Get("confirmed") != "yes" || len(lines) < 1 || len(lines) > 100 {
		return appleUpdateGroupFailure(c, apple.ErrUpdatePlanGroup)
	}
	selection := make([]apple.UpdatePlanGroupSelection, len(lines))
	for i, line := range lines {
		id, token, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			return appleUpdateGroupFailure(c, apple.ErrUpdatePlanGroup)
		}
		selection[i] = apple.UpdatePlanGroupSelection{DeviceID: id, PolicyToken: token}
	}
	r, err := h.Apple.RemoveUpdateGroupPolicies(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"), f.Get("request_key"), selection)
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return appleRedirect(c, info, mdm_views.UpdateGroupRemovalHistoryPath(r.Assignment.Plan.ID, r.Assignment.ID)+"/"+r.ID)
}

func (h *Handler) AppleUpdateGroupRemoval(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	r, err := h.Apple.UpdateGroupRemovalDetails(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"), c.Param("removal"))
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateGroupRemoval(c, info, *r))
}

func (h *Handler) AppleUpdateGroupRemovals(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	items, next, err := h.Apple.UpdateGroupRemovals(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"), q.Get("before"))
	if err != nil {
		return appleUpdateGroupFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateGroupRemovals(c, info, c.Param("plan"), c.Param("assignment"), items, next))
}
