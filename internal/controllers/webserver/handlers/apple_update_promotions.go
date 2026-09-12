package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func appleUpdatePromotionFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "permission"
	case errors.Is(err, apple.ErrNotFound), errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "missing"
	case errors.Is(err, apple.ErrUpdatePromotionNotReady):
		status, key = http.StatusConflict, "not_ready"
	case errors.Is(err, apple.ErrConflict), errors.Is(err, inventory.ErrGroupConflict):
		status, key = http.StatusConflict, "changed"
	case errors.Is(err, inventory.ErrGroupSnapshotLarge):
		status, key = http.StatusUnprocessableEntity, "large"
	case errors.Is(err, apple.ErrUpdatePromotion), errors.Is(err, apple.ErrUpdatePlanGroup), errors.Is(err, apple.ErrUpdatePlan), errors.Is(err, inventory.ErrGroupInvalid):
		status, key = http.StatusBadRequest, "invalid"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "apple_update_promotions."+key))
}
func (h *Handler) AppleUpdatePromotionPlans(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "after")
	if err != nil {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	pilot, err := h.Apple.ReviewUpdatePilotReadiness(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"))
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	plans, next, err := h.Apple.UpdatePlans(c.Request().Context(), h.appleActor(c), h.Access, scope, q.Get("after"))
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	path := partials.GetNavigationUrl(info, mdm_views.UpdatePromotionPath(c.Param("plan"), c.Param("assignment")))
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = path
	}
	if next != "" {
		paging.Next = path + "?" + url.Values{"after": {next}}.Encode()
	}
	return renderApple(c, mdm_views.AppleUpdatePromotionPlans(c, info, *pilot, plans, paging))
}
func (h *Handler) AppleUpdatePromotionGroups(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "destination_plan", "revision", "after")
	if err != nil {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	revision, err := groupRevision(q.Get("revision"))
	if err != nil || revision == 0 {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	pilot, err := h.Apple.ReviewUpdatePilotReadiness(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"))
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	plan, err := h.Apple.UpdatePlanForGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, q.Get("destination_plan"), revision)
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	if !apple.UpdatePromotionTargetMatches(pilot.Progress.Assignment.Plan.Definition, plan.Definition) {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotionNotReady)
	}
	groups, err := inventory.ListDeviceGroups(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, q.Get("after"))
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = mdm_views.UpdatePromotionGroupChoiceURL(info, pilot.Progress.Assignment, *plan, "")
	}
	if groups.Next != "" {
		paging.Next = mdm_views.UpdatePromotionGroupChoiceURL(info, pilot.Progress.Assignment, *plan, groups.Next)
	}
	return renderApple(c, mdm_views.AppleUpdatePromotionGroups(c, info, *pilot, *plan, groups, paging))
}
func (h *Handler) ApplePreviewUpdatePromotion(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "destination_plan", "revision", "group", "group_revision")
	if err != nil {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	revision, err := groupRevision(q.Get("revision"))
	if err != nil || revision == 0 {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	groupVersion, err := groupRevision(q.Get("group_revision"))
	if err != nil || groupVersion == 0 {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	preview, err := h.Apple.PreviewUpdatePromotion(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, c.Param("plan"), c.Param("assignment"), q.Get("destination_plan"), revision, q.Get("group"), groupVersion)
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdatePromotionPreview(c, info, *preview, uuid.NewString()))
}
func appleUpdatePromotionForm(c echo.Context) (apple.UpdatePromotionRequest, error) {
	q := apple.UpdatePromotionRequest{PilotPlanID: c.Param("plan"), PilotAssignmentID: c.Param("assignment")}
	f, err := boundedDeviceManagementForm(c, "apple_update_promotions.invalid", []string{"csrf", "destination_plan", "expected_revision", "group_id", "group_revision", "request_key", "devices", "confirmed"}, 16<<10)
	if err != nil {
		return q, err
	}
	q.DestinationRevision, q.GroupRevision, q.Targets, err = appleUpdateGroupSelection(f)
	if err != nil {
		return q, appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	q.RequestKey, q.DestinationPlanID, q.GroupID = f.Get("request_key"), f.Get("destination_plan"), f.Get("group_id")
	return q, nil
}
func (h *Handler) ApplePromoteUpdatePlanGroup(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := appleUpdatePromotionForm(c)
	if err != nil {
		return err
	}
	r, err := h.Apple.PromoteUpdatePlanGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, q)
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	return appleRedirect(c, info, mdm_views.UpdatePromotionHistoryPath(r.PilotPlanID, r.PilotAssignmentID)+"/"+r.ID)
}
func (h *Handler) AppleUpdatePromotion(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	r, err := h.Apple.UpdatePromotionDetails(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"), c.Param("promotion"))
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdatePromotion(c, info, *r))
}
func (h *Handler) AppleUpdatePromotions(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	items, next, err := h.Apple.UpdatePromotions(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"), q.Get("before"))
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdatePromotions(c, info, c.Param("plan"), c.Param("assignment"), items, next))
}
