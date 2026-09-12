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
	q, err := groupQuery(c, "destination_plan", "revision", "source", "after")
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
	organization, err := appleUpdateGroupSource(q.Get("source"))
	if err != nil {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	groupScope := access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}
	if organization {
		groupScope.SiteID = 0
	}
	groups, err := inventory.ListDeviceGroups(c.Request().Context(), h.Model.DB, h.Access, h.appleActor(c), groupScope, q.Get("after"))
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = mdm_views.UpdatePromotionGroupSourceChoiceURL(info, pilot.Progress.Assignment, *plan, "", organization)
	}
	if groups.Next != "" {
		paging.Next = mdm_views.UpdatePromotionGroupSourceChoiceURL(info, pilot.Progress.Assignment, *plan, groups.Next, organization)
	}
	return renderApple(c, mdm_views.AppleUpdatePromotionGroups(c, info, *pilot, *plan, groups, paging, organization))
}
func (h *Handler) ApplePreviewUpdatePromotion(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "destination_plan", "revision", "group", "group_revision", "source")
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
	organization, err := appleUpdateGroupSource(q.Get("source"))
	if err != nil {
		return appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	previewGroup := h.Apple.PreviewUpdatePromotion
	if organization {
		previewGroup = h.Apple.PreviewUpdatePromotionOrganizationGroup
	}
	preview, err := previewGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, c.Param("plan"), c.Param("assignment"), q.Get("destination_plan"), revision, q.Get("group"), groupVersion)
	if err != nil {
		return appleUpdatePromotionFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdatePromotionPreview(c, info, *preview, uuid.NewString()))
}
func appleUpdatePromotionForm(c echo.Context) (apple.UpdatePromotionRequest, bool, error) {
	q := apple.UpdatePromotionRequest{PilotPlanID: c.Param("plan"), PilotAssignmentID: c.Param("assignment")}
	f, err := boundedDeviceManagementForm(c, "apple_update_promotions.invalid", []string{"csrf", "destination_plan", "expected_revision", "group_id", "group_revision", "group_source", "request_key", "devices", "confirmed"}, 16<<10)
	if err != nil {
		return q, false, err
	}
	q.DestinationRevision, q.GroupRevision, q.Targets, err = appleUpdateGroupSelection(f)
	if err != nil {
		return q, false, appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	q.RequestKey, q.DestinationPlanID, q.GroupID = f.Get("request_key"), f.Get("destination_plan"), f.Get("group_id")
	organization, err := appleUpdateGroupSource(f.Get("group_source"))
	if err != nil {
		return q, false, appleUpdatePromotionFailure(c, apple.ErrUpdatePromotion)
	}
	return q, organization, nil
}
func (h *Handler) ApplePromoteUpdatePlanGroup(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, organization, err := appleUpdatePromotionForm(c)
	if err != nil {
		return err
	}
	promoteGroup := h.Apple.PromoteUpdatePlanGroup
	if organization {
		promoteGroup = h.Apple.PromoteUpdatePlanOrganizationGroup
	}
	r, err := promoteGroup(c.Request().Context(), h.appleActor(c), h.Access, scope, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, q)
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
