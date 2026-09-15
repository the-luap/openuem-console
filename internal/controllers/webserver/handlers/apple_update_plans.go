package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func appleUpdatePlanFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "permission"
	case errors.Is(err, apple.ErrNotFound):
		status, key = http.StatusNotFound, "missing"
	case errors.Is(err, apple.ErrConflict):
		status, key = http.StatusConflict, "changed"
	case errors.Is(err, apple.ErrUpdatePlanLimit):
		status, key = http.StatusUnprocessableEntity, "limit"
	case errors.Is(err, apple.ErrUpdatePlan), errors.Is(err, inventory.ErrGroupInvalid):
		status, key = http.StatusBadRequest, "invalid"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "apple_update_plans."+key))
}
func (h *Handler) appleUpdatePlanContext(c echo.Context) (*partials.CommonInfo, apple.Scope, error) {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if scope.SiteID <= 0 || c.Param("site") == "" {
		return nil, scope, echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "apple_update_plans.site"))
	}
	if err = h.appleReady(); err != nil {
		return nil, scope, err
	}
	return info, scope, nil
}
func (h *Handler) AppleUpdatePlans(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "after")
	if err != nil {
		return appleUpdatePlanFailure(c, err)
	}
	plans, next, err := h.Apple.UpdatePlans(c.Request().Context(), h.appleActor(c), h.Access, scope, q.Get("after"))
	if err != nil {
		return appleUpdatePlanFailure(c, err)
	}
	path := partials.GetNavigationUrl(info, "/ios/update-plans")
	paging := mdm_views.DevicePagination{}
	if q.Get("after") != "" {
		paging.First = path
	}
	if next != "" {
		paging.Next = path + "?" + url.Values{"after": {next}}.Encode()
	}
	return renderApple(c, mdm_views.AppleUpdatePlans(c, info, plans, paging))
}
func (h *Handler) AppleUpdatePlan(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdatePlanFailure(c, err)
	}
	before, err := groupRevision(q.Get("before"))
	if err != nil {
		return appleUpdatePlanFailure(c, err)
	}
	current, history, next, err := h.Apple.UpdatePlanHistory(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), before)
	if err != nil {
		return appleUpdatePlanFailure(c, err)
	}
	path := partials.GetNavigationUrl(info, "/ios/update-plans/"+current.ID)
	paging := mdm_views.DevicePagination{}
	if before > 0 {
		paging.First = path
	}
	if next > 0 {
		paging.Next = path + "?before=" + strconv.Itoa(next)
	}
	return renderApple(c, mdm_views.AppleUpdatePlan(c, info, *current, history, paging))
}
func (h *Handler) AppleSaveUpdatePlan(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	f, err := deviceManagementForm(c, "apple_update_plans.invalid", []string{"csrf", "expected_revision", "name", "description", "platform", "target_version", "target_build", "deadline", "details_url", "archived"})
	if err != nil {
		return err
	}
	expected := 0
	if c.Param("plan") != "" || f.Get("expected_revision") != "0" {
		expected, err = groupRevision(f.Get("expected_revision"))
		if err != nil || expected == 0 {
			return appleUpdatePlanFailure(c, apple.ErrUpdatePlan)
		}
	}
	if f.Has("archived") && f.Get("archived") != "yes" {
		return appleUpdatePlanFailure(c, apple.ErrUpdatePlan)
	}
	deadline := f.Get("deadline")
	if len(deadline) == 16 {
		deadline += ":00"
	}
	definition := apple.UpdatePlanDefinition{Name: f.Get("name"), Description: f.Get("description"), Platform: f.Get("platform"), TargetVersion: f.Get("target_version"), TargetBuild: f.Get("target_build"), Deadline: deadline, DetailsURL: f.Get("details_url"), Archived: f.Get("archived") == "yes"}
	plan, err := h.Apple.SaveUpdatePlan(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), expected, definition)
	if err != nil {
		return appleUpdatePlanFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/update-plans/"+plan.ID)
}
