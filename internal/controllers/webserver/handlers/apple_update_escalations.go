package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func appleUpdateEscalationFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "permission"
	case errors.Is(err, apple.ErrNotFound):
		status, key = http.StatusNotFound, "missing"
	case errors.Is(err, apple.ErrConflict):
		status, key = http.StatusConflict, "changed"
	case errors.Is(err, apple.ErrUpdateEscalationFull):
		status, key = http.StatusConflict, "full"
	case errors.Is(err, apple.ErrUpdateEscalation), errors.Is(err, apple.ErrUpdatePlanGroup):
		status, key = http.StatusBadRequest, "invalid"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "apple_update_escalations."+key))
}
func (h *Handler) AppleReviewUpdateEscalation(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateEscalationFailure(c, apple.ErrUpdateEscalation)
	}
	p, err := h.Apple.ReviewUpdateGroupEscalation(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"))
	if err != nil {
		return appleUpdateEscalationFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateEscalationReview(c, info, *p, uuid.NewString(), uuid.NewString()))
}
func appleUpdateEscalationForm(c echo.Context, ack bool) (apple.UpdateEscalationRequest, error) {
	r := apple.UpdateEscalationRequest{PlanID: c.Param("plan"), AssignmentID: c.Param("assignment")}
	fields := []string{"csrf", "request_key", "configuration_revision", "confirmed", "enabled"}
	if ack {
		fields = []string{"csrf", "request_key", "configuration_revision", "confirmed", "incident", "reason"}
	}
	f, err := boundedDeviceManagementForm(c, "apple_update_escalations.invalid", fields, 8192)
	if err != nil {
		return r, err
	}
	raw := f.Get("configuration_revision")
	revision, err := strconv.Atoi(raw)
	if err != nil || strconv.Itoa(revision) != raw || revision < 0 || revision > 2147483646 || f.Get("confirmed") != "yes" {
		return r, appleUpdateEscalationFailure(c, apple.ErrUpdateEscalation)
	}
	r.ConfigurationRevision = revision
	r.RequestKey = f.Get("request_key")
	if ack {
		r.IncidentID = f.Get("incident")
		r.Reason = strings.TrimSpace(strings.ReplaceAll(f.Get("reason"), "\r\n", "\n"))
		if revision < 1 {
			return r, appleUpdateEscalationFailure(c, apple.ErrUpdateEscalation)
		}
	} else {
		switch f.Get("enabled") {
		case "yes":
			r.Enabled = true
		case "no":
			r.Enabled = false
		default:
			return r, appleUpdateEscalationFailure(c, apple.ErrUpdateEscalation)
		}
	}
	return r, nil
}
func (h *Handler) AppleConfigureUpdateEscalation(c echo.Context) error {
	return h.appleRecordUpdateEscalation(c, false)
}
func (h *Handler) AppleAcknowledgeUpdateEscalation(c echo.Context) error {
	return h.appleRecordUpdateEscalation(c, true)
}
func (h *Handler) appleRecordUpdateEscalation(c echo.Context, ack bool) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := appleUpdateEscalationForm(c, ack)
	if err != nil {
		return err
	}
	var e *apple.UpdateEscalationEvent
	if ack {
		e, err = h.Apple.AcknowledgeUpdateEscalation(c.Request().Context(), h.appleActor(c), h.Access, scope, q)
	} else {
		e, err = h.Apple.ConfigureUpdateEscalation(c.Request().Context(), h.appleActor(c), h.Access, scope, q)
	}
	if err != nil {
		return appleUpdateEscalationFailure(c, err)
	}
	return appleRedirect(c, info, mdm_views.UpdateEscalationPath(e.PlanID, e.AssignmentID)+"/events/"+e.ID)
}
func (h *Handler) AppleUpdateEscalations(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdateEscalationFailure(c, apple.ErrUpdateEscalation)
	}
	items, next, err := h.Apple.UpdateEscalations(c.Request().Context(), h.appleActor(c), h.Access, scope, q.Get("before"))
	if err != nil {
		return appleUpdateEscalationFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateEscalations(c, info, items, next))
}
func (h *Handler) AppleUpdateEscalationEvents(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdateEscalationFailure(c, apple.ErrUpdateEscalation)
	}
	items, next, err := h.Apple.UpdateEscalationEvents(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"), q.Get("before"))
	if err != nil {
		return appleUpdateEscalationFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateEscalationEvents(c, info, c.Param("plan"), c.Param("assignment"), items, next))
}
func (h *Handler) AppleUpdateEscalationEvent(c echo.Context) error {
	info, scope, err := h.appleUpdatePlanContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateEscalationFailure(c, apple.ErrUpdateEscalation)
	}
	e, err := h.Apple.UpdateEscalationEventDetails(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("plan"), c.Param("assignment"), c.Param("event"))
	if err != nil {
		return appleUpdateEscalationFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateEscalationEvent(c, info, *e))
}
