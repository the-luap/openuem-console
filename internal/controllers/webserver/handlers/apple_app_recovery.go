package handlers

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func (h *Handler) MacAppPreviousEnrollments(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	d, risk, items, next, err := h.Apple.MacAppPriorAttempts(c.Request().Context(), scope, id, c.QueryParam("before"), h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "software.inventory.read", id); err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.MacAppPreviousEnrollments(c, info, d, risk, items, next))
}

func (h *Handler) RecordMacAppStoppingEvidence(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	attempt, err := softwareID(c.Param("attempt"))
	if err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "evidence", "reason")
	if err != nil {
		return err
	}
	if err = h.Apple.RecordMacAppStoppingEvidence(c.Request().Context(), scope, id, attempt, f.Get("evidence"), f.Get("reason"), h.appleActor(c), h.Access); err != nil {
		if errors.Is(err, apple.ErrMacApp) {
			return echo.NewHTTPError(400, "Choose the observed stopping evidence and describe it in 1–1000 characters")
		}
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id+"/applications/previous")
}
