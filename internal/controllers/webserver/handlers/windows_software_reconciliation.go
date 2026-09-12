package handlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func windowsSoftwareCheckIDs(c echo.Context) (string, string, error) {
	version, err := softwareID(c.Param("version"))
	if err != nil {
		return "", "", err
	}
	id, err := softwareID(c.Param("request"))
	return version, id, err
}

func (h *Handler) ReviewWindowsSoftwareReconciliation(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, id, err := windowsSoftwareCheckIDs(c)
	if err != nil {
		return err
	}
	review, err := h.Apple.ReviewWindowsSoftwareReconciliation(c.Request().Context(), scope, version, id, h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.WindowsSoftwareReconciliationReview(c, info, *review, uuid.NewString()))
}

func (h *Handler) QueueWindowsSoftwareReconciliation(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, id, err := windowsSoftwareCheckIDs(c)
	if err != nil {
		return err
	}
	form, err := adeEnrollmentForm(c, "reconciliation_id", "review_hash", "expires_at")
	if err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, form.Get("expires_at"))
	if err != nil || expires.UTC().Format(time.RFC3339) != form.Get("expires_at") {
		return echo.NewHTTPError(http.StatusBadRequest, "The reviewed software check deadline is invalid")
	}
	if _, err = h.Apple.QueueWindowsSoftwareReconciliation(c.Request().Context(), scope, version, id, form.Get("reconciliation_id"), form.Get("review_hash"), h.appleActor(c), expires, h.Access); err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+version+"/windows-requests/"+id+"/dispatch/reconciliations")
}

func (h *Handler) WindowsSoftwareReconciliations(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, id, err := windowsSoftwareCheckIDs(c)
	if err != nil {
		return err
	}
	page, err := h.Apple.ReadWindowsSoftwareReconciliations(c.Request().Context(), scope, version, id, c.QueryParam("before"), h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.WindowsSoftwareReconciliations(c, info, *page))
}

func (h *Handler) CancelWindowsSoftwareReconciliation(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, id, err := windowsSoftwareCheckIDs(c)
	if err != nil {
		return err
	}
	reconciliation, err := softwareID(c.Param("reconciliation"))
	if err != nil {
		return err
	}
	if _, err = adeEnrollmentForm(c); err != nil {
		return err
	}
	if err = h.Apple.CancelWindowsSoftwareReconciliation(c.Request().Context(), scope, version, id, reconciliation, h.appleActor(c), h.Access); err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+version+"/windows-requests/"+id+"/dispatch/reconciliations")
}
