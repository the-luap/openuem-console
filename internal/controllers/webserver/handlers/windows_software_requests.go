package handlers

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func (h *Handler) WindowsSoftwareRequests(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, err := softwareID(c.Param("version"))
	if err != nil {
		return err
	}
	page, err := h.Apple.ReadWindowsSoftwareRequests(c.Request().Context(), scope, version, c.QueryParam("q"), c.QueryParam("after"), c.QueryParam("before"), h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.WindowsSoftwareRequests(c, info, *page, c.QueryParam("q"), c.QueryParam("after"), c.QueryParam("before"), uuid.NewString()))
}

func (h *Handler) PrepareWindowsSoftware(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, err := softwareID(c.Param("version"))
	if err != nil {
		return err
	}
	form, err := adeEnrollmentForm(c, "request_id", "device", "operation")
	if err != nil {
		return err
	}
	_, err = h.Apple.PrepareWindowsSoftware(c.Request().Context(), scope, form.Get("request_id"), version, form.Get("device"), form.Get("operation"), h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+version+"/windows-requests")
}

func (h *Handler) CancelWindowsSoftwarePreparation(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	version, err := softwareID(c.Param("version"))
	if err != nil {
		return err
	}
	id, err := softwareID(c.Param("request"))
	if err != nil {
		return err
	}
	if _, err = adeEnrollmentForm(c); err != nil {
		return err
	}
	if err = h.Apple.CancelWindowsSoftwarePreparation(c.Request().Context(), scope, version, id, h.appleActor(c), h.Access); err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+version+"/windows-requests")
}
