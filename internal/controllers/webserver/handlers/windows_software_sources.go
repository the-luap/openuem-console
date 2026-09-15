package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/software/winget"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func windowsSourceFailure(err error) error {
	switch {
	case errors.Is(err, winget.ErrNotFound):
		return echo.NewHTTPError(404, "No manifest exists for this exact WinGet package version")
	case errors.Is(err, winget.ErrSource):
		return echo.NewHTTPError(503, "The Microsoft community source is temporarily unavailable. Retry the same request.")
	case errors.Is(err, winget.ErrManifest), errors.Is(err, winget.ErrCoordinate), errors.Is(err, winget.ErrInstaller):
		return echo.NewHTTPError(400, "The manifest or selected installer does not match the supported package requirements")
	case errors.Is(err, apple.ErrConflict):
		return echo.NewHTTPError(409, "The source review changed, expired or was already used. Reload the source history before confirming again.")
	default:
		return softwareFailure(err)
	}
}

func (h *Handler) WindowsSoftwareSources(c echo.Context) error {
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
	page, err := h.Apple.ReadWindowsSoftwareSources(c.Request().Context(), scope, version, c.QueryParam("before"), h.appleActor(c), h.Access)
	if err != nil {
		return windowsSourceFailure(err)
	}
	return RenderView(c, mdm_views.WindowsSoftwareSources(c, info, *page, uuid.NewString(), h.appleActor(c), scope.SiteID == 0 && info.Can(access.ManageSoftware)))
}

func (h *Handler) WindowsSoftwareSource(c echo.Context) error {
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
	id, err := softwareID(c.Param("source"))
	if err != nil {
		return err
	}
	page, err := h.Apple.ReadWindowsSoftwareSource(c.Request().Context(), scope, version, id, h.appleActor(c), h.Access)
	if err != nil {
		return windowsSourceFailure(err)
	}
	return RenderView(c, mdm_views.WindowsSoftwareSources(c, info, *page, "", h.appleActor(c), scope.SiteID == 0 && info.Can(access.ManageSoftware)))
}

func (h *Handler) ResolveWindowsSoftwareSource(c echo.Context) error {
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
	form, err := adeEnrollmentForm(c, "request_id")
	if err != nil {
		return err
	}
	fetch := h.winGetSource
	if fetch == nil {
		source := winget.NewSource()
		defer source.Close()
		fetch = source.Fetch
	}
	r, err := h.Apple.ResolveWindowsSoftwareSource(c.Request().Context(), scope, version, form.Get("request_id"), h.appleActor(c), h.Access, fetch)
	if err != nil {
		return windowsSourceFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+version+"/sources/"+r.ID+"/review")
}

func (h *Handler) ReviewWindowsSoftwareSource(c echo.Context) error {
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
	id, err := softwareID(c.Param("source"))
	if err != nil {
		return err
	}
	page, err := h.Apple.ReviewWindowsSoftwareSource(c.Request().Context(), scope, version, id, h.appleActor(c), h.Access)
	if err != nil {
		return windowsSourceFailure(err)
	}
	return RenderView(c, mdm_views.WindowsSoftwareSourceReview(c, info, *page, uuid.NewString()))
}

func (h *Handler) ApproveWindowsSoftwareSource(c echo.Context) error {
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
	id, err := softwareID(c.Param("source"))
	if err != nil {
		return err
	}
	form, err := adeEnrollmentForm(c, "approval_id", "installer_index", "review_hash")
	if err != nil {
		return err
	}
	index, err := strconv.Atoi(form.Get("installer_index"))
	if err != nil || index < 0 || index > 255 || strconv.Itoa(index) != form.Get("installer_index") {
		return echo.NewHTTPError(http.StatusBadRequest, "The selected installer index is invalid")
	}
	v, err := h.Apple.ApproveWindowsSoftwareSource(c.Request().Context(), scope, version, id, form.Get("approval_id"), index, form.Get("review_hash"), h.appleActor(c), h.Access)
	if err != nil {
		return windowsSourceFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+v.ID)
}
