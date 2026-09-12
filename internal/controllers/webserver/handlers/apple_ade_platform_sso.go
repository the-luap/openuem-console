package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func (h *Handler) ADEPlatformSSOChoices(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if !info.Can(access.ReadProfiles) {
		return echo.NewHTTPError(403, "Profile read permission is required")
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	for key, values := range c.QueryParams() {
		if (key != "q" && key != "after") || len(values) != 1 {
			return echo.NewHTTPError(400, "Invalid profile search")
		}
	}
	items, next, err := h.Apple.ADEPlatformSSOChoices(c.Request().Context(), scope.TenantID, c.QueryParam("q"), c.QueryParam("after"))
	if err != nil {
		return adeWorkflowFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.ade_choices.read", "catalog"); err != nil {
		return adeWorkflowFailure(err)
	}
	return c.JSON(http.StatusOK, map[string]any{"items": items, "next": next})
}

func (h *Handler) ADEPlatformSSORevisionChoices(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if !info.Can(access.ReadProfiles) {
		return echo.NewHTTPError(403, "Profile read permission is required")
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	for key, values := range c.QueryParams() {
		if (key != "q" && key != "after") || len(values) != 1 {
			return echo.NewHTTPError(400, "Invalid profile search")
		}
	}
	items, next, err := h.Apple.ADEPlatformSSORevisionChoices(c.Request().Context(), scope, id, c.QueryParam("q"), c.QueryParam("after"))
	if err != nil {
		return adeWorkflowFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.ade_choices.read", id); err != nil {
		return adeWorkflowFailure(err)
	}
	return c.JSON(http.StatusOK, map[string]any{"items": items, "next": next})
}

func (h *Handler) CorrectADEPlatformSSO(c echo.Context) error {
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
	f, err := adeEnrollmentForm(c, "expected_revision", "profile_revision", "application_version", "provider_confirmed", "reason")
	if err != nil {
		return err
	}
	if f.Get("provider_confirmed") != "yes" {
		return echo.NewHTTPError(400, "Confirm the provider and application review")
	}
	o := apple.ADEPlatformSSOCorrection{ExpectedRevisionID: f.Get("expected_revision"), ProfileRevisionID: f.Get("profile_revision"), ApplicationVersionID: f.Get("application_version"), ProviderConfirmed: true, Reason: f.Get("reason")}
	if err = h.Apple.CorrectADEPlatformSSO(c.Request().Context(), scope, id, o, h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) ADEPlatformSSORevisions(c echo.Context) error {
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
	for key, values := range c.QueryParams() {
		if key != "before" || len(values) != 1 {
			return echo.NewHTTPError(400, "Invalid provider revision page")
		}
	}
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return adeWorkflowFailure(err)
	}
	r, items, next, err := h.Apple.ADEPlatformSSORevisions(c.Request().Context(), scope, id, c.QueryParam("before"))
	if err != nil {
		return adeWorkflowFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.ade_revisions.read", id); err != nil {
		return adeWorkflowFailure(err)
	}
	return RenderView(c, mdm_views.ADEPlatformSSORevisions(c, info, d, r, items, next))
}

func (h *Handler) RepairADEPlatformSSO(c echo.Context) error {
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
	f, err := adeEnrollmentForm(c, "binding_revision", "reason")
	if err != nil {
		return err
	}
	revision, err := softwareID(f.Get("binding_revision"))
	if err != nil {
		return err
	}
	if err = h.Apple.RepairADEPlatformSSO(c.Request().Context(), scope, id, revision, f.Get("reason"), h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) ADEPlatformSSORepairs(c echo.Context) error {
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
	for key, values := range c.QueryParams() {
		if key != "before" || len(values) != 1 {
			return echo.NewHTTPError(400, "Invalid repair history page")
		}
	}
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return adeWorkflowFailure(err)
	}
	r, items, next, err := h.Apple.ADEPlatformSSORepairs(c.Request().Context(), scope, id, c.QueryParam("before"))
	if err != nil {
		return adeWorkflowFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.ade_repairs.read", id); err != nil {
		return adeWorkflowFailure(err)
	}
	return RenderView(c, mdm_views.ADEPlatformSSORepairs(c, info, d, r, items, next))
}
