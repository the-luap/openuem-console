package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
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
