package handlers

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func (h *Handler) ADESoftwareOptions(c echo.Context) error {
	adeHeaders(c)
	_, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	query := strings.TrimSpace(c.QueryParam("q"))
	if len(query) > 128 {
		return echo.NewHTTPError(400, "Use at most 128 bytes for the application search")
	}
	items, next, err := h.Apple.SearchApprovedMacApplications(c.Request().Context(), scope, c.QueryParam("before"), query, c.QueryParam("package"))
	if err != nil {
		return softwareFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "software.catalog.read", "catalog"); err != nil {
		return softwareFailure(err)
	}
	type option struct {
		ID      string `json:"id"`
		Package string `json:"package"`
		Label   string `json:"label"`
	}
	options := []option{}
	for _, v := range items {
		options = append(options, option{v.ID, v.PackageID, v.Name + " · " + v.Version + " · " + v.Architecture + " · macOS " + v.MinimumOS + "+ · " + v.Identifier})
	}
	return c.JSON(http.StatusOK, struct {
		Items []option `json:"items"`
		Next  string   `json:"next"`
	}{options, next})
}

func (h *Handler) ReplaceADEApplication(c echo.Context) error {
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
	requirement, err := softwareID(c.Param("requirement"))
	if err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "version", "reason")
	if err != nil {
		return err
	}
	version, err := softwareID(f.Get("version"))
	if err != nil {
		return err
	}
	if err = h.Apple.ReplaceADEApplication(c.Request().Context(), scope, id, requirement, version, f.Get("reason"), h.appleActor(c), h.Access); err != nil {
		return adeWorkflowFailure(err)
	}
	return appleRedirect(c, info, "/ios/"+id)
}

func (h *Handler) ADEApplicationHistory(c echo.Context) error {
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
	requirement, err := softwareID(c.Param("requirement"))
	if err != nil {
		return err
	}
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return softwareFailure(err)
	}
	r, items, next, err := h.Apple.ADEApplicationChanges(c.Request().Context(), scope, id, requirement, c.QueryParam("before"))
	if err != nil {
		return softwareFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "software.inventory.read", id); err != nil {
		return softwareFailure(err)
	}
	return RenderView(c, mdm_views.ADEApplicationHistory(c, info, d, *r, items, next))
}
