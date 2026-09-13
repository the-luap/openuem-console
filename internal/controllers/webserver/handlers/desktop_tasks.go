package handlers

import (
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

func (h *Handler) ComputerTasks(c echo.Context, _ string) error {
	r := c.Request()
	if r.Method != http.MethodGet || r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 512 {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	for key, v := range values {
		if (key != "page" && key != "pageSize") || len(v) != 1 || len(v[0]) > 16 {
			return manualFailure(c, inventory.ErrManualInvalid)
		}
	}
	page, err := profilePage(values, "page", 1, 1000000)
	if err != nil {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	size, err := profilePage(values, "pageSize", 25, 100)
	if err != nil {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	result, err := inventory.ReadDesktopTasks(r.Context(), h.Model.DB, h.Access, info.Principal.UserID, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, c.Param("uuid"), page, size)
	if err != nil {
		return manualFailure(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return RenderView(c, computers_views.InventoryIndex("| Computer task reports", desktop_views.TaskHistory(c, info, result), info))
}

// The old URLs accept only the same explicit, reviewed request envelope. A
// display-name selector or a bare task/profile ID can no longer publish work.
func (h *Handler) RunTask(c echo.Context) error    { return h.manualRequest(c, "task") }
func (h *Handler) RunProfile(c echo.Context) error { return h.manualRequest(c, "profile") }
