package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func taskStatusFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTaskInvalid), errors.Is(err, inventory.ErrTagInvalid), errors.Is(err, inventory.ErrProfileInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "task_status."+key))
}

func (h *Handler) EnableTask(c echo.Context, enable bool) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("id"))
	if err != nil {
		return taskStatusFailure(c, err)
	}
	if err = profileStatusForm(c); err != nil {
		return taskStatusFailure(c, inventory.ErrTaskInvalid)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskStatusFailure(c, err)
	}
	if _, err = inventory.SetTaskEnabled(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, enable); err != nil {
		return taskStatusFailure(c, err)
	}
	p := partials.NewPaginationAndSort(5)
	// No list query runs here: preserve the editor's positive paging values
	// without imposing a different database-configured page-size limit.
	if page, err := strconv.Atoi(c.FormValue("page")); err == nil && page > 0 {
		p.CurrentPage = page
	}
	if size, err := strconv.Atoi(c.FormValue("pageSize")); err == nil && size > 0 {
		p.PageSize = size
	}
	p.SortBy, p.SortOrder = c.FormValue("sortBy"), c.FormValue("sortOrder")
	message := "task_status.disabled"
	if enable {
		message = "task_status.enabled"
	}
	// Update only this control and indicator. Rendering the legacy editor would
	// invoke its unrelated task-order initialization and replace unsaved fields.
	return RenderView(c, profiles_views.TaskStatusResponse(&ent.Task{ID: int(id), Disabled: !enable}, p, info, i18n.T(c.Request().Context(), message)))
}
