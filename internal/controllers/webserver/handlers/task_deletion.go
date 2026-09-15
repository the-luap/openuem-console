package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func taskDeletionFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTaskInvalid), errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "task_deletion."+key))
}

func (h *Handler) ConfirmDeleteTask(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	r := c.Request()
	if r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return taskDeletionFailure(c, inventory.ErrTaskInvalid)
	}
	profileID, err := tagID(c.Param("profile"))
	if err != nil {
		return taskDeletionFailure(c, err)
	}
	taskID, err := tagID(c.Param("task"))
	if err != nil {
		return taskDeletionFailure(c, err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskDeletionFailure(c, err)
	}
	review, err := inventory.ReviewTaskDeletion(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, profileID, taskID)
	if err != nil {
		return taskDeletionFailure(c, err)
	}
	return RenderView(c, profiles_views.ProfilesIndex("| Delete task", profiles_views.TaskDeletion(c, review, info), info))
}

// HTMX uses URL parameters for DELETE. Only the reviewed parent is accepted;
// the CSRF token remains in its header and task identity comes from the route.
func (h *Handler) DeleteTask(c echo.Context) error {
	if c.Request().Method != http.MethodDelete {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	r := c.Request()
	if r.ContentLength != 0 || len(r.PostForm) != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 128 {
		return taskDeletionFailure(c, inventory.ErrTaskInvalid)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values) != 1 || len(values["profile"]) != 1 {
		return taskDeletionFailure(c, inventory.ErrTaskInvalid)
	}
	profileID, err := tagID(values.Get("profile"))
	if err != nil {
		return taskDeletionFailure(c, err)
	}
	taskID, err := tagID(c.Param("id"))
	if err != nil {
		return taskDeletionFailure(c, err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskDeletionFailure(c, err)
	}
	if err = inventory.DeleteLegacyTask(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, profileID, taskID); err != nil {
		return taskDeletionFailure(c, err)
	}
	c.Response().Header().Set("HX-Redirect", partials.GetNavigationUrl(info, fmt.Sprintf("/profiles/%d", profileID)))
	return c.NoContent(http.StatusNoContent)
}
