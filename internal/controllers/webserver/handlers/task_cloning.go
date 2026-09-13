package handlers

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/tasks_views"
)

func taskCloningFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTaskInvalid), errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	case errors.Is(err, inventory.ErrProfileCloneProviderScope):
		status, key = http.StatusConflict, "provider_scope"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "task_cloning."+key))
}

func taskCloneValues(c echo.Context) (url.Values, int64, int64, access.Scope, error) {
	invalid := func() (url.Values, int64, int64, access.Scope, error) {
		return nil, 0, 0, access.Scope{}, inventory.ErrTaskInvalid
	}
	r := c.Request()
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 8192 {
		return invalid()
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 8192)
	if r.ParseForm() != nil || len(r.PostForm.Encode()) > 8192 {
		return invalid()
	}
	for key, values := range r.PostForm {
		if len(values) != 1 {
			return invalid()
		}
		switch key {
		case "csrf", "source-profile", "target":
			if len(values[0]) > 128 {
				return invalid()
			}
		case "task-description":
		default:
			return invalid()
		}
	}
	source, err := tagID(r.PostForm.Get("source-profile"))
	if err != nil {
		return invalid()
	}
	parts := strings.Split(r.PostForm.Get("target"), ":")
	if len(parts) != 3 {
		return invalid()
	}
	target, err := tagID(parts[0])
	if err != nil {
		return invalid()
	}
	scope := access.Scope{}
	for i, p := range []*int{&scope.TenantID, &scope.SiteID} {
		value, err := strconv.Atoi(parts[i+1])
		if err != nil || value < 0 || strconv.Itoa(value) != parts[i+1] {
			return invalid()
		}
		*p = value
	}
	if scope.TenantID == 0 && scope.SiteID != 0 {
		return invalid()
	}
	if !(inventory.ProfileMetadata{Name: r.PostForm.Get("task-description"), Assignment: "dontApplyToAll"}).Valid() {
		return invalid()
	}
	return r.PostForm, source, target, scope, nil
}

func (h *Handler) CloneTask(c echo.Context) error {
	method := c.Request().Method
	if method != http.MethodGet && method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	taskID, err := tagID(c.Param("id"))
	if err != nil {
		return taskCloningFailure(c, err)
	}
	var values url.Values
	var sourceProfile, targetProfile int64
	var destination access.Scope
	if method == http.MethodPost {
		values, sourceProfile, targetProfile, destination, err = taskCloneValues(c)
		if err != nil {
			return taskCloningFailure(c, err)
		}
	} else {
		r := c.Request()
		if r.ContentLength != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Encoding") != "" {
			return taskCloningFailure(c, inventory.ErrTaskInvalid)
		}
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	source, err := legacyProfileScope(info)
	if err != nil {
		return taskCloningFailure(c, err)
	}
	if method == http.MethodPost {
		_, err = inventory.CloneLegacyTask(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, source, destination, sourceProfile, taskID, targetProfile, values.Get("task-description"))
		if err != nil {
			return taskCloningFailure(c, err)
		}
		path := fmt.Sprintf("/profiles/%d", targetProfile)
		if destination.SiteID != 0 {
			path = fmt.Sprintf("/site/%d", destination.SiteID) + path
		}
		if destination.TenantID != 0 {
			path = fmt.Sprintf("/tenant/%d", destination.TenantID) + path
		}
		c.Response().Header().Set("HX-Redirect", path)
		return c.NoContent(http.StatusNoContent)
	}
	review, err := inventory.ReviewTaskClone(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, source, taskID, 0, "")
	if err != nil {
		return taskCloningFailure(c, err)
	}
	return RenderView(c, tasks_views.TasksIndex("| Clone task", tasks_views.CloneTask(c, review, info), info))
}

func (h *Handler) TaskCloneTargets(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	r := c.Request()
	if r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 4096 {
		return taskCloningFailure(c, inventory.ErrTaskInvalid)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return taskCloningFailure(c, inventory.ErrTaskInvalid)
	}
	for key, v := range values {
		if len(v) != 1 || (key != "q" && key != "source-profile") {
			return taskCloningFailure(c, inventory.ErrTaskInvalid)
		}
	}
	sourceProfile, err := tagID(values.Get("source-profile"))
	if err != nil {
		return taskCloningFailure(c, err)
	}
	taskID, err := tagID(c.Param("id"))
	if err != nil {
		return taskCloningFailure(c, err)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskCloningFailure(c, err)
	}
	review, err := inventory.ReviewTaskClone(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, taskID, sourceProfile, values.Get("q"))
	if err != nil {
		return taskCloningFailure(c, err)
	}
	return RenderView(c, tasks_views.TaskCloneTargets(review))
}
