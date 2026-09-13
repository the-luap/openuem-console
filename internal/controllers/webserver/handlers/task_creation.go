package handlers

import (
	"errors"
	"fmt"
	"mime"
	"net/http"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/tasks_views"
)

const taskCreationFormLimit = 256 << 10

func taskCreationFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTaskInvalid), errors.Is(err, inventory.ErrTagInvalid), errors.Is(err, inventory.ErrProfileInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	case errors.Is(err, inventory.ErrProfileCloneProviderScope):
		status, key = http.StatusConflict, "provider_scope"
	case errors.Is(err, inventory.ErrTaskSecretStorage):
		key = "secret_storage"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "task_creation."+key))
}

func taskCreationForm(c echo.Context) error {
	r := c.Request()
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return inventory.ErrTaskInvalid
	}
	if r.ContentLength > taskCreationFormLimit {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Task form is too large")
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, taskCreationFormLimit)
	if err = r.ParseForm(); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Task form is too large")
		}
		return inventory.ErrTaskInvalid
	}
	if len(r.PostForm.Encode()) > taskCreationFormLimit {
		return inventory.ErrTaskInvalid
	}
	for key, values := range r.PostForm {
		if key == "netbird-group-id" {
			if len(values) > 100 {
				return inventory.ErrTaskInvalid
			}
			for _, value := range values {
				if len(value) > 128 {
					return inventory.ErrTaskInvalid
				}
			}
			continue
		}
		if !taskCreationFields[key] || len(values) != 1 {
			return inventory.ErrTaskInvalid
		}
		limit := 16 << 10
		switch key {
		case "powershell-script", "unix-script":
			limit = 128 << 10
		case "task-description":
			limit = 2048
		case "csrf", "task-agent-type", "task-type", "task-subtype", "selected-task-type":
			limit = 128
		}
		if len(values[0]) > limit {
			return inventory.ErrTaskInvalid
		}
	}
	return nil
}

func (h *Handler) NewTask(c echo.Context) error {
	method := c.Request().Method
	if method != http.MethodGet && method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	profileID, err := tagID(c.Param("profile"))
	if err != nil {
		return taskCreationFailure(c, err)
	}
	if method == http.MethodPost {
		if err = taskCreationForm(c); err != nil {
			var httpError *echo.HTTPError
			if errors.As(err, &httpError) {
				return err
			}
			return taskCreationFailure(c, err)
		}
	} else {
		r := c.Request()
		if r.ContentLength != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Encoding") != "" {
			return taskCreationFailure(c, inventory.ErrTaskInvalid)
		}
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskCreationFailure(c, err)
	}
	if method == http.MethodPost {
		cfg, err := validateTaskForm(c)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		_, err = inventory.CreateLegacyTask(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, profileID, *cfg, h.EncryptionMasterKey)
		if err != nil {
			return taskCreationFailure(c, err)
		}
		c.Response().Header().Set("HX-Redirect", partials.GetNavigationUrl(info, fmt.Sprintf("/profiles/%d", profileID)))
		return c.NoContent(http.StatusNoContent)
	}
	review, err := inventory.ReviewTaskCreation(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, profileID)
	if err != nil {
		return taskCreationFailure(c, err)
	}
	return RenderView(c, tasks_views.TasksIndex("| New task", tasks_views.NewTask(c, review, info), info))
}
