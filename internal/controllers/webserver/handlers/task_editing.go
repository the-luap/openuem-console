package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/netbirdapi"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/tasks_views"
)

func taskEditingFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTaskInvalid), errors.Is(err, inventory.ErrProfileInvalid), errors.Is(err, inventory.ErrTagInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	case errors.Is(err, inventory.ErrTaskEditConflict):
		status, key = http.StatusConflict, "conflict"
	case errors.Is(err, inventory.ErrProfileCloneProviderScope):
		status, key = http.StatusConflict, "provider_scope"
	case errors.Is(err, inventory.ErrTaskSecretStorage):
		key = "secret_storage"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "task_editing."+key))
}

func (h *Handler) EditTask(c echo.Context) error {
	r := c.Request()
	c.Response().Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	taskID, err := tagID(c.Param("id"))
	if err != nil {
		return taskEditingFailure(c, err)
	}
	if r.Method == http.MethodPost {
		if err = taskDefinitionForm(c, true); err != nil {
			var httpError *echo.HTTPError
			if errors.As(err, &httpError) {
				return err
			}
			return taskEditingFailure(c, err)
		}
	} else if r.ContentLength != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Encoding") != "" {
		return taskEditingFailure(c, inventory.ErrTaskInvalid)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskEditingFailure(c, err)
	}
	if r.Method == http.MethodPost {
		profileID, err := tagID(c.FormValue("profile"))
		if err != nil {
			return taskEditingFailure(c, err)
		}
		rawVersion := c.FormValue("task-version")
		version, err := strconv.Atoi(rawVersion)
		if err != nil || strconv.Itoa(version) != rawVersion || version < 0 {
			return taskEditingFailure(c, inventory.ErrTaskInvalid)
		}
		cfg, err := validateTaskForm(c)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		choices := inventory.TaskEditSecrets{PasswordAction: c.FormValue("task-password-action"), PassphraseAction: c.FormValue("task-passphrase-action")}
		if choices.PasswordAction == "" {
			choices.PasswordAction = "keep"
		}
		if choices.PassphraseAction == "" {
			choices.PassphraseAction = "keep"
		}
		_, err = inventory.UpdateLegacyTask(r.Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, taskID, profileID, version, *cfg, choices, h.EncryptionMasterKey)
		if err != nil {
			return taskEditingFailure(c, err)
		}
		c.Response().Header().Set("HX-Redirect", partials.GetNavigationUrl(info, fmt.Sprintf("/profiles/%d", profileID)))
		return c.NoContent(http.StatusNoContent)
	}
	review, err := inventory.ReviewTaskEdit(r.Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, taskID)
	if err != nil {
		return taskEditingFailure(c, err)
	}
	groups := []nats.NetBirdGroups{}
	if review.Task.Type == task.TypeNetbirdRegister {
		groups, err = inventory.ReadTaskWizard(r.Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, review.ProfileID, "definition", "netbird_register", h.EncryptionMasterKey, func(ctx context.Context, base, token string) ([]nats.NetBirdGroups, error) {
			return netbirdapi.Groups(ctx, h.netbirdHTTPTransport, base, token)
		})
		if err != nil {
			return taskWizardFailure(c, err)
		}
		ids := []string{}
		if json.Unmarshal([]byte("["+review.Task.NetbirdGroups+"]"), &ids) != nil || len(ids) > 100 {
			return taskEditingFailure(c, inventory.ErrTaskEditConflict)
		}
		present := map[string]bool{}
		for _, group := range groups {
			present[group.ID] = true
		}
		// Preserve saved IDs that have disappeared from the provider's group list.
		for _, id := range ids {
			if !present[id] {
				groups = append(groups, nats.NetBirdGroups{ID: id, Name: i18n.T(r.Context(), "task_editing.saved_group", id)})
				present[id] = true
			}
		}
	}

	return RenderView(c, tasks_views.TasksIndex("| Edit task", tasks_views.EditTask(c, review, groups, info), info))
}
