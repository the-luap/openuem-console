package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/netbirdapi"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskconfig"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func taskWizardFailure(c echo.Context, err error) error {
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
	case errors.Is(err, inventory.ErrTaskWizardProvider):
		key = "provider"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "task_wizard."+key))
}

func (h *Handler) RetiredTaskWizard(c echo.Context) error {
	return echo.NewHTTPError(http.StatusGone, i18n.T(c.Request().Context(), "task_wizard.retired"))
}

func (h *Handler) TaskWizard(c echo.Context) error {
	r := c.Request()
	c.Response().Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	profileID, err := tagID(c.Param("profile"))
	if err != nil {
		return taskWizardFailure(c, err)
	}
	stage := c.Param("stage")
	field := map[string]string{"types": "task-agent-type", "subtypes": "task-type", "definition": "task-subtype"}[stage]
	if field == "" || r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 512 {
		return taskWizardFailure(c, inventory.ErrTaskInvalid)
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query[field]) != 1 || !taskconfig.WizardValue(stage, query.Get(field)) {
		return taskWizardFailure(c, inventory.ErrTaskInvalid)
	}
	value := query.Get(field)
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskWizardFailure(c, err)
	}
	groups, err := inventory.ReadTaskWizard(r.Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, profileID, stage, value, h.EncryptionMasterKey, func(ctx context.Context, base, token string) ([]nats.NetBirdGroups, error) {
		return netbirdapi.Groups(ctx, h.taskWizardHTTPTransport, base, token)
	})
	if err != nil {
		return taskWizardFailure(c, err)
	}
	base := partials.GetNavigationUrl(info, fmt.Sprintf("/tasks/%d/new", profileID))
	switch stage {
	case "types":
		return RenderView(c, partials.SelectTaskType(nil, value, base))
	case "subtypes":
		return renderTaskWizardSubtypes(c, value, base)
	case "definition":
		return renderTaskWizardDefinition(c, value, groups)
	}
	return taskWizardFailure(c, inventory.ErrTaskInvalid)
}

func renderTaskWizardSubtypes(c echo.Context, taskType, base string) error {
	switch taskType {
	case "package_type":
		return RenderView(c, partials.SelectWinGetPackageTaskSubtype(nil, base))
	case "registry_type":
		return RenderView(c, partials.SelectRegistryTaskSubtype(nil, base))
	case "local_user_subtype":
		return RenderView(c, partials.SelectLocalUserTaskSubtype(nil, base))
	case "local_group_subtype":
		return RenderView(c, partials.SelectWindowsLocalGroupTaskSubtype(nil, base))
	case "unix_local_user_subtype":
		return RenderView(c, partials.SelectUnixLocalUserTaskSubtype(nil, base))
	case "unix_local_group_subtype":
		return RenderView(c, partials.SelectUnixLocalGroupTaskSubtype(nil, base))
	case "msi_type":
		return RenderView(c, partials.SelectMSITaskSubtype(nil, base))
	case "powershell_type":
		c.Response().Header().Set("HX-Retarget", "#task-definition")
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTML)
		c.Response().Header().Set(echo.HeaderXContentTypeOptions, "nosniff")
		c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
		return partials.PowerShellComponent(nil).Render(c.Request().Context(), c.Response().Writer)
	case "unix_script_type":
		c.Response().Header().Set("HX-Retarget", "#task-definition")
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTML)
		c.Response().Header().Set(echo.HeaderXContentTypeOptions, "nosniff")
		c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
		return partials.UnixScriptComponent(nil).Render(c.Request().Context(), c.Response().Writer)
	case "flatpak_type":
		return RenderView(c, partials.SelectFlatpakPackageTaskSubtype(nil, base))
	case "brew_formula_type":
		return RenderView(c, partials.SelectHomeBrewFormulaTaskSubtype(nil, base))
	case "brew_cask_type":
		return RenderView(c, partials.SelectHomeBrewCaskTaskSubtype(nil, base))
	case "netbird_type":
		return RenderView(c, partials.SelectNetbirdTaskSubtype(nil, base))
	}

	return taskWizardFailure(c, inventory.ErrTaskInvalid)
}

func renderTaskWizardDefinition(c echo.Context, taskType string, ng []nats.NetBirdGroups) error {
	t := ent.Task{}
	switch taskType {
	case task.TypeWingetInstall.String(), task.TypeWingetDelete.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.WingetPackageSearch(&t))
	case task.TypeAddRegistryKey.String(), task.TypeAddRegistryKeyValue.String(), task.TypeUpdateRegistryKeyDefaultValue.String(),
		task.TypeRemoveRegistryKey.String(), task.TypeRemoveRegistryKeyValue.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.RegistryComponent(&t))
	case task.TypeAddLocalUser.String(), task.TypeRemoveLocalUser.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.LocalUserComponent(&t))
	case task.TypeAddLocalGroup.String(), task.TypeRemoveLocalGroup.String(), task.TypeAddUsersToLocalGroup.String(), task.TypeRemoveUsersFromLocalGroup.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.WindowsLocalGroupComponent(&t))
	case task.TypeAddUnixLocalGroup.String(), task.TypeRemoveUnixLocalGroup.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.UnixLocalGroupComponent(&t))
	case task.TypeAddUnixLocalUser.String(), task.TypeRemoveUnixLocalUser.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.UnixLocalUserComponent(&t))
	case task.TypeMsiInstall.String(), task.TypeMsiUninstall.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.MSIComponent(&t))
	case task.TypeFlatpakInstall.String(), task.TypeFlatpakUninstall.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.FlatpakPackageManagement(&t))
	case task.TypeBrewFormulaInstall.String(), task.TypeBrewFormulaUninstall.String(), task.TypeBrewFormulaUpgrade.String(), task.TypeBrewCaskInstall.String(), task.TypeBrewCaskUninstall.String(), task.TypeBrewCaskUpgrade.String():
		t.Type = task.Type(taskType)
		return RenderView(c, partials.HomeBrewPackageManagement(&t))
	case task.TypeNetbirdInstall.String(), task.TypeNetbirdUninstall.String(), task.TypeNetbirdRegister.String():
		t.Type = task.Type(taskType)

		return RenderView(c, partials.NetbirdTaskComponent(&t, ng))
	}

	return taskWizardFailure(c, inventory.ErrTaskInvalid)
}
