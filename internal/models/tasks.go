package models

import (
	"context"
	"errors"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	ent "github.com/open-uem/ent"
	"github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/taskconfig"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

type TaskConfig = taskconfig.Config

func (m *Model) CountAllTasksForProfile(profileID int) (int, error) {
	return m.Client.Task.Query().Where(task.HasProfileWith(profile.ID(profileID))).Count(context.Background())
}

func (m *Model) UpdateProfileTask(c echo.Context, taskID int, cfg TaskConfig) error {

	// common query
	query := m.Client.Task.UpdateOneID(taskID).SetName(cfg.Description).SetIgnoreErrors(cfg.IgnoreErrors)

	// Update version
	query.AddVersion(1)

	// Specify values to be updated

	switch cfg.TaskType {
	case task.TypeWingetInstall.String(), task.TypeWingetDelete.String():
		return query.SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetPackageVersion(cfg.PackageVersion).SetPackageLatest(cfg.PackageLatest).Exec(context.Background())
	case task.TypeAddRegistryKey.String():
		return query.SetRegistryKey(cfg.RegistryKey).Exec(context.Background())
	case task.TypeRemoveRegistryKey.String():
		return query.SetRegistryKey(cfg.RegistryKey).SetRegistryForce(cfg.RegistryForce).Exec(context.Background())
	case task.TypeUpdateRegistryKeyDefaultValue.String():
		return query.SetRegistryKey(cfg.RegistryKey).SetRegistryKeyValueType(task.RegistryKeyValueType(cfg.RegistryKeyValueType)).
			SetRegistryKeyValueData(cfg.RegistryKeyValueData).SetRegistryForce(cfg.RegistryForce).Exec(context.Background())
	case task.TypeAddRegistryKeyValue.String():
		return query.
			SetRegistryKey(cfg.RegistryKey).
			SetRegistryKeyValueName(cfg.RegistryKeyValue).
			SetRegistryKeyValueType(task.RegistryKeyValueType(cfg.RegistryKeyValueType)).
			SetRegistryKeyValueData(cfg.RegistryKeyValueData).
			SetRegistryHex(cfg.RegistryHex).
			SetRegistryForce(cfg.RegistryForce).Exec(context.Background())
	case task.TypeRemoveRegistryKeyValue.String():
		return query.
			SetRegistryKey(cfg.RegistryKey).
			SetRegistryKeyValueName(cfg.RegistryKeyValue).Exec(context.Background())
	case task.TypeAddLocalUser.String():
		return query.
			SetLocalUserUsername(cfg.LocalUserUsername).
			SetLocalUserDescription(cfg.LocalUserDescription).
			SetLocalUserFullname(cfg.LocalUserFullName).
			SetLocalUserPassword(cfg.LocalUserPassword).
			SetLocalUserDisable(cfg.LocalUserDisabled).
			SetLocalUserPasswordChangeNotAllowed(cfg.LocalUserPasswordChangeNotAllowed).
			SetLocalUserPasswordChangeRequired(cfg.LocalUserPasswordChangeRequired).
			SetLocalUserPasswordNeverExpires(cfg.LocalUserNeverExpires).
			Exec(context.Background())
	case task.TypeAddUnixLocalUser.String():
		return query.
			SetLocalUserUsername(cfg.LocalUserUsername).
			SetLocalUserDescription(cfg.LocalUserDescription).
			SetLocalUserGroup(cfg.LocalUserPrimaryGroup).
			SetLocalUserGroups(cfg.LocalUserSupplementaryGroup).
			SetLocalUserHome(cfg.LocalUserHome).
			SetLocalUserShell(cfg.LocalUserShell).
			SetLocalUserCreateHome(cfg.LocalUserCreateHome).
			SetLocalUserSkeleton(cfg.LocalUserSkeleton).
			SetLocalUserUmask(cfg.LocalUserUmask).
			SetLocalUserGenerateSSHKey(cfg.LocalUserGenerateSSHKey).
			SetLocalUserSystem(cfg.LocalUserSystemAccount).
			SetLocalUserPassword(cfg.LocalUserPassword).
			SetLocalUserID(cfg.LocalUserID).
			SetLocalUserExpires(cfg.LocalUserExpires).
			SetLocalUserPasswordLock(cfg.LocalUserPasswordLock).
			SetLocalUserPasswordExpireMax(cfg.LocalUserPasswordExpireMax).
			SetLocalUserPasswordExpireMin(cfg.LocalUserPasswordExpireMin).
			SetLocalUserPasswordExpireAccountDisable(cfg.LocalUserPasswordExpireAccountDisable).
			SetLocalUserPasswordExpireWarn(cfg.LocalUserPasswordExpireWarn).
			SetLocalUserSSHKeyBits(cfg.LocalUserSSHKeyBits).
			SetLocalUserSSHKeyComment(cfg.LocalUserSSHKeyComment).
			SetLocalUserSSHKeyFile(cfg.LocalUserSSHKeyFile).
			SetLocalUserSSHKeyPassphrase(cfg.LocalUserSSHKeyPassphrase).
			SetLocalUserSSHKeyType(cfg.LocalUserSSHKeyType).
			SetLocalUserIDMax(cfg.LocalUserUIDMax).
			SetLocalUserIDMin(cfg.LocalUserUIDMin).
			SetLocalUserForce(cfg.LocalUserForce).
			SetLocalUserAppend(cfg.LocalUserAppend).
			Exec(context.Background())
	case task.TypeRemoveUnixLocalUser.String():
		return query.
			SetLocalUserUsername(cfg.LocalUserUsername).
			SetLocalUserForce(cfg.LocalUserForce).
			Exec(context.Background())
	case task.TypeRemoveLocalUser.String():
		return query.
			SetLocalUserUsername(cfg.LocalUserUsername).
			Exec(context.Background())
	case task.TypeAddLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupDescription(cfg.LocalGroupDescription).
			SetLocalGroupMembers(cfg.LocalGroupMembers).
			Exec(context.Background())
	case task.TypeRemoveLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			Exec(context.Background())
	case task.TypeAddUnixLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupID(cfg.LocalGroupID).
			SetLocalGroupSystem(cfg.LocalGroupSystem).
			Exec(context.Background())
	case task.TypeRemoveUnixLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupForce(cfg.LocalGroupForce).
			Exec(context.Background())
	case task.TypeAddUsersToLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupDescription(cfg.LocalGroupDescription).
			SetLocalGroupMembersToInclude(cfg.LocalGroupMembersToInclude).
			Exec(context.Background())
	case task.TypeRemoveUsersFromLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupDescription(cfg.LocalGroupDescription).
			SetLocalGroupMembersToExclude(cfg.LocalGroupMembersToExclude).
			Exec(context.Background())
	case task.TypeMsiInstall.String(), task.TypeMsiUninstall.String():
		query := query.
			SetMsiProductid(cfg.MsiProductID).
			SetMsiPath(cfg.MsiPath).
			SetMsiArguments(cfg.MsiArguments).
			SetMsiLogPath(cfg.MsiLogPath)

		if cfg.MsiHashAlgorithm != "" && cfg.MsiFileHash != "" {
			query = query.SetMsiFileHashAlg(task.MsiFileHashAlg(cfg.MsiHashAlgorithm)).SetMsiFileHash(cfg.MsiFileHash)
		}
		return query.Exec(context.Background())
	case task.TypePowershellScript.String():
		return query.SetScript(cfg.ShellScript).SetScriptRun(task.ScriptRun(cfg.ShellRunConfig)).Exec(context.Background())
	case task.TypeUnixScript.String():
		return query.SetScript(cfg.ShellScript).SetScriptCreates(cfg.ShellCreates).SetScriptExecutable(cfg.ShellExecute).Exec(context.Background())
	case task.TypeFlatpakInstall.String(), task.TypeFlatpakUninstall.String():
		return query.SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetPackageLatest(cfg.PackageLatest).Exec(context.Background())
	case task.TypeBrewCaskInstall.String(), task.TypeBrewCaskUninstall.String(), task.TypeBrewCaskUpgrade.String(),
		task.TypeBrewFormulaInstall.String(), task.TypeBrewFormulaUninstall.String(), task.TypeBrewFormulaUpgrade.String():
		return query.SetPackageID(cfg.PackageID).
			SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetBrewUpdate(cfg.HomeBrewUpdate).SetBrewGreedy(cfg.HomeBrewGreedy).
			SetBrewInstallOptions(cfg.HomeBrewInstallOptions).SetBrewUpgradeOptions(cfg.HomeBrewUpgradeOptions).SetBrewUpgradeAll(cfg.HomeBrewUpgradeAll).Exec(context.Background())
	case task.TypeNetbirdInstall.String(), task.TypeNetbirdUninstall.String():
		return query.Exec(context.Background())
	case task.TypeNetbirdRegister.String():
		tenantID := c.Param("tenant")
		if tenantID == "" {
			return errors.New("tenant ID cannot be empty")
		}
		id, err := strconv.Atoi(tenantID)
		if err != nil {
			return errors.New("could not parse tenant ID as an int")
		}

		return query.SetTenant(id).SetNetbirdGroups(cfg.NetbirdGroups).SetNetbirdAllowExtraDNSLabels(cfg.NetbirdAllowExtraDNSLabels).Exec(context.Background())
	}
	return errors.New(i18n.T(c.Request().Context(), "tasks.unexpected_task_type"))
}

func (m *Model) GetTasksForProfileByPage(p partials.PaginationAndSort, profileID int) ([]*ent.Task, error) {
	if p.CurrentPage <= 0 || p.CurrentPage > 1000000 || p.PageSize <= 0 || p.PageSize > 1000 {
		return nil, errors.New("invalid task pagination")
	}
	offset := (p.CurrentPage - 1) * p.PageSize
	tasks, err := m.Client.Task.Query().Where(task.HasProfileWith(profile.ID(profileID))).Order(task.ByOrder(), task.ByID()).Limit(p.PageSize).Offset(offset).All(context.Background())
	if err != nil {
		return nil, err
	}
	// Display dense positions without writing legacy zero, duplicate or gapped orders on GET.
	for i, t := range tasks {
		t.Order = offset + i + 1
	}
	return tasks, nil
}

func (m *Model) GetTasksById(taskID int) (*ent.Task, error) {
	return m.Client.Task.Query().WithProfile().Where(task.ID(taskID)).First(context.Background())
}

func (m *Model) GetTaskSensitiveInformation() ([]*ent.Task, error) {
	return m.Client.Task.Query().Select(task.FieldID, task.FieldLocalUserPassword).All(context.Background())
}

func (m *Model) UpdateLocalUserPassword(taskID int, password string) error {
	return m.Client.Task.UpdateOneID(taskID).SetLocalUserPassword(password).Exec(context.Background())
}
