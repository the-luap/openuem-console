package taskconfig

import (
	"context"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/task"
)

// Nil preserves the stored value without reading or returning it. A pointer to
// an empty string explicitly clears that secret from the task configuration.
type SecretUpdate struct {
	Password         *string
	SSHKeyPassphrase *string
}

// Update changes configuration in the caller's locked transaction. Type,
// platform, parent, status, order and historical results stay unchanged.
func Update(ctx context.Context, client *ent.Client, taskID, profileID, nextVersion int, cfg Config, secrets SecretUpdate) (int, error) {

	// common query
	query := client.Task.Update().Where(task.ID(taskID), task.HasProfileWith(profile.ID(profileID))).SetName(cfg.Description).SetIgnoreErrors(cfg.IgnoreErrors)

	// Update version
	query.SetVersion(nextVersion)

	// Specify values to be updated

	switch cfg.TaskType {
	case task.TypeWingetInstall.String(), task.TypeWingetDelete.String():
		return query.SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetPackageVersion(cfg.PackageVersion).SetPackageLatest(cfg.PackageLatest).Save(ctx)
	case task.TypeAddRegistryKey.String():
		return query.SetRegistryKey(cfg.RegistryKey).Save(ctx)
	case task.TypeRemoveRegistryKey.String():
		return query.SetRegistryKey(cfg.RegistryKey).SetRegistryForce(cfg.RegistryForce).Save(ctx)
	case task.TypeUpdateRegistryKeyDefaultValue.String():
		return query.SetRegistryKey(cfg.RegistryKey).SetRegistryKeyValueType(task.RegistryKeyValueType(cfg.RegistryKeyValueType)).
			SetRegistryKeyValueData(cfg.RegistryKeyValueData).SetRegistryForce(cfg.RegistryForce).Save(ctx)
	case task.TypeAddRegistryKeyValue.String():
		return query.
			SetRegistryKey(cfg.RegistryKey).
			SetRegistryKeyValueName(cfg.RegistryKeyValue).
			SetRegistryKeyValueType(task.RegistryKeyValueType(cfg.RegistryKeyValueType)).
			SetRegistryKeyValueData(cfg.RegistryKeyValueData).
			SetRegistryHex(cfg.RegistryHex).
			SetRegistryForce(cfg.RegistryForce).Save(ctx)
	case task.TypeRemoveRegistryKeyValue.String():
		return query.
			SetRegistryKey(cfg.RegistryKey).
			SetRegistryKeyValueName(cfg.RegistryKeyValue).Save(ctx)
	case task.TypeAddLocalUser.String():
		return query.
			SetLocalUserUsername(cfg.LocalUserUsername).
			SetLocalUserDescription(cfg.LocalUserDescription).
			SetLocalUserFullname(cfg.LocalUserFullName).
			SetNillableLocalUserPassword(secrets.Password).
			SetLocalUserDisable(cfg.LocalUserDisabled).
			SetLocalUserPasswordChangeNotAllowed(cfg.LocalUserPasswordChangeNotAllowed).
			SetLocalUserPasswordChangeRequired(cfg.LocalUserPasswordChangeRequired).
			SetLocalUserPasswordNeverExpires(cfg.LocalUserNeverExpires).
			Save(ctx)
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
			SetNillableLocalUserPassword(secrets.Password).
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
			SetNillableLocalUserSSHKeyPassphrase(secrets.SSHKeyPassphrase).
			SetLocalUserSSHKeyType(cfg.LocalUserSSHKeyType).
			SetLocalUserIDMax(cfg.LocalUserUIDMax).
			SetLocalUserIDMin(cfg.LocalUserUIDMin).
			SetLocalUserForce(cfg.LocalUserForce).
			SetLocalUserAppend(cfg.LocalUserAppend).
			Save(ctx)
	case task.TypeRemoveUnixLocalUser.String():
		return query.
			SetLocalUserUsername(cfg.LocalUserUsername).
			SetLocalUserForce(cfg.LocalUserForce).
			Save(ctx)
	case task.TypeRemoveLocalUser.String():
		return query.
			SetLocalUserUsername(cfg.LocalUserUsername).
			Save(ctx)
	case task.TypeAddLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupDescription(cfg.LocalGroupDescription).
			SetLocalGroupMembers(cfg.LocalGroupMembers).
			Save(ctx)
	case task.TypeRemoveLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			Save(ctx)
	case task.TypeAddUnixLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupID(cfg.LocalGroupID).
			SetLocalGroupSystem(cfg.LocalGroupSystem).
			Save(ctx)
	case task.TypeRemoveUnixLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupForce(cfg.LocalGroupForce).
			Save(ctx)
	case task.TypeAddUsersToLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupDescription(cfg.LocalGroupDescription).
			SetLocalGroupMembersToInclude(cfg.LocalGroupMembersToInclude).
			Save(ctx)
	case task.TypeRemoveUsersFromLocalGroup.String():
		return query.
			SetLocalGroupName(cfg.LocalGroupName).
			SetLocalGroupDescription(cfg.LocalGroupDescription).
			SetLocalGroupMembersToExclude(cfg.LocalGroupMembersToExclude).
			Save(ctx)
	case task.TypeMsiInstall.String(), task.TypeMsiUninstall.String():
		query := query.
			SetMsiProductid(cfg.MsiProductID).
			SetMsiPath(cfg.MsiPath).
			SetMsiArguments(cfg.MsiArguments).
			SetMsiLogPath(cfg.MsiLogPath)

		if cfg.MsiHashAlgorithm != "" && cfg.MsiFileHash != "" {
			query = query.SetMsiFileHashAlg(task.MsiFileHashAlg(cfg.MsiHashAlgorithm)).SetMsiFileHash(cfg.MsiFileHash)
		} else {
			query = query.ClearMsiFileHashAlg().ClearMsiFileHash()
		}
		return query.Save(ctx)
	case task.TypePowershellScript.String():
		return query.SetScript(cfg.ShellScript).SetScriptRun(task.ScriptRun(cfg.ShellRunConfig)).Save(ctx)
	case task.TypeUnixScript.String():
		return query.SetScript(cfg.ShellScript).SetScriptCreates(cfg.ShellCreates).SetScriptExecutable(cfg.ShellExecute).Save(ctx)
	case task.TypeFlatpakInstall.String(), task.TypeFlatpakUninstall.String():
		return query.SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetPackageLatest(cfg.PackageLatest).SetPackageBranch(cfg.PackageBranch).Save(ctx)
	case task.TypeBrewCaskInstall.String(), task.TypeBrewCaskUninstall.String(), task.TypeBrewCaskUpgrade.String(),
		task.TypeBrewFormulaInstall.String(), task.TypeBrewFormulaUninstall.String(), task.TypeBrewFormulaUpgrade.String():
		return query.SetPackageID(cfg.PackageID).
			SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetBrewUpdate(cfg.HomeBrewUpdate).SetBrewGreedy(cfg.HomeBrewGreedy).
			SetBrewInstallOptions(cfg.HomeBrewInstallOptions).SetBrewUpgradeOptions(cfg.HomeBrewUpgradeOptions).SetBrewUpgradeAll(cfg.HomeBrewUpgradeAll).Save(ctx)
	case task.TypeNetbirdInstall.String(), task.TypeNetbirdUninstall.String():
		return query.Save(ctx)
	case task.TypeNetbirdRegister.String():
		return query.SetNetbirdGroups(cfg.NetbirdGroups).SetNetbirdAllowExtraDNSLabels(cfg.NetbirdAllowExtraDNSLabels).Save(ctx)
	}
	return 0, ErrInvalid
}
