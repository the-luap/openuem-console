package taskconfig

import (
	"context"
	"errors"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
)

var ErrInvalid = errors.New("invalid task configuration")

type Config struct {
	TaskType                              string
	ExecuteCommand                        string
	PackageID                             string
	PackageName                           string
	PackageLatest                         bool
	PackageVersion                        string
	PackageBranch                         string
	PackageBrewType                       string
	Description                           string
	RegistryKey                           string
	RegistryKeyValue                      string
	RegistryKeyValueType                  string
	RegistryKeyValueData                  string
	RegistryHex                           bool
	RegistryForce                         bool
	LocalUserUsername                     string
	LocalUserDescription                  string
	LocalUserFullName                     string
	LocalUserPassword                     string
	LocalUserDisabled                     bool
	LocalUserPasswordChangeNotAllowed     bool
	LocalUserPasswordChangeRequired       bool
	LocalUserNeverExpires                 bool
	LocalUserID                           string
	LocalUserPrimaryGroup                 string
	LocalUserSupplementaryGroup           string
	LocalUserCreateHome                   bool
	LocalUserGenerateSSHKey               bool
	LocalUserSystemAccount                bool
	LocalUserHome                         string
	LocalUserShell                        string
	LocalUserUmask                        string
	LocalUserSkeleton                     string
	LocalUserExpires                      string
	LocalUserPasswordLock                 bool
	LocalUserPasswordExpireMax            string
	LocalUserPasswordExpireMin            string
	LocalUserPasswordExpireAccountDisable string
	LocalUserPasswordExpireWarn           string
	LocalUserSSHKeyBits                   string
	LocalUserSSHKeyComment                string
	LocalUserSSHKeyFile                   string
	LocalUserSSHKeyPassphrase             string
	LocalUserSSHKeyType                   string
	LocalUserUIDMax                       string
	LocalUserUIDMin                       string
	LocalUserForce                        bool
	LocalUserAppend                       bool
	LocalGroupName                        string
	LocalGroupDescription                 string
	LocalGroupMembers                     string
	LocalGroupMembersToInclude            string
	LocalGroupMembersToExclude            string
	LocalGroupID                          string
	LocalGroupSystem                      bool
	LocalGroupForce                       bool
	MsiProductID                          string
	MsiPath                               string
	MsiArguments                          string
	MsiLogPath                            string
	MsiHashAlgorithm                      string
	MsiFileHash                           string
	ShellScript                           string
	ShellRunConfig                        string
	ShellExecute                          string
	ShellCreates                          string
	AgentsType                            string
	HomeBrewUpgradeAll                    bool
	HomeBrewUpdate                        bool
	HomeBrewInstallOptions                string
	HomeBrewUpgradeOptions                string
	HomeBrewGreedy                        bool
	NetbirdGroups                         string
	NetbirdAllowExtraDNSLabels            bool
	IgnoreErrors                          bool
}

// Create writes only the task row and its parent foreign key. It does not
// change assignments or open a transaction; callers supply a locked parent and
// the next position, and own the transaction used by client.
func Create(ctx context.Context, client *ent.Client, profileID, tenantID, position int, cfg Config) (*ent.Task, error) {
	// common query
	query := client.Task.Create().
		SetName(cfg.Description).
		SetType(task.Type(cfg.TaskType)).
		SetAgentType(task.AgentType(cfg.AgentsType)).
		SetProfileID(profileID).
		SetIgnoreErrors(cfg.IgnoreErrors).
		SetOrder(position).SetVersion(1).SetDisabled(false)

	switch cfg.TaskType {
	case task.TypeWingetInstall.String(), task.TypeWingetDelete.String():
		return query.SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetPackageVersion(cfg.PackageVersion).SetPackageLatest(cfg.PackageLatest).Save(ctx)
	case task.TypeAddRegistryKey.String():
		return query.SetProfileID(profileID).SetRegistryKey(cfg.RegistryKey).Save(ctx)
	case task.TypeRemoveRegistryKey.String():
		return query.SetRegistryKey(cfg.RegistryKey).SetRegistryForce(cfg.RegistryForce).Save(ctx)
	case task.TypeUpdateRegistryKeyDefaultValue.String():
		return query.
			SetRegistryKey(cfg.RegistryKey).SetRegistryKeyValueType(task.RegistryKeyValueType(cfg.RegistryKeyValueType)).
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
			SetLocalUserPassword(cfg.LocalUserPassword).
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
		}
		return query.Save(ctx)
	case task.TypePowershellScript.String():
		return query.
			SetScript(cfg.ShellScript).SetScriptRun(task.ScriptRun(cfg.ShellRunConfig)).Save(ctx)
	case task.TypeUnixScript.String():
		return query.
			SetScript(cfg.ShellScript).SetScriptCreates(cfg.ShellCreates).SetScriptExecutable(cfg.ShellExecute).Save(ctx)
	case task.TypeFlatpakInstall.String(), task.TypeFlatpakUninstall.String():
		return query.SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetPackageLatest(cfg.PackageLatest).SetPackageBranch(cfg.PackageBranch).Save(ctx)
	case task.TypeBrewCaskInstall.String(), task.TypeBrewCaskUninstall.String(), task.TypeBrewCaskUpgrade.String(),
		task.TypeBrewFormulaInstall.String(), task.TypeBrewFormulaUninstall.String(), task.TypeBrewFormulaUpgrade.String():
		return query.
			SetPackageID(cfg.PackageID).SetPackageName(cfg.PackageName).SetBrewUpdate(cfg.HomeBrewUpdate).SetBrewGreedy(cfg.HomeBrewGreedy).SetPackageBrewType(cfg.PackageBrewType).
			SetBrewInstallOptions(cfg.HomeBrewInstallOptions).SetBrewUpgradeOptions(cfg.HomeBrewUpgradeOptions).SetBrewUpgradeAll(cfg.HomeBrewUpgradeAll).Save(ctx)
	case task.TypeNetbirdInstall.String(), task.TypeNetbirdUninstall.String():
		return query.Save(ctx)
	case task.TypeNetbirdRegister.String():
		if tenantID <= 0 {
			return nil, ErrInvalid
		}
		return query.SetTenant(tenantID).SetNetbirdGroups(cfg.NetbirdGroups).SetNetbirdAllowExtraDNSLabels(cfg.NetbirdAllowExtraDNSLabels).Save(ctx)
	}
	return nil, ErrInvalid
}
