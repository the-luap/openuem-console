package taskexecution

import (
	"fmt"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	ansiblecfg "github.com/open-uem/openuem-ansible-config/ansible"
	"github.com/open-uem/wingetcfg/wingetcfg"
	"strconv"
)

func ansiblePlaybook(t *ent.Task, masterKey string) (*ansiblecfg.AnsiblePlaybook, error) {
	var err error

	pb := ansiblecfg.NewAnsiblePlaybook()
	pb.Name = t.Edges.Profile.Name

	switch t.Type {
	case task.TypeAddUnixLocalGroup:
		var gid int

		if t.LocalGroupID != "" {
			gid, err = strconv.Atoi(t.LocalGroupID)
			if err != nil {
				return nil, err
			}
		}

		addLocalGroup, err := ansiblecfg.AddLocalGroup(fmt.Sprintf("task_%d", t.ID), t.LocalGroupName, gid, t.LocalGroupSystem, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(addLocalGroup)

	case task.TypeAddUnixLocalUser:
		var expires float64
		var password_expire_account_disable int
		var password_expire_max int
		var password_expire_min int
		var password_expire_warn int
		var ssh_key_bits int
		var uid int
		var uid_max int
		var uid_min int

		if t.LocalUserExpires != "" {
			expires, err = strconv.ParseFloat(t.LocalUserExpires, 64)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserPasswordExpireAccountDisable != "" {
			password_expire_account_disable, err = strconv.Atoi(t.LocalUserPasswordExpireAccountDisable)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserPasswordExpireMax != "" {
			password_expire_max, err = strconv.Atoi(t.LocalUserPasswordExpireMax)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserPasswordExpireMin != "" {
			password_expire_min, err = strconv.Atoi(t.LocalUserPasswordExpireMin)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserPasswordExpireWarn != "" {
			password_expire_warn, err = strconv.Atoi(t.LocalUserPasswordExpireWarn)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserSSHKeyBits != "" {
			ssh_key_bits, err = strconv.Atoi(t.LocalUserSSHKeyBits)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserID != "" {
			uid, err = strconv.Atoi(t.LocalUserID)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserIDMax != "" {
			uid_max, err = strconv.Atoi(t.LocalUserIDMax)
			if err != nil {
				return nil, err
			}
		}

		if t.LocalUserIDMin != "" {
			uid_min, err = strconv.Atoi(t.LocalUserIDMin)
			if err != nil {
				return nil, err
			}
		}

		password, err := legacyPassword(t.LocalUserPassword, masterKey)
		if err != nil {
			return nil, err
		}
		t.LocalUserPassword = password

		addLinuxUser, err := ansiblecfg.AddLocalUser(fmt.Sprintf("task_%d", t.ID), t.LocalUserAppend, t.LocalUserDescription,
			t.LocalUserCreateHome, expires, t.LocalUserForce, t.LocalUserGenerateSSHKey, t.LocalUserGroup, t.LocalUserGroups,
			t.LocalUserHome, t.LocalUserUsername, t.LocalUserNonunique, t.LocalUserPassword, password_expire_account_disable, password_expire_max,
			password_expire_min, password_expire_warn, t.LocalUserPasswordLock, t.LocalUserShell, t.LocalUserSkeleton, ssh_key_bits,
			t.LocalUserSSHKeyComment, t.LocalUserSSHKeyFile, t.LocalUserSSHKeyPassphrase, t.LocalUserSSHKeyType,
			t.LocalUserSystem, t.LocalUserUmask, uid, uid_max, uid_min, t.AgentType.String(), t.IgnoreErrors)

		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(addLinuxUser)

	case task.TypeRemoveUnixLocalUser:
		removeLinux, err := ansiblecfg.RemoveLocalUser(fmt.Sprintf("task_%d", t.ID), t.LocalUserForce, t.LocalUserUsername, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(removeLinux)

	case task.TypeRemoveUnixLocalGroup:
		removeLocalGroup, err := ansiblecfg.RemoveLocalGroup(fmt.Sprintf("task_%d", t.ID), t.LocalGroupName, t.LocalGroupForce, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(removeLocalGroup)

	case task.TypeUnixScript:
		executeScript, err := ansiblecfg.ExecuteScript(fmt.Sprintf("task_%d", t.ID), t.Script, t.ScriptExecutable, t.ScriptCreates, t.AgentType.String(), t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(executeScript)
	case task.TypeFlatpakInstall:
		install, err := ansiblecfg.InstallFlatpakPackage(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.PackageBranch, t.PackageLatest, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(install)
	case task.TypeFlatpakUninstall:
		uninstall, err := ansiblecfg.UninstallFlatpakPackage(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.PackageBranch, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(uninstall)
	case task.TypeBrewFormulaInstall:
		install, err := ansiblecfg.InstallHomeBrewFormula(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.BrewInstallOptions, t.BrewUpdate, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(install)
	case task.TypeBrewFormulaUpgrade:
		upgrade, err := ansiblecfg.UpgradeHomeBrewFormula(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.BrewUpdate, t.BrewUpgradeAll, t.BrewUpgradeOptions, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(upgrade)
	case task.TypeBrewFormulaUninstall:
		uninstall, err := ansiblecfg.UninstallHomeBrewFormula(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(uninstall)
	case task.TypeBrewCaskInstall:
		install, err := ansiblecfg.InstallHomeBrewCask(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.BrewInstallOptions, t.BrewUpdate, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(install)
	case task.TypeBrewCaskUpgrade:
		upgrade, err := ansiblecfg.UpgradeHomeBrewCask(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.BrewGreedy, t.BrewUpdate, t.BrewUpgradeAll, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(upgrade)
	case task.TypeBrewCaskUninstall:
		uninstall, err := ansiblecfg.UninstallHomeBrewCask(fmt.Sprintf("task_%d", t.ID), t.PackageID, t.IgnoreErrors)
		if err != nil {
			return nil, err
		}
		pb.AddAnsibleTask(uninstall)
	}

	return pb, nil
}

func windowsConfiguration(t *ent.Task, masterKey string) (*wingetcfg.WinGetCfg, error) {
	cfg := wingetcfg.NewWingetCfg()

	taskID := fmt.Sprintf("task_%d_%d", t.ID, t.Version)

	switch t.Type {
	case task.TypeWingetInstall:
		installPackage, err := wingetcfg.InstallPackage(taskID, t.PackageName, t.PackageID, "winget", t.PackageVersion, t.PackageLatest)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(installPackage)
	case task.TypeWingetDelete:
		uninstallPackage, err := wingetcfg.UninstallPackage(taskID, t.PackageName, t.PackageID, "winget", t.PackageVersion, t.PackageLatest)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(uninstallPackage)
	case task.TypeAddRegistryKey:
		registryKey, err := wingetcfg.AddRegistryKey(taskID, t.Name, t.RegistryKey)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(registryKey)
	case task.TypeRemoveRegistryKey:
		registryKey, err := wingetcfg.RemoveRegistryKey(taskID, t.Name, t.RegistryKey, t.RegistryForce)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(registryKey)
	case task.TypeUpdateRegistryKeyDefaultValue:
		registryKey, err := wingetcfg.UpdateRegistryKeyDefaultValue(taskID, t.Name, t.RegistryKey, string(t.RegistryKeyValueType), t.RegistryKeyValueData, t.RegistryForce)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(registryKey)
	case task.TypeAddRegistryKeyValue:
		registryKey, err := wingetcfg.AddRegistryValue(taskID, t.Name, t.RegistryKey, t.RegistryKeyValueName, string(t.RegistryKeyValueType), t.RegistryKeyValueData, t.RegistryHex, t.RegistryForce)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(registryKey)
	case task.TypeRemoveRegistryKeyValue:
		registryKey, err := wingetcfg.RemoveRegistryValue(taskID, t.Name, t.RegistryKey, t.RegistryKeyValueName)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(registryKey)
	case task.TypeAddLocalUser:
		password, err := legacyPassword(t.LocalUserPassword, masterKey)
		if err != nil {
			return nil, err
		}
		t.LocalUserPassword = password

		localUser, err := wingetcfg.AddOrModifyLocalUser(taskID, t.LocalUserUsername, t.LocalUserDescription, t.LocalUserDisable, t.LocalUserFullname, t.LocalUserPassword, t.LocalUserPasswordChangeNotAllowed, t.LocalUserPasswordChangeRequired, t.LocalUserPasswordNeverExpires)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(localUser)
	case task.TypeRemoveLocalUser:
		localUser, err := wingetcfg.RemoveLocalUser(taskID, t.LocalUserUsername)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(localUser)
	case task.TypeAddLocalGroup:
		localGroup, err := wingetcfg.AddOrModifyLocalGroup(taskID, t.LocalGroupName, t.LocalGroupDescription, t.LocalGroupMembers)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(localGroup)
	case task.TypeRemoveLocalGroup:
		localGroup, err := wingetcfg.RemoveLocalGroup(taskID, t.LocalGroupName)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(localGroup)
	case task.TypeAddUsersToLocalGroup:
		localGroup, err := wingetcfg.IncludeMembersToGroup(taskID, t.LocalGroupName, t.LocalGroupMembersToInclude)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(localGroup)
	case task.TypeRemoveUsersFromLocalGroup:
		localGroup, err := wingetcfg.ExcludeMembersFromGroup(taskID, t.LocalGroupName, t.LocalGroupMembersToExclude)
		if err != nil {
			return nil, err
		}
		cfg.AddResource(localGroup)
	case task.TypeMsiInstall:
		msiInstall, err := wingetcfg.InstallMSIPackage(taskID, fmt.Sprintf("Install %s", t.MsiProductid), t.MsiProductid, t.MsiPath, t.MsiArguments, t.MsiLogPath, t.MsiFileHash, string(t.MsiFileHashAlg))
		if err != nil {
			return nil, err
		}
		cfg.AddResource(msiInstall)
	case task.TypeMsiUninstall:
		msiUninstall, err := wingetcfg.UninstallMSIPackage(taskID, fmt.Sprintf("Uninstall %s", t.MsiProductid), t.MsiProductid, t.MsiPath, t.MsiArguments, t.MsiLogPath, t.MsiFileHash, string(t.MsiFileHashAlg))
		if err != nil {
			return nil, err
		}
		cfg.AddResource(msiUninstall)
	case task.TypePowershellScript:
		msiUninstall, err := wingetcfg.ExecutePowershellScript(taskID, t.Name, t.Script, t.ScriptRun.String())
		if err != nil {
			return nil, err
		}
		cfg.AddResource(msiUninstall)
	}
	return cfg, nil
}
