package taskexecution_test

import (
	"strings"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/open-uem/utils"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func executableTask(kind task.Type, platform task.AgentType) *ent.Task {
	t := &ent.Task{ID: 17, Version: 3, Name: "Owned execution", Type: kind, AgentType: platform, PackageName: "Owned package", PackageID: "Owned.Package", PackageBranch: "stable", RegistryKey: `HKEY_LOCAL_MACHINE\Software\Owned`, RegistryKeyValueName: "OwnedValue", RegistryKeyValueType: task.RegistryKeyValueTypeString, RegistryKeyValueData: "Owned data", LocalUserUsername: "owned-user", LocalGroupName: "owned-group", LocalGroupMembers: "owned-user", LocalGroupMembersToInclude: "owned-user", LocalGroupMembersToExclude: "owned-user", MsiProductid: "{00000000-0000-4000-8000-000000000001}", MsiPath: "https://packages.example.invalid/owned.msi", MsiFileHashAlg: task.MsiFileHashAlgSHA256, Script: "echo owned", ScriptExecutable: "/bin/sh", ScriptRun: task.ScriptRunOnce}
	t.Edges.Profile = &ent.Profile{ID: 7, Name: "Owned parent"}
	return t
}

func TestEverySupportedManualTaskBuildsAnExecutableResource(t *testing.T) {
	kinds := []task.Type{task.TypeWingetInstall, task.TypeWingetDelete, task.TypeAddRegistryKey, task.TypeRemoveRegistryKey, task.TypeUpdateRegistryKeyDefaultValue, task.TypeAddRegistryKeyValue, task.TypeRemoveRegistryKeyValue, task.TypeAddLocalUser, task.TypeRemoveLocalUser, task.TypeAddLocalGroup, task.TypeRemoveLocalGroup, task.TypeAddUsersToLocalGroup, task.TypeRemoveUsersFromLocalGroup, task.TypeMsiInstall, task.TypeMsiUninstall, task.TypePowershellScript, task.TypeAddUnixLocalUser, task.TypeRemoveUnixLocalUser, task.TypeAddUnixLocalGroup, task.TypeRemoveUnixLocalGroup, task.TypeUnixScript, task.TypeFlatpakInstall, task.TypeFlatpakUninstall, task.TypeBrewCaskInstall, task.TypeBrewCaskUninstall, task.TypeBrewCaskUpgrade, task.TypeBrewFormulaInstall, task.TypeBrewFormulaUninstall, task.TypeBrewFormulaUpgrade}
	count := 0
	for _, platform := range []task.AgentType{task.AgentTypeWindows, task.AgentTypeLinux, task.AgentTypeMacos} {
		for _, kind := range kinds {
			if !taskexecution.Supported(kind, platform) {
				continue
			}
			t.Run(kind.String()+"/"+platform.String(), func(t *testing.T) {
				source := executableTask(kind, platform)
				payload, err := taskexecution.Build(source, "")
				require.NoError(t, err)
				require.NotEmpty(t, payload.Data)
				var config openuem.ProfileConfig
				require.NoError(t, yaml.Unmarshal(payload.Data, &config))
				require.Equal(t, 7, config.ProfileID)
				if platform == task.AgentTypeWindows {
					require.Equal(t, "windowstask", payload.Operation)
					require.Len(t, config.WinGetConfig.Properties.Resources, 1)
				} else {
					require.Equal(t, "ansible", payload.Operation)
					require.Len(t, config.AnsibleConfig, 1)
					require.NotEmpty(t, config.AnsibleConfig[0].Tasks)
				}
				if kind == task.TypeRemoveUnixLocalUser {
					require.Contains(t, string(payload.Data), "state: absent")
					require.Contains(t, string(payload.Data), "owned-user")
				}
				require.Equal(t, 3, source.Version)
				require.Equal(t, 7, source.Edges.Profile.ID)
			})
			count++
		}
	}
	require.Equal(t, 34, count)
}

func TestManualPayloadSecretsBoundsAndUnsupportedSources(t *testing.T) {
	key := strings.Repeat("x", 32)
	encrypted, err := utils.EncryptSensitiveField("owned-private-password", key)
	require.NoError(t, err)
	for _, platform := range []task.AgentType{task.AgentTypeWindows, task.AgentTypeLinux, task.AgentTypeMacos} {
		kind := task.TypeAddLocalUser
		if platform != task.AgentTypeWindows {
			kind = task.TypeAddUnixLocalUser
		}
		source := executableTask(kind, platform)
		source.LocalUserPassword = encrypted
		payload, err := taskexecution.Build(source, key)
		require.NoError(t, err)
		require.Contains(t, string(payload.Data), "owned-private-password")
		require.NotContains(t, string(payload.Data), encrypted)
		require.Equal(t, encrypted, source.LocalUserPassword)
		for _, wrong := range []string{"", "wrong-owned-key"} {
			p, err := taskexecution.Build(source, wrong)
			require.ErrorIs(t, err, taskexecution.ErrInvalid)
			require.Nil(t, p)
		}
		source.LocalUserPassword = "aabb"
		require.NotPanics(t, func() { _, err := taskexecution.Build(source, key); require.NoError(t, err) })
	}
	for _, alter := range []func(*ent.Task){
		func(t *ent.Task) { t.Disabled = true },
		func(t *ent.Task) { t.Edges.Profile = nil },
		func(t *ent.Task) { t.Script = strings.Repeat("x", (128<<10)+1) },
		func(t *ent.Task) { t.Name = strings.Repeat("界", 700) },
		func(t *ent.Task) { t.LocalUserPassword = strings.Repeat("x", 16385) },
		func(t *ent.Task) { t.Script = "invalid\x00script" },
	} {
		source := executableTask(task.TypePowershellScript, task.AgentTypeWindows)
		alter(source)
		p, err := taskexecution.Build(source, key)
		require.ErrorIs(t, err, taskexecution.ErrInvalid)
		require.Nil(t, p)
	}
	for _, source := range []*ent.Task{nil, executableTask(task.TypeNetbirdRegister, task.AgentTypeAny), executableTask(task.TypeWingetUpdate, task.AgentTypeWindows), executableTask(task.TypeUnixScript, task.AgentTypeWindows)} {
		p, err := taskexecution.Build(source, key)
		require.ErrorIs(t, err, taskexecution.ErrUnsupported)
		require.Nil(t, p)
	}
}
