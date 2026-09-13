package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/taskconfig"
	"github.com/open-uem/utils"
	"github.com/stretchr/testify/require"
)

func ownedTaskConfiguration() taskconfig.Config {
	return taskconfig.Config{TaskType: task.TypePowershellScript.String(), AgentsType: task.AgentTypeWindows.String(), Description: "Owned <created> task", ShellScript: "echo owned", ShellRunConfig: task.ScriptRunAlways.String(), RegistryKey: `HKLM:\Software\Owned`, RegistryKeyValue: "Owned", RegistryKeyValueType: task.RegistryKeyValueTypeDWord.String(), RegistryKeyValueData: "1", MsiHashAlgorithm: task.MsiFileHashAlgSHA256.String(), IgnoreErrors: true}
}

func TestTaskCreationScopesDefaultsAndExistingConfiguration(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		g := ownedDeletionGraph(t, f, scope)
		require.NoError(t, f.client.Task.UpdateOneID(g.task).SetOrder(9).SetVersion(7).Exec(ctx))
		cfg := ownedTaskConfiguration()
		create := func(actor string, requested access.Scope) (int64, error) {
			return inventory.CreateLegacyTask(ctx, f.db, f.permissions, actor, requested, int64(g.profile), cfg, "")
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			id, err := create(actor, scope)
			require.Zero(t, id)
			require.ErrorIs(t, err, access.ErrDenied)
			_, err = inventory.ReviewTaskCreation(ctx, f.db, f.permissions, actor, scope, int64(g.profile))
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, organization, f.scope} {
			if wrong != scope {
				id, err := create("admin", wrong)
				require.Zero(t, id)
				require.ErrorIs(t, err, inventory.ErrNotFound)
				_, err = inventory.ReviewTaskCreation(ctx, f.db, f.permissions, "admin", wrong, int64(g.profile))
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		}
		review, err := inventory.ReviewTaskCreation(ctx, f.db, f.permissions, "admin", scope, int64(g.profile))
		require.NoError(t, err)
		require.Equal(t, int64(g.profile), review.ProfileID)
		require.Equal(t, "Owned <deletion> profile", review.ProfileName)
		id, err := create("admin", scope)
		require.NoError(t, err)
		require.Positive(t, id)
		created, err := f.client.Task.Query().Where(task.ID(int(id))).WithProfile().WithTags().WithReports().Only(ctx)
		require.NoError(t, err)
		require.Equal(t, cfg.Description, created.Name)
		require.Equal(t, 2, created.Order)
		require.Equal(t, 1, created.Version)
		require.False(t, created.Disabled)
		require.True(t, created.When.IsZero())
		require.True(t, created.IgnoreErrors)
		require.Equal(t, g.profile, created.Edges.Profile.ID)
		require.Equal(t, cfg.ShellScript, created.Script)
		require.Empty(t, created.Edges.Tags)
		require.Empty(t, created.Edges.Reports)
		current, err := f.client.Task.Get(ctx, g.task)
		require.NoError(t, err)
		require.Equal(t, 1, current.Order)
		require.Equal(t, 7, current.Version)
		assertDeletionGraph(t, f, g, true)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		for _, action := range []string{"inventory.tasks.create_review", "inventory.tasks.create"} {
			resource := fmt.Sprint(g.profile)
			if action == "inventory.tasks.create" {
				resource = fmt.Sprintf("%d/profile/%d/position/2", id, g.profile)
			}
			filter := audit.Filter{Scope: scope, Source: "inventory", Action: action, Resource: resource, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
			page, err := audits.List(ctx, "admin", filter, "")
			require.NoError(t, err)
			require.Len(t, page.Events, 1)
			data, err := audits.ExportJSON(ctx, "admin", filter)
			require.NoError(t, err)
			require.Contains(t, string(data), resource)
			require.NotContains(t, string(data), "echo owned")
		}
	}
}

func TestTaskCreationMapperAndScopedNetbirdDefaults(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned mapper profile")
	families := map[string][]task.Type{
		"windows": {task.TypeWingetInstall, task.TypeWingetDelete, task.TypeAddRegistryKey, task.TypeRemoveRegistryKey, task.TypeUpdateRegistryKeyDefaultValue, task.TypeAddRegistryKeyValue, task.TypeRemoveRegistryKeyValue, task.TypeAddLocalUser, task.TypeRemoveLocalUser, task.TypeAddLocalGroup, task.TypeRemoveLocalGroup, task.TypeAddUsersToLocalGroup, task.TypeRemoveUsersFromLocalGroup, task.TypeMsiInstall, task.TypeMsiUninstall, task.TypePowershellScript},
		"linux":   {task.TypeAddUnixLocalUser, task.TypeRemoveUnixLocalUser, task.TypeAddUnixLocalGroup, task.TypeRemoveUnixLocalGroup, task.TypeUnixScript, task.TypeFlatpakInstall, task.TypeFlatpakUninstall},
		"macos":   {task.TypeUnixScript, task.TypeAddUnixLocalUser, task.TypeRemoveUnixLocalUser, task.TypeAddUnixLocalGroup, task.TypeRemoveUnixLocalGroup, task.TypeBrewCaskInstall, task.TypeBrewCaskUninstall, task.TypeBrewCaskUpgrade, task.TypeBrewFormulaInstall, task.TypeBrewFormulaUninstall, task.TypeBrewFormulaUpgrade},
		"any":     {task.TypeNetbirdInstall, task.TypeNetbirdUninstall, task.TypeNetbirdRegister},
	}
	position := 0
	for platform, types := range families {
		for _, kind := range types {
			cfg := ownedTaskConfiguration()
			cfg.AgentsType = platform
			cfg.TaskType = kind.String()
			cfg.Description = "Owned " + platform + " " + kind.String()
			cfg.NetbirdGroups = `"owned-group"`
			cfg.NetbirdAllowExtraDNSLabels = true
			id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, "")
			require.NoError(t, err, kind)
			position++
			created, err := f.client.Task.Get(ctx, int(id))
			require.NoError(t, err)
			require.Equal(t, kind, created.Type)
			require.Equal(t, platform, created.AgentType.String())
			require.Equal(t, position, created.Order)
			require.Equal(t, 1, created.Version)
			require.True(t, created.IgnoreErrors)
			if kind == task.TypeNetbirdRegister {
				require.Equal(t, f.scope.TenantID, created.Tenant)
				require.Equal(t, cfg.NetbirdGroups, created.NetbirdGroups)
				require.True(t, created.NetbirdAllowExtraDNSLabels)
			}
			if kind == task.TypeUpdateRegistryKeyDefaultValue {
				require.Equal(t, task.RegistryKeyValueTypeDWord, created.RegistryKeyValueType)
			}
		}
	}
}

func TestTaskCreationRollbackAndPasswordStorage(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	require.NoError(t, f.client.Task.UpdateOneID(g.task).SetOrder(9).Exec(ctx))
	cfg := ownedTaskConfiguration()
	create := func(ctx context.Context, cfg taskconfig.Config, key string) (int64, error) {
		return inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), cfg, key)
	}
	assertRetained := func() {
		assertDeletionGraph(t, f, g, true)
		var n int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM tasks WHERE profile_tasks=$1`, g.profile).Scan(&n))
		require.Equal(t, 1, n)
		entry, err := f.client.Task.Get(ctx, g.task)
		require.NoError(t, err)
		require.Equal(t, 9, entry.Order)
	}
	invalid := cfg
	invalid.TaskType = task.TypeUpdateRegistryKeyDefaultValue.String()
	invalid.RegistryKeyValueType = "invalid"
	id, err := create(ctx, invalid, "")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	assertRetained()
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_task_create_failure CHECK(action NOT IN ('inventory.tasks.create','inventory.tasks.create_review')) NOT VALID`)
	require.NoError(t, err)
	id, err = create(ctx, cfg, "")
	require.Zero(t, id)
	require.Error(t, err)
	assertRetained()
	review, err := inventory.ReviewTaskCreation(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile))
	require.Nil(t, review)
	require.Error(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_task_create_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	id, err = create(canceled, cfg, "")
	require.Zero(t, id)
	require.Error(t, err)
	assertRetained()
	cfg.TaskType = task.TypeAddLocalUser.String()
	cfg.LocalUserUsername = "Owned account"
	cfg.LocalUserPassword = "Owned secret value"
	id, err = create(ctx, cfg, "")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrTaskSecretStorage)
	assertRetained()
	key := strings.Repeat("k", 32)
	id, err = create(ctx, cfg, key)
	require.NoError(t, err)
	created, err := f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	require.NotEqual(t, cfg.LocalUserPassword, created.LocalUserPassword)
	decoded, err := utils.DecryptSensitiveField(created.LocalUserPassword, key)
	require.NoError(t, err)
	require.True(t, decoded == cfg.LocalUserPassword, "stored password did not round trip")
}

func TestTaskCreationValidatesPlatformProviderAndReviewBounds(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	cfg := ownedTaskConfiguration()
	require.NoError(t, f.client.Profile.UpdateOneID(g.profile).SetName(strings.Repeat("界", 2048)).Exec(ctx))
	review, err := inventory.ReviewTaskCreation(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile))
	require.NoError(t, err)
	require.True(t, review.NameTruncated)
	require.Equal(t, strings.Repeat("界", 512), review.ProfileName)
	for _, platform := range []string{"linux", "any", "invalid"} {
		bad := cfg
		bad.AgentsType = platform
		id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), bad, "")
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	}
	for _, name := range []string{"", " ", strings.Repeat("x", 2049), "bad\x00name"} {
		bad := cfg
		bad.Description = name
		id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), bad, "")
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	}
	global := ownedTagProfile(t, f, access.Scope{}, "Owned global")
	cfg.TaskType = task.TypeNetbirdRegister.String()
	cfg.AgentsType = "any"
	id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", access.Scope{}, int64(global.ID), cfg, "")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrProfileCloneProviderScope)
	_, err = f.db.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, g.profile)
	require.NoError(t, err)
	cfg = ownedTaskConfiguration()
	id, err = inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), cfg, "")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}
