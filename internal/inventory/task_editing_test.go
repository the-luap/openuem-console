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
	"github.com/open-uem/utils"
	"github.com/stretchr/testify/require"
)

func TestTaskEditingScopeVersionAndRollback(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	keep := inventory.TaskEditSecrets{PasswordAction: "keep", PassphraseAction: "keep"}
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		p := ownedTagProfile(t, f, scope, "Owned editing parent")
		cfg := ownedTaskConfiguration()
		id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", scope, int64(p.ID), cfg, "")
		require.NoError(t, err)
		cfg.Description = "Owned <edited> task"
		cfg.ShellScript = "Write-Output 'updated'"
		for _, actor := range []string{"tag-admin", "tag-viewer", "tag-operator", "viewer", "missing"} {
			_, err = inventory.ReviewTaskEdit(ctx, f.db, f.permissions, actor, scope, id)
			require.ErrorIs(t, err, access.ErrDenied)
			_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, actor, scope, id, int64(p.ID), 1, cfg, keep, "")
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, organization, f.scope} {
			if wrong != scope {
				_, err = inventory.ReviewTaskEdit(ctx, f.db, f.permissions, "admin", wrong, id)
				require.ErrorIs(t, err, inventory.ErrNotFound)
				_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", wrong, id, int64(p.ID), 1, cfg, keep, "")
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		}
		review, err := inventory.ReviewTaskEdit(ctx, f.db, f.permissions, "admin", scope, id)
		require.NoError(t, err)
		require.Equal(t, int64(p.ID), review.ProfileID)
		require.Equal(t, 1, review.Task.Version)
		version, err := inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", scope, id, int64(p.ID), 1, cfg, keep, "")
		require.NoError(t, err)
		require.Equal(t, 2, version)
		_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", scope, id, int64(p.ID), 1, cfg, keep, "")
		require.ErrorIs(t, err, inventory.ErrTaskEditConflict)
		_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", scope, id, int64(p.ID+1), 2, cfg, keep, "")
		require.ErrorIs(t, err, inventory.ErrNotFound)
		current, err := f.client.Task.Get(ctx, int(id))
		require.NoError(t, err)
		require.Equal(t, cfg.ShellScript, current.Script)
		require.Equal(t, cfg.Description, current.Name)
		require.Equal(t, 1, current.Order)
		require.False(t, current.Disabled)
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.update' AND resource_id=$1`, fmt.Sprintf("%d/profile/%d/version/2", id, p.ID)).Scan(&count))
		require.Equal(t, 1, count)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		for action, revision := range map[string]int{"inventory.tasks.edit_review": 1, "inventory.tasks.update": 2} {
			filter := audit.Filter{Scope: scope, Source: "inventory", Action: action, Resource: fmt.Sprintf("%d/profile/%d/version/%d", id, p.ID, revision), From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
			page, err := audits.List(ctx, "admin", filter, "")
			require.NoError(t, err)
			require.Len(t, page.Events, 1)
			data, err := audits.ExportJSON(ctx, "admin", filter)
			require.NoError(t, err)
			require.NotContains(t, string(data), "Write-Output")
			require.NotContains(t, string(data), "Owned changed")
		}

	}
	p := ownedTagProfile(t, f, f.scope, "Owned editing rollback parent")
	cfg := ownedTaskConfiguration()
	id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, "")
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_task_edit_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.update' OR NEW.action='inventory.tasks.edit_review' THEN RAISE EXCEPTION 'owned task edit audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_task_edit_audit BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_task_edit_audit()`)
	require.NoError(t, err)
	cfg.ShellScript = "must roll back"
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, keep, "")
	require.Error(t, err)
	current, err := f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	require.Equal(t, 1, current.Version)
	require.Equal(t, "echo owned", current.Script)
	review, err := inventory.ReviewTaskEdit(ctx, f.db, f.permissions, "admin", f.scope, id)
	require.Error(t, err)
	require.Nil(t, review)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = inventory.UpdateLegacyTask(cancelled, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, keep, "")
	require.Error(t, err)
}

func TestTaskEditingSecretsRemainHiddenAndRequireExplicitChanges(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned secret editing parent")
	cfg := ownedTaskConfiguration()
	cfg.TaskType = task.TypeAddUnixLocalUser.String()
	cfg.AgentsType = task.AgentTypeLinux.String()
	cfg.LocalUserUsername = "owned"
	cfg.LocalUserPassword = "original-owned-password"
	cfg.LocalUserSSHKeyPassphrase = "original-owned-passphrase"
	key := strings.Repeat("k", 32)
	id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, key)
	require.NoError(t, err)
	before, err := f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	review, err := inventory.ReviewTaskEdit(ctx, f.db, f.permissions, "admin", f.scope, id)
	require.NoError(t, err)
	require.True(t, review.PasswordSet)
	require.True(t, review.PassphraseSet)
	require.Empty(t, review.Task.LocalUserPassword)
	require.Empty(t, review.Task.LocalUserSSHKeyPassphrase)
	cfg.LocalUserPassword = ""
	cfg.LocalUserSSHKeyPassphrase = ""
	cfg.Description = "Owned renamed secret task"
	keep := inventory.TaskEditSecrets{PasswordAction: "keep", PassphraseAction: "keep"}
	version, err := inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, keep, "")
	require.NoError(t, err)
	require.Equal(t, 2, version)
	current, err := f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	require.Equal(t, before.LocalUserPassword, current.LocalUserPassword)
	require.Equal(t, before.LocalUserSSHKeyPassphrase, current.LocalUserSSHKeyPassphrase)
	cfg.LocalUserPassword = "new-owned-password"
	replace := inventory.TaskEditSecrets{PasswordAction: "replace", PassphraseAction: "keep"}
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 2, cfg, replace, "")
	require.ErrorIs(t, err, inventory.ErrTaskSecretStorage)
	version, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 2, cfg, replace, key)
	require.NoError(t, err)
	require.Equal(t, 3, version)
	current, err = f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	plain, err := utils.DecryptSensitiveField(current.LocalUserPassword, key)
	require.NoError(t, err)
	require.Equal(t, "new-owned-password", plain)
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 3, cfg, keep, key)
	require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	cfg.LocalUserPassword = ""
	clear := inventory.TaskEditSecrets{PasswordAction: "clear", PassphraseAction: "clear"}
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 3, cfg, clear, "")
	require.NoError(t, err)
	current, err = f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	require.Empty(t, current.LocalUserPassword)
	require.Empty(t, current.LocalUserSSHKeyPassphrase)
}

func TestTaskEditingConfigurationCorrectionsAndBounds(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned task edit bounds")
	keep := inventory.TaskEditSecrets{PasswordAction: "keep", PassphraseAction: "keep"}
	cfg := ownedTaskConfiguration()
	id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, "")
	require.NoError(t, err)
	changed := cfg
	changed.TaskType = task.TypeUnixScript.String()
	changed.AgentsType = task.AgentTypeLinux.String()
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, changed, keep, "")
	require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	require.NoError(t, f.client.Task.UpdateOneID(int(id)).SetScript(strings.Repeat("x", (128<<10)+1)).Exec(ctx))
	review, err := inventory.ReviewTaskEdit(ctx, f.db, f.permissions, "admin", f.scope, id)
	require.ErrorIs(t, err, inventory.ErrTaskEditConflict)
	require.Nil(t, review)
	require.NoError(t, f.client.Task.UpdateOneID(int(id)).SetScript("owned").SetVersion(0).Exec(ctx))
	version, err := inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 0, cfg, keep, "")
	require.NoError(t, err)
	require.Equal(t, 1, version, "legacy zero versions remain editable")
	cfg.TaskType = task.TypeFlatpakInstall.String()
	cfg.AgentsType = task.AgentTypeLinux.String()
	cfg.PackageID = "owned.package"
	cfg.PackageBranch = "old-branch"
	id, err = inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, "")
	require.NoError(t, err)
	cfg.PackageBranch = "new-branch"
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, keep, "")
	require.NoError(t, err)
	current, err := f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	require.Equal(t, "new-branch", current.PackageBranch)
	cfg = ownedTaskConfiguration()
	cfg.TaskType = task.TypeMsiInstall.String()
	cfg.MsiFileHash = "owned-previous-hash"
	id, err = inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, "")
	require.NoError(t, err)
	cfg.MsiFileHash = ""
	cfg.MsiHashAlgorithm = ""
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, keep, "")
	require.NoError(t, err)
	var cleared bool
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT msi_file_hash IS NULL AND msi_file_hash_alg IS NULL FROM tasks WHERE id=$1`, id).Scan(&cleared))
	require.True(t, cleared)
	cfg = ownedTaskConfiguration()
	cfg.TaskType = task.TypeNetbirdRegister.String()
	cfg.AgentsType = task.AgentTypeAny.String()
	cfg.NetbirdGroups = `"owned-ID"`
	id, err = inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, "")
	require.NoError(t, err)
	require.NoError(t, f.client.Task.UpdateOneID(int(id)).SetTenant(f.scope.TenantID+1).Exec(ctx))
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, keep, "")
	require.ErrorIs(t, err, inventory.ErrProfileCloneProviderScope)
	_, err = inventory.ReviewTaskEdit(ctx, f.db, f.permissions, "admin", f.scope, id)
	require.ErrorIs(t, err, inventory.ErrProfileCloneProviderScope)
}
