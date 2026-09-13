package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats/tasksecrets"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

const taskMigrationKey = "0123456789abcdef0123456789abcdef"

func TestTaskSecretMigrationPreservesMetadataNullsAndAudit(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned migration parent")
	entry, err := f.client.Task.Create().SetName("Owned secret task").SetProfileID(p.ID).SetType(task.TypeAddUnixLocalUser).SetAgentType(task.AgentTypeLinux).SetLocalUserUsername("owned").SetLocalUserPassword("aabb").SetLocalUserSSHKeyPassphrase("owned-private-ssh").SetOrder(9).SetVersion(7).SetDisabled(true).Save(ctx)
	require.NoError(t, err)
	empty, err := f.client.Task.Create().SetName("Owned null secret task").SetProfileID(p.ID).SetType(task.TypeUnixScript).SetAgentType(task.AgentTypeLinux).Save(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "UPDATE tasks SET local_user_password=NULL,local_user_ssh_key_passphrase='' WHERE id=$1", empty.ID)
	require.NoError(t, err)
	var before, after string
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT (to_jsonb(t)-ARRAY['local_user_password','local_user_ssh_key_passphrase'])::text FROM tasks t WHERE id=$1", entry.ID).Scan(&before))
	require.NoError(t, inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey))
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT (to_jsonb(t)-ARRAY['local_user_password','local_user_ssh_key_passphrase'])::text FROM tasks t WHERE id=$1", entry.ID).Scan(&after))
	require.Equal(t, before, after)
	current, err := f.client.Task.Get(ctx, entry.ID)
	require.NoError(t, err)
	require.NotEqual(t, entry.LocalUserPassword, current.LocalUserPassword)
	require.NotEqual(t, entry.LocalUserSSHKeyPassphrase, current.LocalUserSSHKeyPassphrase)
	password, err := tasksecrets.OpenPassword(current.LocalUserPassword, taskMigrationKey)
	require.NoError(t, err)
	require.True(t, password == "aabb")
	ssh, err := tasksecrets.OpenSSH(current.LocalUserSSHKeyPassphrase, taskMigrationKey)
	require.NoError(t, err)
	require.True(t, ssh == "owned-private-ssh")
	var nulls bool
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT local_user_password IS NULL AND local_user_ssh_key_passphrase='' FROM tasks WHERE id=$1", empty.ID).Scan(&nulls))
	require.True(t, nulls)
	require.NoError(t, inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey))
	repeated, err := f.client.Task.Get(ctx, entry.ID)
	require.NoError(t, err)
	require.Equal(t, current.LocalUserPassword, repeated.LocalUserPassword)
	require.Equal(t, current.LocalUserSSHKeyPassphrase, repeated.LocalUserSSHKeyPassphrase)
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	filter := audit.Filter{Scope: access.Scope{}, Source: "inventory", Action: "inventory.tasks.secrets_migrate", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
	page, err := audits.List(ctx, "admin", filter, "")
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	require.Equal(t, "system:task-secret-migration", page.Events[0].Actor)
	data, err := audits.ExportJSON(ctx, "admin", filter)
	require.NoError(t, err)
	for _, private := range []string{password, ssh, current.LocalUserPassword, current.LocalUserSSHKeyPassphrase, taskMigrationKey} {
		require.NotContains(t, string(data), private)
	}
	filter.Scope = f.scope
	page, err = audits.List(ctx, "admin", filter, "")
	require.NoError(t, err)
	require.Empty(t, page.Events)
}

func TestTaskSecretMigrationRollbackAndRestart(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned resumable migration")
	ids := []int{}
	for i := 0; i < 130; i++ {
		value := "owned-legacy-ssh"
		if i == 129 {
			value = tasksecrets.Prefix + "ssh:v9:unavailable"
		}
		entry, err := f.client.Task.Create().SetName("Owned batch task").SetProfileID(p.ID).SetType(task.TypeAddUnixLocalUser).SetAgentType(task.AgentTypeLinux).SetLocalUserSSHKeyPassphrase(value).Save(ctx)
		require.NoError(t, err)
		ids = append(ids, entry.ID)
	}
	failure := inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey)
	require.ErrorIs(t, failure, inventory.ErrTaskSecretMigration)
	require.Contains(t, failure.Error(), fmt.Sprint(ids[129]))
	var committed int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.secrets_migrate'").Scan(&committed))
	require.Equal(t, 128, committed)
	current, err := f.client.Task.Get(ctx, ids[128])
	require.NoError(t, err)
	require.Equal(t, "owned-legacy-ssh", current.LocalUserSSHKeyPassphrase, "failing batch must roll back earlier rows too")
	require.NoError(t, f.client.Task.UpdateOneID(ids[129]).SetLocalUserSSHKeyPassphrase("owned-repaired-ssh").Exec(ctx))
	require.NoError(t, inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey))
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.secrets_migrate'").Scan(&committed))
	require.Equal(t, 130, committed)
	require.ErrorIs(t, inventory.MigrateTaskSecrets(ctx, f.db, strings.Repeat("k", 32)), inventory.ErrTaskSecretMigration)
	require.NoError(t, inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey))
}

func TestTaskSecretMigrationAuditFailureMissingKeyAndBounds(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned atomic migration")
	entry, err := f.client.Task.Create().SetName("Owned atomic task").SetProfileID(p.ID).SetType(task.TypeAddUnixLocalUser).SetAgentType(task.AgentTypeLinux).SetLocalUserPassword("aabb").SetLocalUserSSHKeyPassphrase("owned-ssh").Save(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, inventory.MigrateTaskSecrets(ctx, f.db, ""), inventory.ErrTaskSecretMigration)
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_secret_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.secrets_migrate' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_secret_audit BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_secret_audit()`)
	require.NoError(t, err)
	require.ErrorIs(t, inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey), inventory.ErrTaskSecretMigration)
	current, err := f.client.Task.Get(ctx, entry.ID)
	require.NoError(t, err)
	require.Equal(t, entry.LocalUserPassword, current.LocalUserPassword)
	require.Equal(t, entry.LocalUserSSHKeyPassphrase, current.LocalUserSSHKeyPassphrase)
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_secret_audit ON uem_inventory_audit")
	require.NoError(t, err)
	for _, invalid := range []string{strings.Repeat("x", tasksecrets.MaxSSHStoredSize+1), tasksecrets.Prefix + "ssh:v1:broken"} {
		require.NoError(t, f.client.Task.UpdateOneID(entry.ID).SetLocalUserSSHKeyPassphrase(invalid).Exec(ctx))
		require.ErrorIs(t, inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey), inventory.ErrTaskSecretMigration)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, inventory.MigrateTaskSecrets(cancelled, f.db, taskMigrationKey), inventory.ErrTaskSecretMigration)
	require.NoError(t, f.client.Task.UpdateOneID(entry.ID).SetLocalUserSSHKeyPassphrase("owned-fixed").Exec(ctx))
	require.NoError(t, inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey))
}

func TestTaskSSHCreationEditingCloningAndExecution(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned SSH parent")
	cfg := ownedTaskConfiguration()
	cfg.TaskType, cfg.AgentsType = task.TypeAddUnixLocalUser.String(), task.AgentTypeLinux.String()
	cfg.LocalUserUsername, cfg.LocalUserSSHKeyPassphrase = "owned-user", "owned-private-ssh"
	_, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, "")
	require.ErrorIs(t, err, inventory.ErrTaskSecretStorage)
	id, err := inventory.CreateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), cfg, taskMigrationKey)
	require.NoError(t, err)
	current, err := f.client.Task.Get(ctx, int(id))
	require.NoError(t, err)
	require.NotEqual(t, cfg.LocalUserSSHKeyPassphrase, current.LocalUserSSHKeyPassphrase)
	cfg.LocalUserSSHKeyPassphrase = tasksecrets.Prefix + "literal-new-value"
	choices := inventory.TaskEditSecrets{PasswordAction: "keep", PassphraseAction: "replace"}
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, choices, "")
	require.ErrorIs(t, err, inventory.ErrTaskSecretStorage)
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, id, int64(p.ID), 1, cfg, choices, taskMigrationKey)
	require.NoError(t, err)
	target := ownedTagProfile(t, f, f.scope, "Owned SSH clone target")
	clone, err := inventory.CloneLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, f.scope, int64(p.ID), id, int64(target.ID), "Owned SSH task copy")
	require.NoError(t, err)
	profileCopy, err := inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "admin", f.scope, f.scope, int64(p.ID), "Owned SSH profile copy")
	require.NoError(t, err)
	profileTask, err := f.client.Task.Query().Where(task.HasProfileWith(profile.ID(int(profileCopy)))).Only(ctx)
	require.NoError(t, err)
	for _, taskID := range []int{int(id), int(clone), profileTask.ID} {
		stored, err := f.client.Task.Query().Where(task.ID(taskID)).WithProfile().Only(ctx)
		require.NoError(t, err)
		plain, err := tasksecrets.OpenSSH(stored.LocalUserSSHKeyPassphrase, taskMigrationKey)
		require.NoError(t, err)
		require.True(t, plain == cfg.LocalUserSSHKeyPassphrase)
		payload, err := taskexecution.Build(stored, taskMigrationKey)
		require.NoError(t, err)
		require.Contains(t, string(payload.Data), plain)
		require.NotContains(t, string(payload.Data), stored.LocalUserSSHKeyPassphrase)
	}
}

func TestTaskSSHMaximumStorageDispatchAndInvalidSecret(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetOs("linux").Exec(ctx))
	p := ownedTagProfile(t, f, f.scope, "Owned bounded SSH dispatch")
	plain := strings.Repeat("x", tasksecrets.MaxPlainSize)
	stored, err := tasksecrets.SealSSH(plain, taskMigrationKey)
	require.NoError(t, err)
	entry, err := f.client.Task.Create().SetName("Owned bounded SSH account").SetProfileID(p.ID).SetType(task.TypeAddUnixLocalUser).SetAgentType(task.AgentTypeLinux).SetLocalUserUsername("owned").SetLocalUserSSHKeyPassphrase(stored).SetVersion(1).Save(ctx)
	require.NoError(t, err)
	sent := 0
	store, err := inventory.NewManualExecutionStore(f.db, f.permissions, false, taskMigrationKey, func(_ context.Context, _ string, _ string, payload *taskexecution.Payload) error {
		sent++
		require.Contains(t, string(payload.Data), plain)
		require.NotContains(t, string(payload.Data), stored)
		return nil
	})
	require.NoError(t, err)
	review, err := store.Review(ctx, "admin", f.scope, f.id, "task", int64(entry.ID))
	require.NoError(t, err)
	_, err = store.Request(ctx, "admin", f.scope, f.id, uuid.NewString(), "task", int64(entry.ID), review.Source.Revision)
	require.NoError(t, err)
	worked, err := store.DispatchOne(ctx)
	require.NoError(t, err)
	require.True(t, worked)
	require.Equal(t, 1, sent)
	// Tampered encrypted data must fail before any second publisher call.
	require.NoError(t, f.client.Task.UpdateOneID(entry.ID).SetLocalUserSSHKeyPassphrase(tasksecrets.Prefix+"ssh:v1:broken").Exec(ctx))
	review, err = store.Review(ctx, "admin", f.scope, f.id, "task", int64(entry.ID))
	if err == nil {
		_, err = store.Request(ctx, "admin", f.scope, f.id, uuid.NewString(), "task", int64(entry.ID), review.Source.Revision)
		require.Error(t, err)
	}
	require.Equal(t, 1, sent)
}

func TestTaskSecretConcurrentMigrationsDoNotReencryptOrDuplicateAudit(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Owned concurrent migration")
	for i := 0; i < 8; i++ {
		_, err := f.client.Task.Create().SetName("Owned concurrent secret").SetProfileID(p.ID).SetType(task.TypeAddUnixLocalUser).SetAgentType(task.AgentTypeLinux).SetLocalUserSSHKeyPassphrase("owned-concurrent-ssh").Save(ctx)
		require.NoError(t, err)
	}
	start := make(chan struct{})
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; done <- inventory.MigrateTaskSecrets(ctx, f.db, taskMigrationKey) }()
	}
	close(start)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.secrets_migrate'").Scan(&count))
	require.Equal(t, 8, count)
}
