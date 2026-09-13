package inventory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestTaskEditingLocksVersionAndPreservesHistory(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	g := ownedDeletionGraph(t, f, f.scope)
	other := ownedTagProfile(t, f, f.scope, "Owned concurrent task target")
	when := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, f.client.Task.UpdateOneID(g.task).SetType(task.TypePowershellScript).SetAgentType(task.AgentTypeWindows).SetScript("old-owned-script").SetVersion(1).SetOrder(9).SetDisabled(true).SetWhen(when).Exec(ctx))
	cfg := ownedTaskConfiguration()
	keep := inventory.TaskEditSecrets{PasswordAction: "keep", PassphraseAction: "keep"}
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810075)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810075)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_task_edit_entered; CREATE FUNCTION hold_owned_task_edit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.update' THEN PERFORM nextval('owned_task_edit_entered'); PERFORM pg_advisory_xact_lock(673810075); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_task_edit AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_task_edit()`)
	require.NoError(t, err)
	type outcome struct {
		version int
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		version, err := inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.task), int64(g.profile), 1, cfg, keep, "")
		done <- outcome{version, err}
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_task_edit_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	current, err := f.client.Task.Get(ctx, g.task)
	require.NoError(t, err)
	require.Equal(t, 1, current.Version)
	require.Equal(t, "old-owned-script", current.Script)
	for _, change := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), int64(g.profile), 1, cfg, keep, "")
			return err
		},
		func(ctx context.Context) error {
			_, err := inventory.ReviewTaskEdit(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task))
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE tasks SET profile_tasks=$1 WHERE id=$2`, other.ID, g.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `DELETE FROM tasks WHERE id=$1`, g.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE profiles SET name='changed' WHERE id=$1`, g.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `DELETE FROM site_profiles WHERE profile_id=$1`, g.profile)
			return err
		},
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}})
		},
	} {
		bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		err := change(bounded)
		cancel()
		require.Error(t, err)
	}
	release()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Equal(t, 2, result.version)
	case <-time.After(2 * time.Second):
		t.Fatal("task edit did not leave audit gate")
	}
	results := make(chan outcome, 2)
	for _, name := range []string{"First concurrent edit", "Second concurrent edit"} {
		candidate := cfg
		candidate.Description = name
		go func() {
			version, err := inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), int64(g.profile), 2, candidate, keep, "")
			results <- outcome{version, err}
		}()
	}
	succeeded, conflicts := 0, 0
	for range 2 {
		select {
		case result := <-results:
			if result.err == nil {
				succeeded++
				require.Equal(t, 3, result.version)
			} else {
				require.True(t, errors.Is(result.err, inventory.ErrTaskEditConflict))
				conflicts++
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent task edit did not complete")
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, conflicts)
	current, err = f.client.Task.Get(ctx, g.task)
	require.NoError(t, err)
	require.Equal(t, 9, current.Order)
	require.True(t, current.Disabled)
	require.True(t, when.Equal(current.When))
	require.Equal(t, 3, current.Version)
	assertDeletionGraph(t, f, g, true)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	_, err = inventory.UpdateLegacyTask(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.task), int64(g.profile), 3, cfg, keep, "")
	require.ErrorIs(t, err, access.ErrDenied)
}
