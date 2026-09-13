package inventory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestTaskCloningHoldsSourceDestinationAndAuthorityThroughBothAudits(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	source := ownedDeletionGraph(t, f, f.scope)
	target := ownedDeletionGraph(t, f, organization)
	require.NoError(t, f.client.Task.UpdateOneID(target.task).SetOrder(9).Exec(ctx))
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810072)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810072)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_task_clone_entered; CREATE FUNCTION hold_owned_task_clone() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.clone' THEN PERFORM nextval('owned_task_clone_entered'); PERFORM pg_advisory_xact_lock(673810072); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_task_clone AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_task_clone()`)
	require.NoError(t, err)
	type outcome struct {
		id  int64
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		id, err := inventory.CloneLegacyTask(ctx, f.db, f.permissions, "tag-admin", f.scope, organization, int64(source.profile), int64(source.task), int64(target.profile), "Owned concurrent copy")
		done <- outcome{id, err}
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, `SELECT is_called FROM owned_task_clone_entered`).Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	assertDeletionGraph(t, f, source, true)
	assertDeletionGraph(t, f, target, true)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM tasks WHERE profile_tasks=$1`, target.profile).Scan(&count))
	require.Equal(t, 1, count)
	current, err := f.client.Task.Get(ctx, target.task)
	require.NoError(t, err)
	require.Equal(t, 9, current.Order)
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE tasks SET script='Concurrent source edit' WHERE id=$1`, source.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE tasks SET name='Concurrent target edit' WHERE id=$1`, target.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `INSERT INTO tasks(name,type,disabled,profile_tasks) VALUES('Concurrent destination task','unix_script',false,$1)`, target.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE tasks SET profile_tasks=$1 WHERE id=$2`, target.profile, source.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `DELETE FROM profiles WHERE id=$1`, source.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `DELETE FROM profiles WHERE id=$1`, target.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `DELETE FROM tenant_profiles WHERE profile_id=$1`, target.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := inventory.ReviewTaskClone(ctx, f.db, f.permissions, "admin", f.scope, int64(source.task), int64(source.profile), "")
			return err
		},
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}})
		},
	} {
		bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		require.Error(t, mutation(bounded))
		cancel()
	}
	release()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Positive(t, result.id)
	case <-time.After(2 * time.Second):
		t.Fatal("task clone did not leave its audit gate")
	}
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM tasks WHERE profile_tasks=$1`, target.profile).Scan(&count))
	require.Equal(t, 2, count)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	id, err := inventory.CloneLegacyTask(ctx, f.db, f.permissions, "tag-admin", f.scope, organization, int64(source.profile), int64(source.task), int64(target.profile), "Revoked copy")
	require.Zero(t, id)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestTaskCloningOppositeDirectionsCommitWithoutDeadlock(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	a := ownedDeletionGraph(t, f, f.scope)
	b := ownedDeletionGraph(t, f, f.scope)
	start := make(chan struct{})
	done := make(chan error, 2)
	for _, pair := range [][2]deletionGraph{{a, b}, {b, a}} {
		go func(pair [2]deletionGraph) {
			<-start
			_, err := inventory.CloneLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, f.scope, int64(pair[0].profile), int64(pair[0].task), int64(pair[1].profile), "Opposite copy")
			done <- err
		}(pair)
	}
	close(start)
	for range 2 {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("opposite task clones did not finish")
		}
	}
	for _, g := range []deletionGraph{a, b} {
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM tasks WHERE profile_tasks=$1`, g.profile).Scan(&count))
		require.Equal(t, 2, count)
		assertDeletionGraph(t, f, g, true)
	}
}
