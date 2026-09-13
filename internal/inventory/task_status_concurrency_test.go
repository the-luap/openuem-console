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

func TestTaskStatusRechecksOwnershipAfterWaitingForProfile(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	other := ownedTagProfile(t, f, f.scope, "New task owner in the same scope")
	lock, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer lock.Rollback()
	_, err = lock.ExecContext(ctx, "SELECT id FROM profiles WHERE id=$1 FOR UPDATE", g.profile)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := inventory.SetTaskEnabled(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), false)
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		return f.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT p.id FROM profiles p WHERE p.id=$1%')").Scan(&waiting) == nil && waiting
	}, 2*time.Second, 10*time.Millisecond)
	_, err = f.db.ExecContext(ctx, "UPDATE tasks SET profile_tasks=$1 WHERE id=$2", other.ID, g.task)
	require.NoError(t, err)
	require.NoError(t, lock.Commit())
	select {
	case err := <-done:
		require.ErrorIs(t, err, inventory.ErrNotFound)
	case <-time.After(2 * time.Second):
		t.Fatal("task status did not recheck its changed parent")
	}
	current, err := f.client.Task.Get(ctx, g.task)
	require.NoError(t, err)
	require.False(t, current.Disabled)
	id, err := inventory.SetTaskEnabled(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), false)
	require.NoError(t, err)
	require.Equal(t, int64(other.ID), id)
}

func TestTaskStatusHoldsTaskParentAndAuthorityUntilAuditCommit(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	g := ownedDeletionGraph(t, f, f.scope)
	other := ownedTagProfile(t, f, f.scope, "Owned other task parent")
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810069)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810069)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, "CREATE SEQUENCE owned_task_status_entered; CREATE FUNCTION hold_owned_task_status() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.disable' THEN PERFORM nextval('owned_task_status_entered'); PERFORM pg_advisory_xact_lock(673810069); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_task_status AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_task_status()")
	require.NoError(t, err)
	type outcome struct {
		id  int64
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		id, err := inventory.SetTaskEnabled(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.task), false)
		done <- outcome{id, err}
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_task_status_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	current, err := f.client.Task.Get(ctx, g.task)
	require.NoError(t, err)
	require.False(t, current.Disabled, "uncommitted task status was published before audit")
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tasks SET profile_tasks=$1 WHERE id=$2", other.ID, g.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM tasks WHERE id=$1", g.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM profiles WHERE id=$1", g.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM site_profiles WHERE profile_id=$1", g.profile)
			return err
		},
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}})
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE sites SET tenant_sites=NULL WHERE id=$1", f.scope.SiteID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM sites WHERE id=$1", f.scope.SiteID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM tenants WHERE id=$1", organization.TenantID)
			return err
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
		t.Fatal("task status did not leave its audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	id, err := inventory.SetTaskEnabled(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.task), true)
	require.Zero(t, id)
	require.ErrorIs(t, err, access.ErrDenied)
}
