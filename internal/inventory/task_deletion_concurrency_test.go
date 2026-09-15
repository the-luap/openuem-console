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

func TestTaskDeletionHoldsSiblingsParentAndAuthorityUntilAuditCommit(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	g := ownedDeletionGraph(t, f, f.scope)
	sibling, err := f.client.Task.Create().SetName("Owned sibling order").SetType("unix_script").SetOrder(9).SetProfileID(g.profile).Save(ctx)
	require.NoError(t, err)
	other := ownedTagProfile(t, f, f.scope, "Owned other task parent")
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810071)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810071)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, "CREATE SEQUENCE owned_task_deletion_entered; CREATE FUNCTION hold_owned_task_deletion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.delete' THEN PERFORM nextval('owned_task_deletion_entered'); PERFORM pg_advisory_xact_lock(673810071); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_task_deletion AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_task_deletion()")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- inventory.DeleteLegacyTask(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.profile), int64(g.task))
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_task_deletion_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	current, err := f.client.Task.Get(ctx, g.task)
	require.NoError(t, err)
	require.Zero(t, current.Order)
	assertDeletionGraph(t, f, g, true)
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tasks SET name='Concurrent sibling edit' WHERE id=$1", sibling.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO tasks(name,type,disabled,profile_tasks) VALUES('New sibling','unix_script',false,$1)", g.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task))
			return err
		},
		func(ctx context.Context) error {
			_, err := inventory.ReorderLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(sibling.ID), 2, 1)
			return err
		},
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
		require.NoError(t, result)
	case <-time.After(2 * time.Second):
		t.Fatal("task deletion did not leave its audit gate")
	}
	_, err = f.client.Task.Get(ctx, g.task)
	require.Error(t, err)
	current, err = f.client.Task.Get(ctx, sibling.ID)
	require.NoError(t, err)
	require.Equal(t, 1, current.Order)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	err = inventory.DeleteLegacyTask(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.profile), int64(sibling.ID))
	require.ErrorIs(t, err, access.ErrDenied)
}
