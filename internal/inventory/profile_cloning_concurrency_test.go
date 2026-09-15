package inventory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileCloningWaitsForSourceEditsAndRejectsChangedAudience(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, organization)
	clone := func(ctx context.Context) (int64, error) {
		return inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "admin", organization, f.scope, int64(g.profile), "Current source clone")
	}
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "UPDATE tasks SET name='Current committed task' WHERE id=$1", g.task)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	id, err := clone(bounded)
	cancel()
	require.Zero(t, id)
	require.Error(t, err)
	require.NoError(t, tx.Commit())
	id, err = clone(ctx)
	require.NoError(t, err)
	var name string
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT name FROM tasks WHERE profile_tasks=$1", id).Scan(&name))
	require.Equal(t, "Current committed task", name)
	tx, err = f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "DELETE FROM tenant_profiles WHERE profile_id=$1", g.profile)
	require.NoError(t, err)
	bounded, cancel = context.WithTimeout(ctx, 120*time.Millisecond)
	id, err = clone(bounded)
	cancel()
	require.Zero(t, id)
	require.Error(t, err)
	require.NoError(t, tx.Commit())
	id, err = clone(ctx)
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestProfileCloningWaitsForChangedDestinationParent(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, access.Scope{}, "Global clone source")
	other, err := f.client.Tenant.Create().SetDescription("Moved clone destination").Save(ctx)
	require.NoError(t, err)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "UPDATE sites SET tenant_sites=$1 WHERE id=$2", other.ID, f.scope.SiteID)
	require.NoError(t, err)
	clone := func(ctx context.Context) (int64, error) {
		return inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "admin", access.Scope{}, f.scope, int64(p.ID), "Moved destination clone")
	}
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	id, err := clone(bounded)
	cancel()
	require.Zero(t, id)
	require.Error(t, err)
	require.NoError(t, tx.Commit())
	id, err = clone(ctx)
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	sites, err := inventory.ProfileCloneSites(ctx, f.db, f.permissions, "admin", organization)
	require.NoError(t, err)
	for _, site := range sites {
		require.NotEqual(t, f.scope.SiteID, site.ID)
	}
	_, err = inventory.ProfileCloneSites(ctx, f.db, f.permissions, "tag-admin", organization)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestProfileCloningHoldsSourceTasksDestinationAndAuthorityUntilCommit(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	source := ownedDeletionGraph(t, f, organization)
	destination := f.scope
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810068)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810068)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, "CREATE SEQUENCE owned_profile_cloning_entered; CREATE FUNCTION hold_owned_profile_cloning() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profiles.clone' THEN PERFORM nextval('owned_profile_cloning_entered'); PERFORM pg_advisory_xact_lock(673810068); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_profile_cloning AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_profile_cloning()")
	require.NoError(t, err)
	type outcome struct {
		id  int64
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		id, err := inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "tag-admin", organization, destination, int64(source.profile), "Held profile clone")
		done <- outcome{id, err}
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_profile_cloning_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	count, err := f.client.Profile.Query().Where(entprofile.NameEQ("Held profile clone")).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count, "uncommitted profile was published before audit")
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tasks SET name='Concurrent source edit' WHERE id=$1", source.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM tasks WHERE id=$1", source.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tasks SET profile_tasks=NULL WHERE id=$1", source.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO tasks(name,type,disabled,profile_tasks) VALUES('Concurrent new source task','unix_script',false,$1)", source.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM tenant_profiles WHERE profile_id=$1", source.profile)
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
		t.Fatal("profile clone did not leave its audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	id, err := inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "tag-admin", organization, destination, int64(source.profile), "Revoked clone")
	require.Zero(t, id)
	require.ErrorIs(t, err, access.ErrDenied)
}
