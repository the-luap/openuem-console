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

func TestProfileCreationHoldsAuthorityAndSiteUntilAuditCommit(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810067)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810067)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, "CREATE SEQUENCE owned_profile_creation_entered; CREATE FUNCTION hold_owned_profile_creation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profiles.create' THEN PERFORM nextval('owned_profile_creation_entered'); PERFORM pg_advisory_xact_lock(673810067); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_profile_creation AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_profile_creation()")
	require.NoError(t, err)
	type outcome struct {
		id  int64
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		id, err := inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "tag-admin", f.scope, "Held profile creation")
		done <- outcome{id, err}
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_profile_creation_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	count, err := f.client.Profile.Query().Where(entprofile.NameEQ("Held profile creation")).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count, "uncommitted profile was published before audit")
	for _, mutation := range []func(context.Context) error{
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
		t.Fatal("profile creation did not leave its audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	id, err := inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "tag-admin", f.scope, "Revoked creation")
	require.Zero(t, id)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestProfileCreationWaitsForChangedSiteParent(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	other, err := f.client.Tenant.Create().SetDescription("Changed creation parent").Save(ctx)
	require.NoError(t, err)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "UPDATE sites SET tenant_sites=$1 WHERE id=$2", other.ID, f.scope.SiteID)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	id, err := inventory.CreateLegacyProfile(bounded, f.db, f.permissions, "admin", f.scope, "Stale creation source")
	cancel()
	require.Zero(t, id)
	require.Error(t, err)
	require.NoError(t, tx.Commit())
	id, err = inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "admin", f.scope, "Stale creation source")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	count, err := f.client.Profile.Query().Where(entprofile.NameEQ("Stale creation source")).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count)
}
