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

func TestProfileAudienceHoldsAuthorityThroughDestinationAudit(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	profile := ownedTagProfile(t, f, f.scope, "Destination audit authority")
	tag, err := f.client.Tag.Create().SetTag("Concurrent audience tag").SetColor("blue").SetTenantID(organization.TenantID).Save(ctx)
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(673810064)`)
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(673810064)`)
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_profile_audience_entered; CREATE FUNCTION hold_owned_profile_audience() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profiles.move_global' AND NEW.tenant_id=0 THEN PERFORM nextval('owned_profile_audience_entered'); PERFORM pg_advisory_xact_lock(673810064); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_profile_audience AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_profile_audience()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(profile.ID), true)
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, `SELECT is_called FROM owned_profile_audience_entered`).Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}})
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE profiles SET name='Unreviewed concurrent edit' WHERE id=$1`, profile.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `DELETE FROM tenant_profiles WHERE profile_id=$1`, profile.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, profile.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE sites SET tenant_sites=NULL WHERE id=$1`, f.scope.SiteID)
			return err
		},
		func(ctx context.Context) error {
			return inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), int64(tag.ID), true)
		},
		func(ctx context.Context) error {
			return inventory.SetProfileEnabled(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), false)
		},
		func(ctx context.Context) error {
			return inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), false)
		},
	} {
		bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		require.Error(t, mutation(bounded))
		cancel()
	}
	release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("audience move did not leave its destination audit gate")
	}
	current, err := f.client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.Equal(t, profile.Name, current.Name)
	require.False(t, current.Disabled)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	require.ErrorIs(t, inventory.SetProfileEnabled(ctx, f.db, f.permissions, "tag-admin", access.Scope{}, int64(profile.ID), false), access.ErrDenied)
	require.ErrorIs(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), int64(tag.ID), true), inventory.ErrNotFound)
}
