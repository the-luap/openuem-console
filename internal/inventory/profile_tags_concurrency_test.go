package inventory_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileTagsPreserveConcurrentMembershipsAndRepairUnscopedTags(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	profile := ownedTagProfile(t, f, scope, "Concurrent profile tags")
	var ids []int64
	for i := 0; i < 2; i++ {
		tag, err := f.client.Tag.Create().SetTag(fmt.Sprintf("Concurrent profile tag %d", i)).SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
		require.NoError(t, err)
		ids = append(ids, int64(tag.ID))
	}
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Go(func() {
			results <- inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", scope, int64(profile.ID), ids[i%2], true)
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM profile_tags WHERE profile_id=$1`, profile.ID).Scan(&count))
	require.Equal(t, 2, count)
	require.NoError(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", scope, int64(profile.ID), ids[0], false))
	require.NoError(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", scope, int64(profile.ID), ids[0], false))
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM profile_tags WHERE profile_id=$1`, profile.ID).Scan(&count))
	require.Equal(t, 1, count)
	unscoped, err := f.client.Tag.Create().SetTag("Legacy unscoped profile tag").SetColor("red").Save(ctx)
	require.NoError(t, err)
	for i, requested := range []access.Scope{scope, {}} {
		p := ownedTagProfile(t, f, requested, fmt.Sprintf("Unscoped tag repair %d", i))
		require.ErrorIs(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", requested, int64(p.ID), int64(unscoped.ID), true), inventory.ErrNotFound)
		require.ErrorIs(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", requested, int64(p.ID), int64(unscoped.ID), false), inventory.ErrNotFound)
		require.NoError(t, f.client.Profile.UpdateOneID(p.ID).AddTagIDs(unscoped.ID).Exec(ctx))
		require.NoError(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", requested, int64(p.ID), int64(unscoped.ID), false))
	}
}

func TestProfileTagsWaitForCurrentAudienceAndDefinition(t *testing.T) {
	for _, source := range []string{"tag", "profile", "organization edge", "site edge", "site parent"} {
		t.Run(source, func(t *testing.T) {
			f, scope := tagFixture(t)
			ctx := t.Context()
			profile := ownedTagProfile(t, f, f.scope, "Changing audience")
			tag, err := f.client.Tag.Create().SetTag("Changing tag").SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
			require.NoError(t, err)
			tx, err := f.db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			switch source {
			case "tag":
				_, err = tx.ExecContext(ctx, `UPDATE tags SET tenant_tags=NULL WHERE id=$1`, tag.ID)
			case "profile":
				_, err = tx.ExecContext(ctx, `DELETE FROM profiles WHERE id=$1`, profile.ID)
			case "organization edge":
				_, err = tx.ExecContext(ctx, `DELETE FROM tenant_profiles WHERE profile_id=$1`, profile.ID)
			case "site edge":
				_, err = tx.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, profile.ID)
			case "site parent":
				_, err = tx.ExecContext(ctx, `UPDATE sites SET tenant_sites=NULL WHERE id=$1`, f.scope.SiteID)
			}
			require.NoError(t, err)
			bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
			err = inventory.ChangeProfileTag(bounded, f.db, f.permissions, "admin", f.scope, int64(profile.ID), int64(tag.ID), true)
			cancel()
			require.Error(t, err)
			require.NoError(t, tx.Commit())
			require.ErrorIs(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), int64(tag.ID), true), inventory.ErrNotFound)
		})
	}
}

func TestProfileTagsHoldAuthorityAndAudienceThroughFinalAudit(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	profile := ownedTagProfile(t, f, f.scope, "Final profile audience")
	tag, err := f.client.Tag.Create().SetTag("Final profile tag").SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(673810062)`)
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(673810062)`)
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_profile_tag_entered; CREATE FUNCTION hold_owned_profile_tag() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profile_tags.assign' THEN PERFORM nextval('owned_profile_tag_entered'); PERFORM pg_advisory_xact_lock(673810062); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_profile_tag AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_profile_tag()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- inventory.ChangeProfileTag(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(profile.ID), int64(tag.ID), true)
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, `SELECT is_called FROM owned_profile_tag_entered`).Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}})
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE tags SET tenant_tags=NULL WHERE id=$1`, tag.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE profiles SET apply_to_all=true WHERE id=$1`, profile.ID)
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
		t.Fatal("profile assignment did not leave its audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}))
	require.ErrorIs(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(profile.ID), int64(tag.ID), false), access.ErrDenied)
}
