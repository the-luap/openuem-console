package inventory_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileStatusRequiresExactAudienceAndPreservesDefinition(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	tag, err := f.client.Tag.Create().SetTag("Retained status tag").SetColor("blue").SetTenantID(organization.TenantID).Save(ctx)
	require.NoError(t, err)
	scopes := []access.Scope{{}, organization, f.scope}
	for i, scope := range scopes {
		profile := ownedTagProfile(t, f, scope, fmt.Sprintf("Status scope %d", i))
		require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).AddTagIDs(tag.ID).Exec(ctx))
		task, err := f.client.Task.Create().SetName("Retained profile task").SetType("powershell_script").SetProfileID(profile.ID).Save(ctx)
		require.NoError(t, err)
		set := func(actor string, requested access.Scope, enabled bool) error {
			return inventory.SetProfileEnabled(ctx, f.db, f.permissions, actor, requested, int64(profile.ID), enabled)
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			require.ErrorIs(t, set(actor, scope, false), access.ErrDenied)
		}
		for _, requested := range scopes {
			if requested != scope {
				require.ErrorIs(t, set("admin", requested, false), inventory.ErrNotFound)
			}
		}
		for _, enabled := range []bool{false, false, true} {
			require.NoError(t, set("admin", scope, enabled))
			current, err := f.client.Profile.Query().Where(entprofile.ID(profile.ID)).WithTags().WithTasks().Only(ctx)
			require.NoError(t, err)
			require.Equal(t, !enabled, current.Disabled)
			require.Equal(t, profile.Name, current.Name)
			require.True(t, current.ApplyToAll)
			require.Equal(t, profile.Type, current.Type)
			require.Len(t, current.Edges.Tags, 1)
			require.Equal(t, tag.ID, current.Edges.Tags[0].ID)
			require.Len(t, current.Edges.Tasks, 1)
			require.Equal(t, task.ID, current.Edges.Tasks[0].ID)
		}
		var events int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND resource_id=$3 AND action IN ('inventory.profiles.enable','inventory.profiles.disable')`, scope.TenantID, scope.SiteID, fmt.Sprint(profile.ID)).Scan(&events))
		require.Equal(t, 3, events)
	}
	require.ErrorIs(t, inventory.SetProfileEnabled(ctx, f.db, f.permissions, "admin", f.scope, 0, true), inventory.ErrProfileInvalid)
	require.ErrorIs(t, inventory.SetProfileEnabled(ctx, f.db, f.permissions, "admin", access.Scope{SiteID: f.scope.SiteID}, 1, true), access.ErrDenied)
}

func TestProfileStatusWaitsForChangedAudienceAndRollsBackFailedAudit(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	profile := ownedTagProfile(t, f, f.scope, "Status rollback")
	set := func(ctx context.Context, enabled bool) error {
		return inventory.SetProfileEnabled(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), enabled)
	}
	_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_profile_status_audit_failure CHECK(action NOT IN ('inventory.profiles.enable','inventory.profiles.disable')) NOT VALID`)
	require.NoError(t, err)
	require.Error(t, set(ctx, false))
	current, err := f.client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.False(t, current.Disabled)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_profile_status_audit_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, set(canceled, false))
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, profile.ID)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	require.Error(t, set(bounded, false))
	cancel()
	require.NoError(t, tx.Commit())
	require.ErrorIs(t, set(ctx, false), inventory.ErrNotFound)
	require.ErrorIs(t, inventory.SetProfileEnabled(ctx, f.db, f.permissions, "admin", scope, int64(profile.ID), false), inventory.ErrNotFound)
	current, err = f.client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.False(t, current.Disabled)
}

func TestProfileStatusHoldsAuthorityUntilFinalAudit(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	profile := ownedTagProfile(t, f, f.scope, "Audited profile status")
	tag, err := f.client.Tag.Create().SetTag("Competing profile tag").SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(673810063)`)
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(673810063)`)
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_profile_status_entered; CREATE FUNCTION hold_owned_profile_status() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profiles.disable' THEN PERFORM nextval('owned_profile_status_entered'); PERFORM pg_advisory_xact_lock(673810063); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_profile_status AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_profile_status()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- inventory.SetProfileEnabled(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(profile.ID), false)
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, `SELECT is_called FROM owned_profile_status_entered`).Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}})
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE profiles SET disabled=false WHERE id=$1`, profile.ID)
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
		t.Fatal("profile status did not leave its audit gate")
	}
	current, err := f.client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.True(t, current.Disabled)
	require.True(t, current.ApplyToAll)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}))
	require.ErrorIs(t, inventory.SetProfileEnabled(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(profile.ID), true), access.ErrDenied)
}
