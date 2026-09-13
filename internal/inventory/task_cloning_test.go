package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestTaskCloningPreservesConfigurationAcrossExactScopes(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	scopes := []access.Scope{{}, organization, f.scope}
	for _, source := range scopes {
		g := ownedDeletionGraph(t, f, source)
		require.NoError(t, f.client.Task.UpdateOneID(g.task).SetName("Owned source label").SetType(task.TypeAptInstall).SetAptName("owned-package").SetVersion(7).SetWhen(time.Now()).SetScript("Owned secret script").SetLocalUserPassword("Owned encrypted value").SetDisabled(true).Exec(ctx))
		_, err := f.db.ExecContext(ctx, `UPDATE tasks SET apt_deb=NULL,"order"=NULL WHERE id=$1`, g.task)
		require.NoError(t, err)
		for _, destination := range scopes {
			target := ownedTagProfile(t, f, destination, "Owned target")
			existing, err := f.client.Task.Create().SetName("Existing destination task").SetType("unix_script").SetOrder(9).SetVersion(4).SetProfileID(target.ID).Save(ctx)
			require.NoError(t, err)
			name := "Owned <copied> task\n第二行"
			id, err := inventory.CloneLegacyTask(ctx, f.db, f.permissions, "admin", source, destination, int64(g.profile), int64(g.task), int64(target.ID), name)
			require.NoError(t, err)
			require.NotEqual(t, int64(g.task), id)
			copied, err := f.client.Task.Query().Where(task.ID(int(id))).WithTags().WithReports().WithProfile().Only(ctx)
			require.NoError(t, err)
			require.Equal(t, name, copied.Name)
			require.Equal(t, 2, copied.Order)
			require.Equal(t, 1, copied.Version)
			require.True(t, copied.When.IsZero())
			require.Equal(t, target.ID, copied.Edges.Profile.ID)
			require.Empty(t, copied.Edges.Tags)
			require.Empty(t, copied.Edges.Reports)
			var equal bool
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (to_jsonb(a)-ARRAY['id','name','version','when','order','profile_tasks'])=(to_jsonb(b)-ARRAY['id','name','version','when','order','profile_tasks']) FROM tasks a,tasks b WHERE a.id=$1 AND b.id=$2`, g.task, id).Scan(&equal))
			require.True(t, equal, "cloned task configuration differs")
			current, err := f.client.Task.Get(ctx, existing.ID)
			require.NoError(t, err)
			require.Equal(t, 1, current.Order)
			require.Equal(t, 4, current.Version)
			assertDeletionGraph(t, f, g, true)
			audits, err := audit.NewStore(f.db, f.permissions)
			require.NoError(t, err)
			resource := fmt.Sprintf("%d/from/%d/%d/%d/%d/to/%d/%d/%d/position/2", id, g.task, g.profile, source.TenantID, source.SiteID, target.ID, destination.TenantID, destination.SiteID)
			for _, scope := range []access.Scope{source, destination} {
				filter := audit.Filter{Scope: scope, Source: "inventory", Action: "inventory.tasks.clone", Resource: resource, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
				page, err := audits.List(ctx, "admin", filter, "")
				require.NoError(t, err)
				found := 0
				for _, event := range page.Events {
					if event.TenantID == scope.TenantID && event.SiteID == scope.SiteID {
						found++
					}
				}
				require.Equal(t, 1, found)
				data, err := audits.ExportJSON(ctx, "admin", filter)
				require.NoError(t, err)
				require.Contains(t, string(data), resource)
				require.NotContains(t, string(data), "Owned secret")
			}
		}
		// Cloning into the source itself appends after deterministic normalization.
		id, err := inventory.CloneLegacyTask(ctx, f.db, f.permissions, "admin", source, source, int64(g.profile), int64(g.task), int64(g.profile), "Same profile copy")
		require.NoError(t, err)
		copied, err := f.client.Task.Get(ctx, int(id))
		require.NoError(t, err)
		require.Equal(t, 2, copied.Order)
	}
}

func TestTaskCloningRechecksScopeParentAuthorityAndProvider(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	target := ownedTagProfile(t, f, organization, "Owned target")
	clone := func(actor string, source, destination access.Scope, parent, targetID int64, name string) (int64, error) {
		return inventory.CloneLegacyTask(ctx, f.db, f.permissions, actor, source, destination, parent, int64(g.task), targetID, name)
	}
	for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "viewer", "missing"} {
		id, err := clone(actor, f.scope, organization, int64(g.profile), int64(target.ID), "Denied")
		require.Zero(t, id)
		require.ErrorIs(t, err, access.ErrDenied)
		_, err = inventory.ReviewTaskClone(ctx, f.db, f.permissions, actor, f.scope, int64(g.task), 0, "")
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, source := range []access.Scope{{}, organization} {
		id, err := clone("admin", source, organization, int64(g.profile), int64(target.ID), "Wrong source")
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrNotFound)
	}
	for _, destination := range []access.Scope{{}, f.scope} {
		id, err := clone("admin", f.scope, destination, int64(g.profile), int64(target.ID), "Wrong destination")
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrNotFound)
	}
	for _, name := range []string{"", " ", strings.Repeat("x", 2049), "bad\x00name"} {
		id, err := clone("admin", f.scope, organization, int64(g.profile), int64(target.ID), name)
		require.Zero(t, id)
		require.Error(t, err)
	}
	require.NoError(t, f.client.Task.UpdateOneID(g.task).SetType(task.TypeNetbirdRegister).SetTenant(organization.TenantID).Exec(ctx))
	global := ownedTagProfile(t, f, access.Scope{}, "Owned global target")
	id, err := clone("admin", f.scope, access.Scope{}, int64(g.profile), int64(global.ID), "Invalid provider copy")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrProfileCloneProviderScope)
	id, err = clone("admin", f.scope, organization, int64(g.profile), int64(target.ID), "Owned provider copy")
	require.NoError(t, err)
	require.Positive(t, id)
	moved := ownedTagProfile(t, f, f.scope, "Owned moved source")
	require.NoError(t, f.client.Task.UpdateOneID(g.task).SetProfileID(moved.ID).Exec(ctx))
	id, err = clone("admin", f.scope, organization, int64(g.profile), int64(target.ID), "Stale source")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = inventory.ReviewTaskClone(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), int64(g.profile), "")
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = f.db.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, moved.ID)
	require.NoError(t, err)
	id, err = clone("admin", f.scope, organization, int64(moved.ID), int64(target.ID), "Ambiguous source")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestTaskCloningRollbackIncludesDestinationOrderAndBothReceipts(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	target := ownedTagProfile(t, f, organization, "Owned target")
	sibling, err := f.client.Task.Create().SetName("Retained destination").SetType("unix_script").SetOrder(9).SetProfileID(target.ID).Save(ctx)
	require.NoError(t, err)
	clone := func(ctx context.Context) (int64, error) {
		return inventory.CloneLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, organization, int64(g.profile), int64(g.task), int64(target.ID), "Owned copy")
	}
	assertRetained := func() {
		assertDeletionGraph(t, f, g, true)
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM tasks WHERE profile_tasks=$1`, target.ID).Scan(&count))
		require.Equal(t, 1, count)
		current, err := f.client.Task.Get(ctx, sibling.ID)
		require.NoError(t, err)
		require.Equal(t, 9, current.Order)
	}
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_task_clone() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned task clone failure'; END $$; CREATE TRIGGER reject_owned_task_clone BEFORE INSERT ON tasks FOR EACH ROW EXECUTE FUNCTION reject_owned_task_clone()`)
	require.NoError(t, err)
	id, err := clone(ctx)
	require.Zero(t, id)
	require.Error(t, err)
	assertRetained()
	_, err = f.db.ExecContext(ctx, `DROP TRIGGER reject_owned_task_clone ON tasks; DROP FUNCTION reject_owned_task_clone()`)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_task_clone_audit_failure CHECK(action!='inventory.tasks.clone' OR site_id!=0) NOT VALID`)
	require.NoError(t, err)
	id, err = clone(ctx)
	require.Zero(t, id)
	require.Error(t, err)
	assertRetained()
	var events int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.clone'`).Scan(&events))
	require.Zero(t, events)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_task_clone_audit_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	id, err = clone(canceled)
	require.Zero(t, id)
	require.Error(t, err)
	assertRetained()
}

func TestTaskCloningReviewSearchBoundsAndAudit(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	require.NoError(t, f.client.Task.UpdateOneID(g.task).SetName(strings.Repeat("界", 2048)).SetScript("Owned hidden script").Exec(ctx))
	for i := 0; i < 53; i++ {
		ownedTagProfile(t, f, access.Scope{}, fmt.Sprintf("Owned searchable target %02d", i))
	}
	ambiguous := ownedTagProfile(t, f, f.scope, "Owned searchable ambiguous")
	_, err := f.db.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, ambiguous.ID)
	require.NoError(t, err)
	review, err := inventory.ReviewTaskClone(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), int64(g.profile), "Owned searchable")
	require.NoError(t, err)
	require.Empty(t, review.Name)
	require.True(t, review.HasMore)
	require.Len(t, review.Targets, 50)
	for _, target := range review.Targets {
		require.NotEqual(t, int64(ambiguous.ID), target.ID)
		require.Equal(t, access.Scope{}, target.Scope)
	}
	exact := review.Targets[12]
	review, err = inventory.ReviewTaskClone(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), int64(g.profile), fmt.Sprint(exact.ID))
	require.NoError(t, err)
	require.Len(t, review.Targets, 1)
	require.Equal(t, exact.ID, review.Targets[0].ID)
	require.False(t, review.HasMore)
	for _, query := range []string{strings.Repeat("a", 257), "bad\x00query", string([]byte{255})} {
		_, err := inventory.ReviewTaskClone(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), int64(g.profile), query)
		require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	}
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_task_review_failure CHECK(action!='inventory.tasks.clone_review') NOT VALID`)
	require.NoError(t, err)
	review, err = inventory.ReviewTaskClone(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), 0, "")
	require.Error(t, err)
	require.Nil(t, review)
}
