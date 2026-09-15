package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestTaskDeletionScopesHistoryAndSiblingOrder(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	unrelated := ownedDeletionGraph(t, f, f.scope)
	require.NoError(t, f.client.Task.UpdateOneID(unrelated.task).SetOrder(99).Exec(ctx))
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		g := ownedDeletionGraph(t, f, scope)
		ids := []int{}
		for _, order := range []int{0, 8, 8, 99} {
			task, err := f.client.Task.Create().SetName("Owned sibling").SetType("unix_script").SetVersion(7).SetOrder(order).SetScript("Owned confidential script").SetProfileID(g.profile).Save(ctx)
			require.NoError(t, err)
			ids = append(ids, task.ID)
		}
		_, err := f.db.ExecContext(ctx, `UPDATE tasks SET "order"=NULL WHERE id=$1`, ids[3])
		require.NoError(t, err)
		var before string
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(t)-'order' ORDER BY id)::text FROM tasks t WHERE profile_tasks=$1 AND id!=$2`, g.profile, g.task).Scan(&before))
		remove := func(actor string, requested access.Scope) error {
			return inventory.DeleteLegacyTask(ctx, f.db, f.permissions, actor, requested, int64(g.profile), int64(g.task))
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			require.ErrorIs(t, remove(actor, scope), access.ErrDenied)
			_, err := inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, actor, scope, int64(g.profile), int64(g.task))
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, organization, f.scope} {
			if wrong != scope {
				require.ErrorIs(t, remove("admin", wrong), inventory.ErrNotFound)
				_, err := inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", wrong, int64(g.profile), int64(g.task))
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		}
		review, err := inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), int64(g.task))
		require.NoError(t, err)
		require.Equal(t, int64(g.task), review.ID)
		require.Equal(t, int64(g.profile), review.ProfileID)
		require.Equal(t, "Owned deletion task", review.Name)
		assertDeletionGraph(t, f, g, true)
		require.NoError(t, remove("admin", scope))
		require.ErrorIs(t, remove("admin", scope), inventory.ErrNotFound)
		for _, row := range []struct {
			table string
			id    int
			count int
		}{{"tasks", g.task, 0}, {"task_reports", g.report, 0}, {"profiles", g.profile, 1}, {"profile_issues", g.issue, 1}, {"tags", g.tag, 1}} {
			var n int
			require.NoError(t, f.db.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE id=$1", row.table), row.id).Scan(&n))
			require.Equal(t, row.count, n, row.table)
		}
		var after string
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(t)-'order' ORDER BY id)::text FROM tasks t WHERE profile_tasks=$1`, g.profile).Scan(&after))
		require.True(t, before == after, "sibling configuration changed")
		for i, id := range ids {
			task, err := f.client.Task.Get(ctx, id)
			require.NoError(t, err)
			require.Equal(t, i+1, task.Order)
		}
		assertDeletionGraph(t, f, unrelated, true)
		other, err := f.client.Task.Get(ctx, unrelated.task)
		require.NoError(t, err)
		require.Equal(t, 99, other.Order)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		for _, action := range []string{"inventory.tasks.delete_review", "inventory.tasks.delete"} {
			filter := audit.Filter{Scope: scope, Source: "inventory", Action: action, Resource: fmt.Sprintf("%d/profile/%d", g.task, g.profile), From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
			if action == "inventory.tasks.delete" {
				filter.Resource += "/remaining/4"
			}
			page, err := audits.List(ctx, "admin", filter, "")
			require.NoError(t, err)
			require.Len(t, page.Events, 1)
			exported, err := audits.ExportJSON(ctx, "admin", filter)
			require.NoError(t, err)
			require.Contains(t, string(exported), filter.Resource)
			require.NotContains(t, string(exported), "Owned confidential")
		}
	}
}

func TestTaskDeletionRollbackAndReviewedParent(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	sibling, err := f.client.Task.Create().SetName("Retained sibling").SetType("unix_script").SetOrder(9).SetProfileID(g.profile).Save(ctx)
	require.NoError(t, err)
	remove := func(ctx context.Context) error {
		return inventory.DeleteLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task))
	}
	// Failure after the delete must restore both cascading reports and sibling order.
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_task_renumber() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned task renumber failure'; END $$; CREATE TRIGGER reject_owned_task_renumber BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION reject_owned_task_renumber()`)
	require.NoError(t, err)
	require.Error(t, remove(ctx))
	assertDeletionGraph(t, f, g, true)
	_, err = f.db.ExecContext(ctx, `DROP TRIGGER reject_owned_task_renumber ON tasks; DROP FUNCTION reject_owned_task_renumber()`)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_task_delete_failure CHECK(action NOT IN ('inventory.tasks.delete','inventory.tasks.delete_review')) NOT VALID`)
	require.NoError(t, err)
	require.Error(t, remove(ctx))
	assertDeletionGraph(t, f, g, true)
	review, err := inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task))
	require.Error(t, err)
	require.Nil(t, review)
	current, err := f.client.Task.Get(ctx, sibling.ID)
	require.NoError(t, err)
	require.Equal(t, 9, current.Order)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_task_delete_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, remove(canceled))
	assertDeletionGraph(t, f, g, true)
	other := ownedTagProfile(t, f, f.scope, "Owned new parent")
	require.NoError(t, f.client.Task.UpdateOneID(g.task).SetProfileID(other.ID).Exec(ctx))
	require.ErrorIs(t, remove(ctx), inventory.ErrNotFound)
	_, err = inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task))
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.NoError(t, inventory.DeleteLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(other.ID), int64(g.task)))
	var events int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.delete' AND resource_id=$1`, fmt.Sprintf("%d/profile/%d/remaining/0", g.task, other.ID)).Scan(&events))
	require.Equal(t, 1, events)
}

func TestTaskDeletionBoundsReviewAndRejectsAmbiguousOrMissingOwners(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	require.NoError(t, f.client.Task.UpdateOneID(g.task).SetName(strings.Repeat("界", 2048)).SetScript("Owned hidden script").SetLocalUserPassword("Owned hidden password").Exec(ctx))
	review, err := inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task))
	require.NoError(t, err)
	require.True(t, review.NameTruncated)
	require.Equal(t, strings.Repeat("界", 512), review.Name)
	for _, ids := range [][2]int64{{0, int64(g.task)}, {int64(g.profile), 0}, {-1, -1}} {
		require.ErrorIs(t, inventory.DeleteLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, ids[0], ids[1]), inventory.ErrTaskInvalid)
		_, err := inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", f.scope, ids[0], ids[1])
		require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	}
	_, err = f.db.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, g.profile)
	require.NoError(t, err)
	require.ErrorIs(t, inventory.DeleteLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task)), inventory.ErrNotFound)
	_, err = inventory.ReviewTaskDeletion(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task))
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = f.db.ExecContext(ctx, `UPDATE tasks SET profile_tasks=NULL WHERE id=$1`, g.task)
	require.NoError(t, err)
	require.ErrorIs(t, inventory.DeleteLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.task)), inventory.ErrNotFound)
}
