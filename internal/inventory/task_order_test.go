package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent"
	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestTaskOrderAndReadPageUseCurrentScopeWithoutReadingSecrets(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	scopes := []access.Scope{{}, organization, f.scope}
	for _, scope := range scopes {
		g := ownedDeletionGraph(t, f, scope)
		require.NoError(t, f.client.Task.UpdateOneID(g.task).SetVersion(9).SetScript("Owned private script").SetLocalUserPassword("Owned private credential").SetPackageName("Owned summary package").SetWhen(time.Now()).Exec(ctx))
		ids := []int{g.task}
		for i, order := range []int{0, 7, 7, 10} {
			name := fmt.Sprintf("Owned task %d", i)
			if i == 0 {
				name = strings.Repeat("x", 600)
			}
			row, err := f.client.Task.Create().SetName(name).SetType(task.TypeUnixScript).SetOrder(order).SetProfileID(g.profile).Save(ctx)
			require.NoError(t, err)
			ids = append(ids, row.ID)
		}
		_, err := f.db.ExecContext(ctx, "UPDATE tasks SET \"order\"=NULL WHERE id=$1", ids[4])
		require.NoError(t, err)
		var original, configuration string
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT jsonb_agg(to_jsonb(t) ORDER BY id)::text,jsonb_agg(to_jsonb(t)-'order' ORDER BY id)::text FROM tasks t WHERE profile_tasks=$1", g.profile).Scan(&original, &configuration))
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			id, err := inventory.ReorderLegacyTask(ctx, f.db, f.permissions, actor, scope, int64(ids[2]), 3, 1)
			require.Zero(t, id)
			require.ErrorIs(t, err, access.ErrDenied)
			page, err := inventory.ReadLegacyTaskPage(ctx, f.db, f.permissions, actor, scope, int64(g.profile), 1, 2)
			require.Nil(t, page)
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range scopes {
			if wrong == scope {
				continue
			}
			id, err := inventory.ReorderLegacyTask(ctx, f.db, f.permissions, "admin", wrong, int64(ids[2]), 3, 1)
			require.Zero(t, id)
			require.ErrorIs(t, err, inventory.ErrNotFound)
			page, err := inventory.ReadLegacyTaskPage(ctx, f.db, f.permissions, "admin", wrong, int64(g.profile), 1, 2)
			require.Nil(t, page)
			require.ErrorIs(t, err, inventory.ErrNotFound)
		}
		page, err := inventory.ReadLegacyTaskPage(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), 1, 2)
		require.NoError(t, err)
		require.Equal(t, 5, page.Total)
		require.Len(t, page.Tasks, 2)
		require.Equal(t, ids[0], page.Tasks[0].ID)
		require.Equal(t, 1, page.Tasks[0].Order)
		require.Empty(t, page.Tasks[0].Script)
		require.Empty(t, page.Tasks[0].LocalUserPassword)
		require.Equal(t, "Owned summary package", page.Tasks[0].PackageName)
		require.Equal(t, strings.Repeat("x", 512)+"…", page.Tasks[1].Name)
		last, err := inventory.ReadLegacyTaskPage(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), 100, 2)
		require.NoError(t, err)
		require.Equal(t, 3, last.Page)
		require.Len(t, last.Tasks, 1)
		require.Equal(t, ids[4], last.Tasks[0].ID)
		require.Equal(t, 5, last.Tasks[0].Order)
		var equal bool
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT jsonb_agg(to_jsonb(t) ORDER BY id)=$2::jsonb FROM tasks t WHERE profile_tasks=$1", g.profile, original).Scan(&equal))
		require.True(t, equal, "task page read changed stored task values")
		id, err := inventory.ReorderLegacyTask(ctx, f.db, f.permissions, "admin", scope, int64(ids[2]), 3, 1)
		require.NoError(t, err)
		require.Equal(t, int64(g.profile), id)
		ordered, err := f.client.Task.Query().Where(task.HasProfileWith(entprofile.ID(g.profile))).Order(ent.Asc(task.FieldOrder)).All(ctx)
		require.NoError(t, err)
		for i, want := range []int{ids[2], ids[0], ids[1], ids[3], ids[4]} {
			require.Equal(t, want, ordered[i].ID)
			require.Equal(t, i+1, ordered[i].Order)
		}
		id, err = inventory.ReorderLegacyTask(ctx, f.db, f.permissions, "admin", scope, int64(ids[2]), 3, 2)
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrTaskOrderChanged)
		id, err = inventory.ReorderLegacyTask(ctx, f.db, f.permissions, "admin", scope, int64(ids[2]), 1, 1)
		require.NoError(t, err)
		require.Equal(t, int64(g.profile), id)
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT jsonb_agg(to_jsonb(t)-'order' ORDER BY id)=$2::jsonb FROM tasks t WHERE profile_tasks=$1", g.profile, configuration).Scan(&equal))
		require.True(t, equal, "reordering changed task configuration or history")
		assertDeletionGraph(t, f, g, true)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		filter := audit.Filter{Scope: scope, Source: "inventory", Action: "inventory.tasks.reorder", Resource: fmt.Sprintf("%d/profile/%d/from/3/to/1/tasks/5", ids[2], g.profile), From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
		events, err := audits.List(ctx, "admin", filter, "")
		require.NoError(t, err)
		require.Len(t, events.Events, 1)
		data, err := audits.ExportJSON(ctx, "admin", filter)
		require.NoError(t, err)
		require.Contains(t, string(data), filter.Resource)
		require.NotContains(t, string(data), "Owned private")
	}
}

func TestTaskOrderAndPageRejectInvalidRequestsAndRollBackFailedAudit(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	other := ownedDeletionGraph(t, f, f.scope)
	_, err := f.client.Task.Create().SetName("Owned second reorder task").SetType(task.TypeUnixScript).SetOrder(9).SetProfileID(g.profile).Save(ctx)
	require.NoError(t, err)
	move := func(ctx context.Context, from, to int64) (int64, error) {
		return inventory.ReorderLegacyTask(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), from, to)
	}
	for _, positions := range [][2]int64{{0, 1}, {1, 0}, {1, 3}} {
		id, err := move(ctx, positions[0], positions[1])
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	}
	for _, bounds := range [][2]int{{0, 2}, {1, 0}, {1000001, 2}, {1, 1001}} {
		page, err := inventory.ReadLegacyTaskPage(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), bounds[0], bounds[1])
		require.Nil(t, page)
		require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	}
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_task_order_failure CHECK(action NOT IN ('inventory.tasks.reorder','inventory.tasks.list')) NOT VALID")
	require.NoError(t, err)
	id, err := move(ctx, 1, 2)
	require.Zero(t, id)
	require.Error(t, err)
	page, err := inventory.ReadLegacyTaskPage(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), 1, 2)
	require.Nil(t, page)
	require.Error(t, err)
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_task_order_failure")
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	id, err = move(canceled, 1, 2)
	require.Zero(t, id)
	require.Error(t, err)
	current, err := f.client.Task.Get(ctx, g.task)
	require.NoError(t, err)
	require.Zero(t, current.Order)
	unchanged, err := f.client.Task.Get(ctx, other.task)
	require.NoError(t, err)
	require.Zero(t, unchanged.Order)
	id, err = move(ctx, 1, 2)
	require.NoError(t, err)
	require.Equal(t, int64(g.profile), id)
	unchanged, err = f.client.Task.Get(ctx, other.task)
	require.NoError(t, err)
	require.Zero(t, unchanged.Order)
	assertDeletionGraph(t, f, g, true)
	assertDeletionGraph(t, f, other, true)
}
