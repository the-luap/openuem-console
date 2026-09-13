package inventory_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestTaskStatusUsesCurrentExactProfileAndPreservesDefinition(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	scopes := []access.Scope{{}, organization, f.scope}
	for _, scope := range scopes {
		g := ownedDeletionGraph(t, f, scope)
		require.NoError(t, f.client.Task.UpdateOneID(g.task).SetVersion(7).SetOrder(0).SetScript("Owned retained task script").SetLocalUserPassword("Owned synthetic credential").AddTagIDs(g.tag).Exec(ctx))
		var original string
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT (to_jsonb(t)-'disabled')::text FROM tasks t WHERE id=$1", g.task).Scan(&original))
		set := func(actor string, requested access.Scope, enabled bool) (int64, error) {
			return inventory.SetTaskEnabled(ctx, f.db, f.permissions, actor, requested, int64(g.task), enabled)
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			id, err := set(actor, scope, false)
			require.Zero(t, id)
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range scopes {
			if wrong == scope {
				continue
			}
			id, err := set("admin", wrong, false)
			require.Zero(t, id)
			require.ErrorIs(t, err, inventory.ErrNotFound)
		}
		for _, enabled := range []bool{false, false, true} {
			id, err := set("admin", scope, enabled)
			require.NoError(t, err)
			require.Equal(t, int64(g.profile), id)
			var disabled, equal bool
			require.NoError(t, f.db.QueryRowContext(ctx, "SELECT disabled,(to_jsonb(t)-'disabled')=$2::jsonb FROM tasks t WHERE id=$1", g.task, original).Scan(&disabled, &equal))
			require.Equal(t, !enabled, disabled)
			require.True(t, equal, "task status changed configuration, version, owner or order")
			assertDeletionGraph(t, f, g, true)
		}
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		filter := audit.Filter{Scope: scope, Source: "inventory", Action: "inventory.tasks.disable", Resource: fmt.Sprintf("%d/profile/%d", g.task, g.profile), From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
		page, err := audits.List(ctx, "admin", filter, "")
		require.NoError(t, err)
		require.Len(t, page.Events, 2)
		data, err := audits.ExportJSON(ctx, "admin", filter)
		require.NoError(t, err)
		require.Contains(t, string(data), filter.Resource)
		require.NotContains(t, string(data), "Owned synthetic credential")
	}
	orphan, err := f.client.Task.Create().SetName("Owned orphan status task").SetType("unix_script").Save(ctx)
	require.NoError(t, err)
	id, err := inventory.SetTaskEnabled(ctx, f.db, f.permissions, "admin", organization, int64(orphan.ID), false)
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	id, err = inventory.SetTaskEnabled(ctx, f.db, f.permissions, "admin", organization, 0, false)
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	id, err = inventory.SetTaskEnabled(ctx, f.db, f.permissions, "admin", access.Scope{SiteID: f.scope.SiteID}, int64(orphan.ID), false)
	require.Zero(t, id)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestTaskStatusRollsBackAndRejectsChangedAudience(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	set := func(ctx context.Context) (int64, error) {
		return inventory.SetTaskEnabled(ctx, f.db, f.permissions, "admin", f.scope, int64(g.task), false)
	}
	_, err := f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_task_status_failure CHECK(action!='inventory.tasks.disable') NOT VALID")
	require.NoError(t, err)
	id, err := set(ctx)
	require.Zero(t, id)
	require.Error(t, err)
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_task_status_failure")
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	id, err = set(canceled)
	require.Zero(t, id)
	require.Error(t, err)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)", f.otherSite, g.profile)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	id, err = set(bounded)
	cancel()
	require.Zero(t, id)
	require.Error(t, err)
	require.NoError(t, tx.Commit())
	id, err = set(ctx)
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	current, err := f.client.Task.Get(ctx, g.task)
	require.NoError(t, err)
	require.False(t, current.Disabled)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.tasks.disable'").Scan(&count))
	require.Zero(t, count)
	assertDeletionGraph(t, f, g, true)
}
