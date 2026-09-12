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

func TestOrganizationTagDeletionPreservesAllAssignmentKinds(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	tag, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, 0, "", tagDefinition("Reference target"))
	require.NoError(t, err)
	profile, err := f.client.Profile.Create().SetName("Owned tagged profile").AddTagIDs(int(tag.ID)).Save(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision), inventory.ErrTagUsed)
	require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).RemoveTagIDs(int(tag.ID)).Exec(ctx))
	child, err := f.client.Tag.Create().SetTag("Owned child").SetColor("#123456").SetTenantID(scope.TenantID).SetParentID(int(tag.ID)).Save(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision), inventory.ErrTagUsed)
	childView, err := inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, int64(child.ID))
	require.NoError(t, err)
	require.ErrorIs(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, childView.ID, childView.Revision), inventory.ErrTagUsed)
	require.NoError(t, f.client.Tag.UpdateOneID(child.ID).ClearParent().Exec(ctx))
	task, err := f.client.Task.Create().SetName("Owned tagged task").SetType("powershell_script").Save(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `UPDATE tags SET task_tags=$1 WHERE id=$2`, task.ID, tag.ID)
	require.NoError(t, err)
	tag, err = inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID)
	require.NoError(t, err)
	require.ErrorIs(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision), inventory.ErrTagUsed)
	_, err = f.db.ExecContext(ctx, `UPDATE tags SET task_tags=NULL WHERE id=$1`, tag.ID)
	require.NoError(t, err)
	tag, err = inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID)
	require.NoError(t, err)
	// A pending new reference holds the foreign-key lock before deletion starts.
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_tags(agent_id,tag_id) VALUES($1,$2)`, f.id, tag.ID)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	err = inventory.DeleteOrganizationTag(bounded, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision)
	cancel()
	require.Error(t, err)
	require.NoError(t, tx.Commit())
	require.ErrorIs(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision), inventory.ErrTagUsed)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).RemoveTagIDs(int(tag.ID)).Exec(ctx))
	require.NoError(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision))
}

func TestOrganizationTagDeleteHoldsPermissionAndReferenceLocksUntilAuditCommit(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	tag, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, 0, "", tagDefinition("Final audited delete"))
	require.NoError(t, err)
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(673810060)`)
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(673810060)`)
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_tag_delete_entered; CREATE FUNCTION hold_owned_tag_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tags.delete' THEN PERFORM nextval('owned_tag_delete_entered'); PERFORM pg_advisory_xact_lock(673810060); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_tag_delete AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_tag_delete()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision)
	}()
	require.Eventually(t, func() bool {
		var entered bool
		err := f.db.QueryRowContext(ctx, `SELECT is_called FROM owned_tag_delete_entered`).Scan(&entered)
		return err == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	err = f.permissions.ReplaceGrants(bounded, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}})
	cancel()
	require.Error(t, err)
	bounded, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = f.db.ExecContext(bounded, `INSERT INTO agent_tags(agent_id,tag_id) VALUES($1,$2)`, f.id, tag.ID)
	cancel()
	require.Error(t, err)
	release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("tag deletion did not leave its audit gate")
	}
	var refs int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM agent_tags WHERE tag_id=$1`, tag.ID).Scan(&refs))
	require.Zero(t, refs)
	_, err = f.db.ExecContext(ctx, `INSERT INTO agent_tags(agent_id,tag_id) VALUES($1,$2)`, f.id, tag.ID)
	require.Error(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}))
}
