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

type deletionGraph struct{ profile, task, issue, report, tag int }

func ownedDeletionGraph(t *testing.T, f *refreshFixture, scope access.Scope) deletionGraph {
	t.Helper()
	ctx := t.Context()
	p := ownedTagProfile(t, f, scope, "Owned <deletion> profile")
	task, err := f.client.Task.Create().SetName("Owned deletion task").SetType("powershell_script").SetProfileID(p.ID).Save(ctx)
	require.NoError(t, err)
	issue, err := f.client.ProfileIssue.Create().SetProfileID(p.ID).SetError("Owned report history").Save(ctx)
	require.NoError(t, err)
	var report int
	require.NoError(t, f.db.QueryRowContext(ctx, `INSERT INTO task_reports(task_reports,profile_issue_tasksreports,std_output) VALUES($1,$2,'Owned retained output') RETURNING id`, task.ID, issue.ID).Scan(&report))
	tag, err := f.client.Tag.Create().SetTag(fmt.Sprintf("Deletion tag %d", p.ID)).SetColor("blue").SetTenantID(f.scope.TenantID).Save(ctx)
	require.NoError(t, err)
	require.NoError(t, f.client.Profile.UpdateOneID(p.ID).AddTagIDs(tag.ID).Exec(ctx))
	return deletionGraph{p.ID, task.ID, issue.ID, report, tag.ID}
}

func assertDeletionGraph(t *testing.T, f *refreshFixture, g deletionGraph, retained bool) {
	t.Helper()
	for _, row := range []struct {
		table string
		id    int
	}{{"profiles", g.profile}, {"tasks", g.task}, {"profile_issues", g.issue}, {"task_reports", g.report}} {
		var exists bool
		require.NoError(t, f.db.QueryRowContext(t.Context(), fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id=$1)", row.table), row.id).Scan(&exists))
		require.Equal(t, retained, exists, row.table)
	}
	var exists bool
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM tags WHERE id=$1)`, g.tag).Scan(&exists))
	require.True(t, exists, "deletion removed a shared tag")
}

func TestProfileDeletionScopesAndCascadesAreAuditedTogether(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	other := ownedDeletionGraph(t, f, access.Scope{TenantID: organization.TenantID, SiteID: f.otherSite})
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		g := ownedDeletionGraph(t, f, scope)
		remove := func(actor string, requested access.Scope) error {
			return inventory.DeleteLegacyProfile(ctx, f.db, f.permissions, actor, requested, int64(g.profile))
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			require.ErrorIs(t, remove(actor, scope), access.ErrDenied)
			_, err := inventory.ReviewProfileDeletion(ctx, f.db, f.permissions, actor, scope, int64(g.profile))
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, organization, f.scope} {
			if wrong != scope {
				require.ErrorIs(t, remove("admin", wrong), inventory.ErrNotFound)
				_, err := inventory.ReviewProfileDeletion(ctx, f.db, f.permissions, "admin", wrong, int64(g.profile))
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		}
		review, err := inventory.ReviewProfileDeletion(ctx, f.db, f.permissions, "admin", scope, int64(g.profile))
		require.NoError(t, err)
		require.Equal(t, int64(g.profile), review.ID)
		require.Equal(t, "Owned <deletion> profile", review.Name)
		require.False(t, review.NameTruncated)
		assertDeletionGraph(t, f, g, true)
		require.NoError(t, remove("admin", scope))
		require.ErrorIs(t, remove("admin", scope), inventory.ErrNotFound)
		assertDeletionGraph(t, f, g, false)
		assertDeletionGraph(t, f, other, true)
		var edges int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM profile_tags WHERE profile_id=$1)+(SELECT count(*) FROM tenant_profiles WHERE profile_id=$1)+(SELECT count(*) FROM site_profiles WHERE profile_id=$1)`, g.profile).Scan(&edges))
		require.Zero(t, edges)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		filter := audit.Filter{Scope: scope, Source: "inventory", Action: "inventory.profiles.delete", Resource: fmt.Sprintf("%d/tasks/1", g.profile), From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
		page, err := audits.List(ctx, "admin", filter, "")
		require.NoError(t, err)
		require.Len(t, page.Events, 1)
		require.Equal(t, scope.TenantID, page.Events[0].TenantID)
		require.Equal(t, scope.SiteID, page.Events[0].SiteID)
		exported, err := audits.ExportJSON(ctx, "admin", filter)
		require.NoError(t, err)
		require.Contains(t, string(exported), filter.Resource)
	}
}

func TestProfileDeletionRollsBackTaskAndReportRemoval(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	remove := func(ctx context.Context) error {
		return inventory.DeleteLegacyProfile(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile))
	}
	_, err := f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_profile_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned parent deletion failure'; END $$; CREATE TRIGGER reject_owned_profile_delete BEFORE DELETE ON profiles FOR EACH ROW EXECUTE FUNCTION reject_owned_profile_delete()`)
	require.NoError(t, err)
	require.Error(t, remove(ctx))
	assertDeletionGraph(t, f, g, true)
	_, err = f.db.ExecContext(ctx, `DROP TRIGGER reject_owned_profile_delete ON profiles; DROP FUNCTION reject_owned_profile_delete()`)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_profile_delete_audit_failure CHECK(action!='inventory.profiles.delete') NOT VALID`)
	require.NoError(t, err)
	require.Error(t, remove(ctx))
	assertDeletionGraph(t, f, g, true)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_profile_delete_audit_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, remove(canceled))
	assertDeletionGraph(t, f, g, true)
	var events int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.profiles.delete'`).Scan(&events))
	require.Zero(t, events)
	require.NoError(t, remove(ctx))
	assertDeletionGraph(t, f, g, false)
}

func TestProfileDeletionWaitsForCurrentAudienceAndBoundsReview(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	long := strings.Repeat("界", 2048)
	require.NoError(t, f.client.Profile.UpdateOneID(g.profile).SetName(long).Exec(ctx))
	review, err := inventory.ReviewProfileDeletion(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile))
	require.NoError(t, err)
	require.True(t, review.NameTruncated)
	require.Equal(t, strings.Repeat("界", 512), review.Name)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, g.profile)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	require.Error(t, inventory.DeleteLegacyProfile(bounded, f.db, f.permissions, "admin", f.scope, int64(g.profile)))
	cancel()
	require.NoError(t, tx.Commit())
	require.ErrorIs(t, inventory.DeleteLegacyProfile(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile)), inventory.ErrNotFound)
	_, err = inventory.ReviewProfileDeletion(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile))
	require.ErrorIs(t, err, inventory.ErrNotFound)
	assertDeletionGraph(t, f, g, true)
}
