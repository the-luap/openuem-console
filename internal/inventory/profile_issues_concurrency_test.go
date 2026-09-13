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

func TestProfileIssueHistoryHoldsSourceAndAuthorityUntilReceipt(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	require.NoError(t, f.client.ProfileIssue.UpdateOneID(g.issue).SetAgentsID(f.id).Exec(ctx))
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810077)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810077)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_issue_read_entered; CREATE FUNCTION hold_owned_issue_read() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profile_issues.read' THEN PERFORM nextval('owned_issue_read_entered'); PERFORM pg_advisory_xact_lock(673810077); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_issue_read AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_issue_read()`)
	require.NoError(t, err)
	type outcome struct {
		page *inventory.ProfileIssueReportsPage
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		p, err := inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.profile), int64(g.issue), 1)
		done <- outcome{p, err}
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_issue_read_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	select {
	case <-done:
		t.Fatal("history returned before receipt commit")
	default:
	}
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE profile_issues SET error='Concurrent error' WHERE id=$1", g.issue)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO profile_issues(profile_issues,error) VALUES($1,'Concurrent report')", g.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO task_reports(profile_issue_tasksreports) VALUES($1)", g.issue)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE task_reports SET std_output='Concurrent output' WHERE id=$1", g.report)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM task_reports WHERE id=$1", g.report)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tasks SET name='Concurrent task name' WHERE id=$1", g.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE agents SET nickname='Concurrent endpoint name' WHERE oid=$1", f.id)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM agents WHERE oid=$1", f.id)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)", f.id, f.otherSite)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM site_profiles WHERE profile_id=$1", g.profile)
			return err
		},
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: org}})
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
		require.Equal(t, "Owned retained output", result.page.Reports[0].Output)
	case <-time.After(2 * time.Second):
		t.Fatal("history read did not leave audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: org}}))
	page, err := inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.profile), int64(g.issue), 1)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, page)
	assertDeletionGraph(t, f, g, true)
}
