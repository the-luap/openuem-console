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

func TestProfileIssueHistoryScopeAndRetainedOrphans(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	unrelated := ownedDeletionGraph(t, f, access.Scope{})
	for _, scope := range []access.Scope{{}, org, f.scope} {
		g := ownedDeletionGraph(t, f, scope)
		require.NoError(t, f.client.Task.UpdateOneID(g.task).SetDisabled(true).SetScript("private-history-script").SetLocalUserPassword("private-history-password").Exec(ctx))
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "viewer", "missing"} {
			_, err := inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, actor, scope, int64(g.profile), 1, 25)
			require.ErrorIs(t, err, access.ErrDenied)
			_, err = inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, actor, scope, int64(g.profile), int64(g.issue), 1)
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, org, f.scope} {
			if wrong != scope {
				_, err := inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", wrong, int64(g.profile), 1, 25)
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		}
		page, err := inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), 99, 25)
		require.NoError(t, err)
		require.Equal(t, 1, page.Page)
		require.Len(t, page.Issues, 1)
		require.Equal(t, "missing", page.Issues[0].EndpointState)
		require.Equal(t, 1, page.Issues[0].Reports)
		require.NotContains(t, fmt.Sprint(page), "Owned retained output")
		require.NotContains(t, fmt.Sprint(page), "private-history-")
		reports, err := inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), int64(g.issue), 99)
		require.NoError(t, err)
		require.Len(t, reports.Reports, 1)
		require.True(t, reports.Reports[0].TaskDisabled)
		require.Equal(t, "Owned retained output", reports.Reports[0].Output)
		require.Nil(t, reports.Reports[0].End)
		_, err = inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), int64(unrelated.issue), 1)
		require.ErrorIs(t, err, inventory.ErrNotFound)
		require.NoError(t, f.client.ProfileIssue.UpdateOneID(g.issue).SetAgentsID(f.id).Exec(ctx))
		page, err = inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), 1, 25)
		require.NoError(t, err)
		require.Equal(t, "available", page.Issues[0].EndpointState)
		require.Equal(t, f.id, page.Issues[0].EndpointID)
		require.Equal(t, f.scope, page.Issues[0].EndpointScope)
		// Extra endpoint memberships cannot create duplicate rows or a misleading link.
		_, err = f.db.ExecContext(ctx, `INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)`, f.id, f.otherSite)
		require.NoError(t, err)
		page, err = inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), 1, 25)
		require.NoError(t, err)
		require.Len(t, page.Issues, 1)
		require.Equal(t, "unavailable", page.Issues[0].EndpointState)
		require.Empty(t, page.Issues[0].EndpointID)
		require.Empty(t, page.Issues[0].EndpointName)
		_, err = f.db.ExecContext(ctx, `DELETE FROM site_agents WHERE agent_id=$1 AND site_id=$2`, f.id, f.otherSite)
		require.NoError(t, err)
		assertDeletionGraph(t, f, g, true)
		assertDeletionGraph(t, f, unrelated, true)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		for action, resource := range map[string]string{"inventory.profile_issues.list": fmt.Sprintf("%d/page/1/size/25", g.profile), "inventory.profile_issues.read": fmt.Sprintf("%d/issue/%d/page/1", g.profile, g.issue)} {
			filter := audit.Filter{Scope: scope, Source: "inventory", Action: action, Resource: resource, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
			events, err := audits.List(ctx, "admin", filter, "")
			require.NoError(t, err)
			require.NotEmpty(t, events.Events)
			data, err := audits.ExportJSON(ctx, "admin", filter)
			require.NoError(t, err)
			require.NotContains(t, string(data), "Owned retained output")
			require.NotContains(t, string(data), "private-history-")
		}
	}
}

func TestProfileIssueHistoryBoundedPagesAndAuditRollback(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	_, err := f.db.ExecContext(ctx, `UPDATE profile_issues SET "when"=NULL,error=$2 WHERE id=$1`, g.issue, strings.Repeat("界", 1100))
	require.NoError(t, err)
	for i := 0; i < 30; i++ {
		_, err = f.db.ExecContext(ctx, `INSERT INTO profile_issues(profile_issues,"when") VALUES($1,$2)`, g.profile, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		require.NoError(t, err)
	}
	page, err := inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), 99, 25)
	require.NoError(t, err)
	require.Equal(t, 2, page.Page)
	require.Equal(t, 31, page.Total)
	require.Len(t, page.Issues, 6)
	last := page.Issues[5]
	require.Equal(t, int64(g.issue), last.ID)
	require.Nil(t, last.When)
	require.True(t, last.ErrorTruncated)
	require.Len(t, []rune(last.Error), 1024)
	for i := 0; i < 52; i++ {
		_, err = f.db.ExecContext(ctx, `INSERT INTO task_reports(profile_issue_tasksreports,std_output,std_error,failed,"end") VALUES($1,$2,$3,$4,$5)`, g.issue, strings.Repeat("界", 4500), strings.Repeat("E", 4500), i%2 == 0, "2026-01-02T03:04:05.123456789+02:00")
		require.NoError(t, err)
	}
	reports, err := inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.issue), 99)
	require.NoError(t, err)
	require.Equal(t, 3, reports.Page)
	require.Equal(t, 53, reports.Total)
	require.Len(t, reports.Reports, 3)
	for _, r := range reports.Reports {
		require.Zero(t, r.TaskID)
		require.Empty(t, r.TaskName)
		require.True(t, r.OutputTruncated)
		require.True(t, r.ErrorTruncated)
		require.Len(t, []rune(r.Output), 4096)
		require.NotNil(t, r.End)
		require.Equal(t, 123456789, r.End.Nanosecond())
	}
	other := ownedDeletionGraph(t, f, access.Scope{})
	_, err = f.db.ExecContext(ctx, `UPDATE task_reports SET task_reports=$2,"end"='not a timestamp' WHERE id=$1`, g.report, other.task)
	require.NoError(t, err)
	reports, err = inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.issue), 1)
	require.NoError(t, err)
	require.Zero(t, reports.Reports[0].TaskID)
	require.Empty(t, reports.Reports[0].TaskName)
	require.Equal(t, "Owned retained output", reports.Reports[0].Output)
	require.Nil(t, reports.Reports[0].End)
	require.Equal(t, "not a timestamp", reports.Reports[0].RawEnd)
	for _, v := range [][2]int{{0, 25}, {1000001, 25}, {1, 101}, {1, 0}} {
		_, err = inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), v[0], v[1])
		require.ErrorIs(t, err, inventory.ErrProfileInvalid)
	}
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_issue_read() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('inventory.profile_issues.list','inventory.profile_issues.read') THEN RAISE EXCEPTION 'private issue audit error'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_issue_read BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_issue_read()`)
	require.NoError(t, err)
	page, err = inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), 1, 25)
	require.Error(t, err)
	require.Nil(t, page)
	reports, err = inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "admin", f.scope, int64(g.profile), int64(g.issue), 1)
	require.Error(t, err)
	require.Nil(t, reports)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = inventory.ReadLegacyProfileIssues(cancelled, f.db, f.permissions, "admin", f.scope, int64(g.profile), 1, 25)
	require.Error(t, err)
	assertDeletionGraph(t, f, g, true)
	assertDeletionGraph(t, f, other, true)
}

func TestProfileIssueHistoryDoesNotExposeForeignCurrentEndpointIdentity(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	foreign, err := f.client.Tenant.Create().SetDescription("Foreign history endpoint owner").Save(ctx)
	require.NoError(t, err)
	site, err := f.client.Site.Create().SetDescription("Foreign history endpoint site").SetTenantID(foreign.ID).Save(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `UPDATE site_agents SET site_id=$2 WHERE agent_id=$1`, f.id, site.ID)
	require.NoError(t, err)
	for _, scope := range []access.Scope{{}, org, f.scope} {
		g := ownedDeletionGraph(t, f, scope)
		require.NoError(t, f.client.ProfileIssue.UpdateOneID(g.issue).SetAgentsID(f.id).Exec(ctx))
		page, err := inventory.ReadLegacyProfileIssues(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), 1, 25)
		require.NoError(t, err)
		require.Len(t, page.Issues, 1)
		if scope.TenantID == 0 {
			require.Equal(t, "available", page.Issues[0].EndpointState)
			require.Equal(t, access.Scope{TenantID: foreign.ID, SiteID: site.ID}, page.Issues[0].EndpointScope)
		} else {
			require.Equal(t, "unavailable", page.Issues[0].EndpointState)
			require.Empty(t, page.Issues[0].EndpointID)
			require.Empty(t, page.Issues[0].EndpointName)
			require.Zero(t, page.Issues[0].EndpointScope.TenantID)
		}
		reports, err := inventory.ReadLegacyProfileIssueReports(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), int64(g.issue), 1)
		require.NoError(t, err)
		require.Equal(t, page.Issues[0].EndpointState, reports.Issue.EndpointState)
		require.Equal(t, "Owned retained output", reports.Reports[0].Output)
		assertDeletionGraph(t, f, g, true)
	}
}
