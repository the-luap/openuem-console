package inventory_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestDesktopTaskHistoryIsBoundedScopedAndKeepsMissingDefinitions(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	p, id := manualTask(t, f, f.scope)
	issue, err := f.client.ProfileIssue.Create().SetProfileID(p).SetAgentsID(f.id).Save(ctx)
	require.NoError(t, err)
	report, err := f.client.TaskReport.Create().SetProfileissueID(issue.ID).SetTaskID(id).SetStdOutput("Owned <output>").SetStdError("Owned <error>").SetFailed(true).SetEnd("2026-09-13T12:34:56.123456789Z").Save(ctx)
	require.NoError(t, err)
	for _, actor := range []string{"tag-admin", "tag-viewer", "tag-operator", "missing"} {
		_, err = inventory.ReadDesktopTasks(ctx, f.db, f.permissions, actor, f.scope, f.id, 1, 25)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, scope := range []access.Scope{org, f.scope} {
		page, err := inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", scope, f.id, 99, 25)
		require.NoError(t, err)
		require.Equal(t, 1, page.Page)
		require.Equal(t, 1, page.Total)
		require.Len(t, page.Reports, 1)
		require.Equal(t, int64(report.ID), page.Reports[0].ID)
		require.True(t, page.Reports[0].CanReview)
		require.True(t, page.Reports[0].Failed)
		require.NotNil(t, page.Reports[0].End)
		require.Equal(t, "Owned <output>", page.Reports[0].Output)
		require.Equal(t, f.scope, page.Reports[0].ProfileScope)
		require.NotContains(t, fmt.Sprint(page), "Owned command")
	}
	require.NoError(t, f.client.Task.UpdateOneID(id).SetDisabled(true).Exec(ctx))
	page, err := inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", f.scope, f.id, 1, 25)
	require.NoError(t, err)
	require.True(t, page.Reports[0].TaskDisabled)
	require.False(t, page.Reports[0].CanReview)
	require.NoError(t, f.client.TaskReport.UpdateOneID(report.ID).ClearTask().Exec(ctx))
	require.NoError(t, f.client.Task.DeleteOneID(id).Exec(ctx))
	page, err = inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", f.scope, f.id, 1, 25)
	require.NoError(t, err)
	require.Zero(t, page.Reports[0].TaskID)
	require.Equal(t, "Owned <output>", page.Reports[0].Output)
	_, err = f.db.ExecContext(ctx, "INSERT INTO site_profiles(profile_id,site_id) VALUES($1,$2)", p, f.otherSite)
	require.NoError(t, err)
	page, err = inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", f.scope, f.id, 1, 25)
	require.NoError(t, err)
	require.Zero(t, page.Reports[0].ProfileID)
	require.Empty(t, page.Reports[0].ProfileName)
	require.Equal(t, access.Scope{}, page.Reports[0].ProfileScope)
	_, err = f.db.ExecContext(ctx, "INSERT INTO task_reports(profile_issue_tasksreports,std_output,std_error,\"end\") SELECT $1,repeat('x',5000),repeat('e',5000),'invalid time' FROM generate_series(1,30)", issue.ID)
	require.NoError(t, err)
	page, err = inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", f.scope, f.id, 1, 25)
	require.NoError(t, err)
	require.Equal(t, 31, page.Total)
	require.Len(t, page.Reports, 25)
	require.Len(t, page.Reports[0].Output, 4096)
	require.Len(t, page.Reports[0].Error, 4096)
	require.True(t, page.Reports[0].OutputTruncated)
	require.True(t, page.Reports[0].ErrorTruncated)
	require.Nil(t, page.Reports[0].End)
	require.Equal(t, "invalid time", page.Reports[0].RawEnd)
	_, err = inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", access.Scope{TenantID: org.TenantID, SiteID: f.otherSite}, f.id, 1, 25)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	for _, args := range [][2]int{{0, 25}, {1000001, 25}, {1, 0}, {1, 101}} {
		_, err = inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", f.scope, f.id, args[0], args[1])
		require.ErrorIs(t, err, inventory.ErrManualInvalid)
	}
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_task_history_failure CHECK(action<>'inventory.desktop_tasks.read') NOT VALID")
	require.NoError(t, err)
	page, err = inventory.ReadDesktopTasks(ctx, f.db, f.permissions, "admin", f.scope, f.id, 1, 25)
	require.Error(t, err)
	require.Nil(t, page)
	require.NotContains(t, strings.ToLower(fmt.Sprint(page)), "owned")
}
