package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskexecution"
)

type DesktopTaskReport struct {
	ProfileIssueReport
	ProfileID    int64
	ProfileName  string
	ProfileScope access.Scope
	CanReview    bool
}

type DesktopTasksPage struct {
	Target                ManualTarget
	Status                string
	Reports               []DesktopTaskReport
	Page, PageSize, Total int
}

// ReadDesktopTasks returns a bounded report snapshot for one uniquely assigned
// computer. It never loads task definitions, provider settings or broker state.
func ReadDesktopTasks(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, deviceID string, page, size int) (*DesktopTasksPage, error) {
	if !ValidReportDeviceID(deviceID) || page < 1 || page > 1000000 || size < 1 || size > 100 {
		return nil, ErrManualInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginGroupTransaction(ctx, db, permissions, actor, scope, access.ManageProfiles)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageProfiles, access.Scope{}); err != nil {
		return nil, err
	}
	// Keep complete endpoint membership and profile audience stable until the
	// read receipt commits. A single statement below couples rows and totals.
	_, err = tx.ExecContext(ctx, "LOCK TABLE site_agents,tenant_profiles,site_profiles IN SHARE MODE")
	if err != nil {
		return nil, err
	}
	result := &DesktopTasksPage{Page: page, PageSize: size}
	err = tx.QueryRowContext(ctx, "SELECT a.oid,coalesce(left(nullif(a.nickname,''),256),left(a.hostname,256),''),coalesce(a.os,''),s.tenant_sites,s.id,a.agent_status FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id WHERE a.oid=$1 AND s.tenant_sites=$2 AND ($3::bigint=0 OR s.id=$3) AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 AND a.agent_status IN ('Enabled','No contact','Disabled') FOR SHARE OF a,s", deviceID, scope.TenantID, scope.SiteID).Scan(&result.Target.ID, &result.Target.Name, &result.Target.Platform, &result.Target.Scope.TenantID, &result.Target.Scope.SiteID, &result.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if result.Target.Platform == "macOS" {
		result.Target.Platform = "macos"
	}
	rows, err := tx.QueryContext(ctx, desktopTaskReportsSQL, deviceID, result.Target.Scope.TenantID, result.Target.Scope.SiteID, page, size)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item DesktopTaskReport
		var id sql.NullInt64
		var kind, platform string
		var profileDisabled bool
		if err = rows.Scan(&result.Total, &result.Page, &id, &item.TaskID, &item.TaskName, &item.TaskDisabled, &item.Failed, &item.Output, &item.Error, &item.OutputTruncated, &item.ErrorTruncated, &item.RawEnd, &item.ProfileID, &item.ProfileName, &item.ProfileScope.TenantID, &item.ProfileScope.SiteID, &profileDisabled, &kind, &platform); err != nil {
			rows.Close()
			return nil, err
		}
		if !id.Valid {
			continue
		}
		item.ID = id.Int64
		if parsed, err := time.Parse(time.RFC3339Nano, item.RawEnd); err == nil {
			item.End = &parsed
		}
		item.CanReview = item.TaskID > 0 && !item.TaskDisabled && !profileDisabled && result.Status != "Disabled" && platform == result.Target.Platform && taskexecution.Supported(task.Type(kind), task.AgentType(platform))
		result.Reports = append(result.Reports, item)
	}
	if err = finishProfileIssueRows(rows); err != nil {
		return nil, err
	}
	if err = commitProfileIssueRead(ctx, tx, actor, result.Target.Scope, "inventory.desktop_tasks.read", fmt.Sprintf("%s/page/%d/size/%d", deviceID, result.Page, size)); err != nil {
		return nil, err
	}
	return result, nil
}

const desktopTaskReportsSQL = "WITH history AS NOT MATERIALIZED (" +
	"SELECT r.*,i.profile_issues AS parent_id,i.\"when\" AS issue_time FROM task_reports r JOIN profile_issues i ON i.id=r.profile_issue_tasksreports WHERE i.profile_issue_agents=$1)," +
	"total AS (SELECT count(*)::int AS n FROM history), paging AS (SELECT n,least($4::int,greatest(1,(n+$5::int-1)/$5::int)) AS page FROM total)," +
	"selected AS (SELECT h.* FROM history h ORDER BY h.issue_time DESC NULLS LAST,h.id DESC OFFSET (SELECT (page-1)*$5::int FROM paging) LIMIT $5) " +
	"SELECT paging.n,paging.page,r.id,coalesce(t.id,0),coalesce(left(t.name,512),''),coalesce(t.disabled,false),coalesce(r.failed,false),coalesce(left(r.std_output,4096),''),coalesce(left(r.std_error,4096),''),coalesce(char_length(r.std_output)>4096,false),coalesce(char_length(r.std_error)>4096,false),coalesce(left(r.\"end\",128),''),coalesce(p.id,0),coalesce(left(p.name,512),''),CASE WHEN p.id IS NOT NULL THEN audience.tenant_id ELSE 0 END,CASE WHEN p.id IS NOT NULL THEN audience.site_id ELSE 0 END,coalesce(p.disabled,false),coalesce(t.type,''),coalesce(t.agent_type,'') " +
	"FROM paging LEFT JOIN selected r ON true " +
	"LEFT JOIN LATERAL (SELECT (SELECT count(*) FROM tenant_profiles WHERE profile_id=r.parent_id) AS tenants,coalesce((SELECT min(tenant_id) FROM tenant_profiles WHERE profile_id=r.parent_id),0) AS tenant_id,(SELECT count(*) FROM site_profiles WHERE profile_id=r.parent_id) AS sites,coalesce((SELECT min(site_id) FROM site_profiles WHERE profile_id=r.parent_id),0) AS site_id) audience ON true " +
	"LEFT JOIN profiles p ON p.id=r.parent_id AND ((audience.tenants=0 AND audience.sites=0) OR (audience.tenants=1 AND audience.tenant_id=$2 AND (audience.sites=0 OR (audience.sites=1 AND audience.site_id=$3)))) " +
	"LEFT JOIN tasks t ON t.id=r.task_reports AND t.profile_tasks=p.id " +
	"ORDER BY r.issue_time DESC NULLS LAST,r.id DESC"
