package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

const ProfileIssueReportPageSize = 25

type ProfileIssueSummary struct {
	ID                                      int64
	When                                    *time.Time
	Error                                   string
	ErrorTruncated                          bool
	EndpointID, EndpointName, EndpointState string
	EndpointScope                           access.Scope
	Reports, Failed                         int
}

type ProfileIssuesPage struct {
	ProfileID             int64
	ProfileName           string
	Page, PageSize, Total int
	Issues                []ProfileIssueSummary
}

type ProfileIssueReport struct {
	ID, TaskID                      int64
	TaskName                        string
	TaskDisabled, Failed            bool
	Output, Error, RawEnd           string
	OutputTruncated, ErrorTruncated bool
	End                             *time.Time
}

type ProfileIssueReportsPage struct {
	ProfileID   int64
	ProfileName string
	Issue       ProfileIssueSummary
	Page, Total int
	Reports     []ProfileIssueReport
}

// History belongs to its exact profile, including records whose endpoint or
// current task no longer exists. Reads never perform orphan cleanup.
func ReadLegacyProfileIssues(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, page, size int) (*ProfileIssuesPage, error) {
	if page <= 0 || page > 1000000 || size <= 0 || size > 100 {
		return nil, ErrProfileInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = lockProfileIssueHistory(ctx, tx, profileID); err != nil {
		return nil, err
	}
	result := &ProfileIssuesPage{ProfileID: profileID, Page: page, PageSize: size, Issues: []ProfileIssueSummary{}}
	if err = tx.QueryRowContext(ctx, `SELECT coalesce(left(name,512),''),(SELECT count(*) FROM profile_issues WHERE profile_issues=$1) FROM profiles WHERE id=$1`, profileID).Scan(&result.ProfileName, &result.Total); err != nil {
		return nil, err
	}
	result.Page = min(page, max(1, (result.Total+size-1)/size))
	rows, err := tx.QueryContext(ctx, profileIssueSummarySQL+` WHERE i.profile_issues=$1 ORDER BY i."when" DESC NULLS LAST,i.id DESC OFFSET $4 LIMIT $5`, profileID, scope.TenantID, scope.SiteID, (result.Page-1)*size, size)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		item, err := scanProfileIssueSummary(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		result.Issues = append(result.Issues, item)
	}
	if err = finishProfileIssueRows(rows); err != nil {
		return nil, err
	}
	if err = commitProfileIssueRead(ctx, tx, actor, scope, "inventory.profile_issues.list", fmt.Sprintf("%d/page/%d/size/%d", profileID, result.Page, size)); err != nil {
		return nil, err
	}
	return result, nil
}

func ReadLegacyProfileIssueReports(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID, issueID int64, page int) (*ProfileIssueReportsPage, error) {
	if issueID <= 0 || page <= 0 || page > 1000000 {
		return nil, ErrProfileInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = lockProfileIssueHistory(ctx, tx, profileID); err != nil {
		return nil, err
	}
	result := &ProfileIssueReportsPage{ProfileID: profileID, Page: page, Reports: []ProfileIssueReport{}}
	result.Issue, err = scanProfileIssueSummary(tx.QueryRowContext(ctx, profileIssueSummarySQL+` WHERE i.profile_issues=$1 AND i.id=$4`, profileID, scope.TenantID, scope.SiteID, issueID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT coalesce(left(name,512),'') FROM profiles WHERE id=$1`, profileID).Scan(&result.ProfileName); err != nil {
		return nil, err
	}
	result.Total = result.Issue.Reports
	result.Page = min(page, max(1, (result.Total+ProfileIssueReportPageSize-1)/ProfileIssueReportPageSize))
	// Lock referenced current task rows before the label query. Labels/links are
	// exposed only when the task still belongs to the reviewed profile.
	locked, err := tx.QueryContext(ctx, `SELECT t.id FROM tasks t JOIN task_reports r ON r.task_reports=t.id WHERE r.profile_issue_tasksreports=$1 ORDER BY t.id FOR SHARE OF t`, issueID)
	if err != nil {
		return nil, err
	}
	for locked.Next() {
	}
	if err = finishProfileIssueRows(locked); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.id,CASE WHEN t.profile_tasks=$2 THEN t.id ELSE 0 END,CASE WHEN t.profile_tasks=$2 THEN coalesce(left(t.name,512),'') ELSE '' END,CASE WHEN t.profile_tasks=$2 THEN coalesce(t.disabled,false) ELSE false END,r.failed,coalesce(left(r.std_output,4096),''),coalesce(left(r.std_error,4096),''),coalesce(char_length(r.std_output)>4096,false),coalesce(char_length(r.std_error)>4096,false),coalesce(left(r."end",128),'') FROM task_reports r LEFT JOIN tasks t ON t.id=r.task_reports WHERE r.profile_issue_tasksreports=$1 ORDER BY r.id OFFSET $3 LIMIT 25`, issueID, profileID, (result.Page-1)*ProfileIssueReportPageSize)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var report ProfileIssueReport
		if err = rows.Scan(&report.ID, &report.TaskID, &report.TaskName, &report.TaskDisabled, &report.Failed, &report.Output, &report.Error, &report.OutputTruncated, &report.ErrorTruncated, &report.RawEnd); err != nil {
			rows.Close()
			return nil, err
		}
		if parsed, err := time.Parse(time.RFC3339Nano, report.RawEnd); err == nil {
			report.End = &parsed
		}
		result.Reports = append(result.Reports, report)
	}
	if err = finishProfileIssueRows(rows); err != nil {
		return nil, err
	}
	if err = commitProfileIssueRead(ctx, tx, actor, scope, "inventory.profile_issues.read", fmt.Sprintf("%d/issue/%d/page/%d", profileID, issueID, result.Page)); err != nil {
		return nil, err
	}
	return result, nil
}

// Endpoint links follow the endpoint's current unique site. Foreign/ambiguous
// endpoint associations do not disclose current identity through a scoped
// profile. Their historical issue remains visible to the profile administrator.
const profileIssueSummarySQL = `SELECT i.id,i."when",coalesce(left(i.error,1024),''),coalesce(char_length(i.error)>1024,false),
 CASE WHEN membership.visible THEN coalesce(a.oid,'') ELSE '' END,CASE WHEN membership.visible THEN coalesce(left(a.nickname,256),'') ELSE '' END,
 CASE WHEN a.oid IS NULL THEN 'missing' WHEN membership.visible THEN 'available' ELSE 'unavailable' END,
 CASE WHEN membership.visible THEN membership.tenant_id ELSE 0 END,CASE WHEN membership.visible THEN membership.site_id ELSE 0 END,
 (SELECT count(*) FROM task_reports r WHERE r.profile_issue_tasksreports=i.id),(SELECT count(*) FROM task_reports r WHERE r.profile_issue_tasksreports=i.id AND r.failed)
 FROM profile_issues i LEFT JOIN agents a ON a.oid=i.profile_issue_agents
 LEFT JOIN LATERAL (SELECT s.tenant_sites AS tenant_id,s.id AS site_id,((SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 AND ($2::bigint=0 OR s.tenant_sites=$2) AND ($3::bigint=0 OR s.id=$3)) AS visible FROM site_agents sa JOIN sites s ON s.id=sa.site_id JOIN tenants org ON org.id=s.tenant_sites WHERE sa.agent_id=a.oid ORDER BY s.id LIMIT 1) membership ON true`

type profileIssueScanner interface{ Scan(...any) error }

func scanProfileIssueSummary(row profileIssueScanner) (ProfileIssueSummary, error) {
	var issue ProfileIssueSummary
	var when sql.NullTime
	err := row.Scan(&issue.ID, &when, &issue.Error, &issue.ErrorTruncated, &issue.EndpointID, &issue.EndpointName, &issue.EndpointState, &issue.EndpointScope.TenantID, &issue.EndpointScope.SiteID, &issue.Reports, &issue.Failed)
	if when.Valid {
		issue.When = &when.Time
	}
	if issue.EndpointState == "available" && !ValidReportDeviceID(issue.EndpointID) {
		issue.EndpointID = ""
		issue.EndpointName = ""
		issue.EndpointScope = access.Scope{}
		issue.EndpointState = "unavailable"
	}
	return issue, err
}

func lockProfileIssueHistory(ctx context.Context, tx *sql.Tx, profileID int64) error {
	// Parent UPDATE prevents incoming issues. Issue UPDATE prevents incoming
	// reports; held report rows preserve counts, outputs and historical outcomes.
	// The membership lock also covers extra endpoint sites outside this profile.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE site_agents IN SHARE MODE`); err != nil {
		return err
	}
	for _, query := range []string{
		`SELECT id FROM profile_issues WHERE profile_issues=$1 ORDER BY id FOR UPDATE`,
		`SELECT r.id FROM task_reports r JOIN profile_issues i ON i.id=r.profile_issue_tasksreports WHERE i.profile_issues=$1 ORDER BY r.id FOR SHARE OF r`,
		`SELECT a.oid FROM agents a JOIN profile_issues i ON i.profile_issue_agents=a.oid WHERE i.profile_issues=$1 ORDER BY a.oid FOR SHARE OF a`,
		`SELECT s.id FROM sites s JOIN site_agents sa ON sa.site_id=s.id JOIN profile_issues i ON i.profile_issue_agents=sa.agent_id WHERE i.profile_issues=$1 ORDER BY s.id FOR SHARE OF s`,
		`SELECT org.id FROM tenants org JOIN sites s ON s.tenant_sites=org.id JOIN site_agents sa ON sa.site_id=s.id JOIN profile_issues i ON i.profile_issue_agents=sa.agent_id WHERE i.profile_issues=$1 ORDER BY org.id FOR SHARE OF org`,
	} {
		rows, err := tx.QueryContext(ctx, query, profileID)
		if err != nil {
			return err
		}
		for rows.Next() {
		}
		if err = finishProfileIssueRows(rows); err != nil {
			return err
		}
	}
	return nil
}

func finishProfileIssueRows(rows *sql.Rows) error {
	err := rows.Err()
	closed := rows.Close()
	if err != nil {
		return err
	}
	return closed
}
func commitProfileIssueRead(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, action, resource string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, action, resource); err != nil {
		return err
	}
	return tx.Commit()
}
