package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Each source exposes only identifiers and outcome metadata. Configuration,
// command payloads, grant documents, credentials and arbitrary JSON stay out.
type auditSource struct{ name, table, query string }

var sourceQueries = append([]auditSource{
	{"apple", "mdm_apple_audit", `SELECT id,tenant_id,CASE WHEN details->>'site_id' ~ '^[0-9]{1,18}$' THEN (details->>'site_id')::bigint ELSE 0 END AS site_id,actor,action,resource_id AS resource,CASE WHEN details->>'result' IN ('success','failure','denied','deferred','cancelled') THEN details->>'result' ELSE 'recorded' END AS result,created_at FROM mdm_apple_audit`},
	{"agent", "uem_agent_audit", `SELECT id,tenant_id,COALESCE(site_id,0) AS site_id,actor,action,resource_id::text AS resource,'recorded'::text AS result,created_at FROM uem_agent_audit`},
	{"inventory", "uem_inventory_audit", `SELECT id,tenant_id,site_id,actor,action,resource_id AS resource,'recorded'::text AS result,created_at FROM uem_inventory_audit`},
	{"inventory-refresh", "uem_inventory_refresh_audit", `SELECT id,tenant_id,site_id,actor,action,resource_id AS resource,result,created_at FROM uem_inventory_refresh_audit`},
	{"access", "uem_access_audit", `SELECT id,0::bigint AS tenant_id,0::bigint AS site_id,actor,action,subject AS resource,'recorded'::text AS result,created_at FROM uem_access_audit`},
	{"release", "uem_desktop_release_audit", `SELECT id,0::bigint AS tenant_id,0::bigint AS site_id,actor,action,digest AS resource,'recorded'::text AS result,created_at FROM uem_desktop_release_audit`},
	{"activity", "uem_audit_activity", `SELECT id,tenant_id,site_id,actor,action,resource_id AS resource,result,created_at FROM uem_audit_activity`},
	{"retention", "uem_audit_retention_history", `SELECT id,tenant_id,0::bigint AS site_id,actor,action,'organization:'||tenant_id::text AS resource,'success'::text AS result,created_at FROM uem_audit_retention_history`},
}, windowsSources...)

func availableSources(ctx context.Context, tx *sql.Tx) ([]bool, error) {
	available := make([]bool, len(sourceQueries))
	parts := make([]string, len(sourceQueries))
	values := make([]any, len(sourceQueries))
	for i, source := range sourceQueries {
		parts[i] = "to_regclass('" + source.table + "') IS NOT NULL"
		values[i] = &available[i]
	}
	err := tx.QueryRowContext(ctx, "SELECT "+strings.Join(parts, ",")).Scan(values...)
	return available, err
}

func selectEvents(ctx context.Context, tx *sql.Tx, f Filter, c cursor, limit int) ([]Event, []string, error) {
	available, err := availableSources(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	parts, sources := []string{}, []string{}
	for i, source := range sourceQueries {
		if !available[i] {
			continue
		}
		if f.Scope.TenantID != 0 && (source.name == "access" || source.name == "release") {
			continue
		}
		sources = append(sources, source.name)
		if f.Source != "" && f.Source != source.name {
			continue
		}
		// Names and SQL fragments are compile-time constants, never request data.
		query := fmt.Sprintf(`(SELECT id,'%s'::text AS source,tenant_id,site_id,
 CASE WHEN octet_length(actor)<=1024 THEN actor ELSE '[oversized actor omitted]' END AS actor,
 CASE WHEN octet_length(action)<=1024 THEN action ELSE '[oversized action omitted]' END AS action,
 CASE WHEN octet_length(resource)<=2048 THEN resource ELSE '[oversized resource omitted]' END AS resource,
 result,created_at FROM (%s) e
 WHERE ($1::bigint=0 OR tenant_id=$1) AND ($2::bigint=0 OR site_id=$2)
 AND created_at>=$3 AND created_at<$4 AND ($5::text='' OR actor=$5)
 AND ($6::text='' OR action=$6) AND ($7::text='' OR resource=$7)
 AND ($8::text='' OR result=$8)
 AND (created_at,'%s'::text COLLATE "C",id)<($9,$10::text COLLATE "C",$11)
 ORDER BY created_at DESC,id DESC LIMIT $12)`, source.name, source.query, source.name)
		parts = append(parts, query)
	}
	if len(parts) == 0 {
		return []Event{}, sources, nil
	}
	query := `SELECT * FROM (` + strings.Join(parts, " UNION ALL ") + `) combined ORDER BY created_at DESC,source COLLATE "C" DESC,id DESC LIMIT $12`
	rows, err := tx.QueryContext(ctx, query, f.Scope.TenantID, f.Scope.SiteID, f.From.UTC(), f.Until.UTC(), f.Actor, f.Action, f.Resource, f.Result, c.At.UTC(), c.Source, c.ID, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.Source, &e.TenantID, &e.SiteID, &e.Actor, &e.Action, &e.Resource, &e.Result, &e.CreatedAt); err != nil {
			return nil, nil, err
		}
		events = append(events, e)
	}
	return events, sources, rows.Err()
}

func recordActivity(ctx context.Context, tx *sql.Tx, actor, action, result string, f Filter, count int) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_audit_activity(tenant_id,site_id,actor,action,resource_id,result,event_count) VALUES($1,$2,$3,$4,$5,$6,$7)`, f.Scope.TenantID, f.Scope.SiteID, actor, action, f.digest(), result, count)
	return err
}

func (s *Store) List(ctx context.Context, actor string, f Filter, encoded string) (*Page, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	c, err := decodeCursor(f, encoded)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorize(ctx, tx, actor, f.Scope); err != nil {
		return nil, err
	}
	events, sources, err := selectEvents(ctx, tx, f, c, 101)
	if err != nil {
		return nil, err
	}
	page := &Page{Events: events, Sources: sources}
	if len(events) > 100 {
		page.Events = events[:100]
		page.Next = encodeCursor(f, page.Events[99])
	}
	if err = recordActivity(ctx, tx, actor, "audit.view", "success", f, len(page.Events)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
