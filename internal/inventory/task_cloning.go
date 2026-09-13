package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type TaskCloneTarget struct {
	ID           int64
	Name         string
	Scope        access.Scope
	Organization string
	Site         string
}

type TaskCloneReview struct {
	ID        int64
	ProfileID int64
	Name      string
	Targets   []TaskCloneTarget
	HasMore   bool
}

// A zero expected parent is allowed only for the initial review. Follow-up
// target searches bind to the parent already displayed in the clone form.
func ReviewTaskClone(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, taskID, expectedParent int64, query string) (*TaskCloneReview, error) {
	if expectedParent < 0 || len(query) > 256 || !utf8.ValidString(query) || strings.ContainsRune(query, 0) {
		return nil, ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, owner, err := beginLegacyTaskTransaction(ctx, db, permissions, actor, scope, taskID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if expectedParent != 0 && owner != expectedParent {
		return nil, ErrNotFound
	}
	review := &TaskCloneReview{ID: taskID, ProfileID: owner, Targets: []TaskCloneTarget{}}
	var oversized bool
	if err = tx.QueryRowContext(ctx, `SELECT coalesce(left(name,2048),''),coalesce(octet_length(name)>2048,false) FROM tasks WHERE id=$1 AND profile_tasks=$2`, taskID, owner).Scan(&review.Name, &oversized); err != nil {
		return nil, err
	}
	if oversized || !(ProfileMetadata{Name: review.Name, Assignment: "dontApplyToAll"}).Valid() {
		review.Name = ""
	}
	// Exclude ambiguous audiences and orphaned/inconsistent organization/site
	// associations. Search is literal text (or an exact ID), limited to 50 choices.
	rows, err := tx.QueryContext(ctx, `SELECT p.id,CASE WHEN char_length(p.name)>512 THEN left(p.name,512)||'…' ELSE p.name END,coalesce(ta.tenant_id,0),coalesce(sa.site_id,0),coalesce(left(t.description,128),''),coalesce(left(s.description,128),'')
FROM profiles p
LEFT JOIN LATERAL (SELECT count(*) n,min(tenant_id) tenant_id FROM tenant_profiles WHERE profile_id=p.id) ta ON true
LEFT JOIN LATERAL (SELECT count(*) n,min(site_id) site_id FROM site_profiles WHERE profile_id=p.id) sa ON true
LEFT JOIN tenants t ON t.id=ta.tenant_id LEFT JOIN sites s ON s.id=sa.site_id
WHERE ta.n<=1 AND sa.n<=1 AND (ta.n=0 OR t.id IS NOT NULL) AND (sa.n=0 OR (ta.n=1 AND s.tenant_sites=ta.tenant_id))
AND ($1='' OR CASE WHEN $1 ~ '^[1-9][0-9]*$' THEN p.id::text=$1 ELSE position(lower($1) in lower(p.name))>0 END)
ORDER BY lower(p.name),p.id LIMIT 51`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry TaskCloneTarget
		if err = rows.Scan(&entry.ID, &entry.Name, &entry.Scope.TenantID, &entry.Scope.SiteID, &entry.Organization, &entry.Site); err != nil {
			return nil, err
		}
		review.Targets = append(review.Targets, entry)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if len(review.Targets) > 50 {
		review.HasMore = true
		review.Targets = review.Targets[:50]
	}
	resource := fmt.Sprintf("%d/profile/%d/targets/%d", taskID, owner, len(review.Targets))
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.clone_review',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return review, nil
}

func CloneLegacyTask(parent context.Context, db *sql.DB, permissions *access.Store, actor string, source, destination access.Scope, sourceProfile, taskID, targetProfile int64, name string) (int64, error) {
	if sourceProfile <= 0 || taskID <= 0 || targetProfile <= 0 || !(ProfileMetadata{Name: name, Assignment: "dontApplyToAll"}).Valid() {
		return 0, ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileScopeTransaction(ctx, db, permissions, actor, source)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = lockProfileCloneDestination(ctx, tx, destination); err != nil {
		return 0, err
	}
	// Acquire the write-compatible audience lock before either parent row. This
	// serializes opposite-direction clones without upgrading a shared table lock.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE tenant_profiles,site_profiles IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return 0, err
	}
	parents := []struct {
		id    int64
		scope access.Scope
	}{{sourceProfile, source}, {targetProfile, destination}}
	if sourceProfile > targetProfile {
		parents[0], parents[1] = parents[1], parents[0]
	}
	for _, p := range parents {
		if err = lockLegacyProfileAudience(ctx, tx, p.scope, p.id, true); err != nil {
			return 0, err
		}
	}
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM tasks WHERE id=$1 AND profile_tasks=$2 FOR SHARE`, taskID, sourceProfile).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if err = lockProfileTasks(ctx, tx, targetProfile, true); err != nil {
		return 0, err
	}
	var incompatible bool
	if err = tx.QueryRowContext(ctx, `SELECT type='netbird_register' AND (tenant IS NULL OR tenant<=0 OR tenant!=$2) FROM tasks WHERE id=$1`, taskID, destination.TenantID).Scan(&incompatible); err != nil {
		return 0, err
	}
	if incompatible {
		return 0, ErrProfileCloneProviderScope
	}
	result, err := tx.ExecContext(ctx, `WITH ranked AS (SELECT id,row_number() OVER (ORDER BY "order",id) position FROM tasks WHERE profile_tasks=$1) UPDATE tasks t SET "order"=r.position FROM ranked r WHERE t.id=r.id AND t.profile_tasks=$1`, targetProfile)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	fields := legacyTaskCopyFields(true)
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO tasks (`+fields+`,name,version,"order",profile_tasks) SELECT `+fields+`,$3,1,$4,$5 FROM tasks WHERE id=$1 AND profile_tasks=$2 RETURNING id`, taskID, sourceProfile, name, count+1, targetProfile).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	resource := fmt.Sprintf("%d/from/%d/%d/%d/%d/to/%d/%d/%d/position/%d", id, taskID, sourceProfile, source.TenantID, source.SiteID, targetProfile, destination.TenantID, destination.SiteID, count+1)
	scopes := []access.Scope{source}
	if source != destination {
		scopes = append(scopes, destination)
	}
	for _, scope := range scopes {
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.clone',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}
