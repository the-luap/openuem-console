package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrTaskOrderChanged = errors.New("task position has changed")

// The held parent lock prevents incoming task foreign keys. Lock existing rows
// before counting, reading or changing their order, without loading task values.
func lockProfileTasks(ctx context.Context, tx *sql.Tx, profileID int64, write bool) error {
	query := "SELECT id FROM tasks WHERE profile_tasks=$1 ORDER BY id FOR SHARE"
	if write {
		query = "SELECT id FROM tasks WHERE profile_tasks=$1 ORDER BY id FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, query, profileID)
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	err = rows.Err()
	closed := rows.Close()
	if err != nil {
		return err
	}
	return closed
}

func ReorderLegacyTask(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, taskID, from, to int64) (int64, error) {
	if from <= 0 || to <= 0 {
		return 0, ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, profileID, err := beginLegacyTaskTransaction(ctx, db, permissions, actor, scope, taskID)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = lockProfileTasks(ctx, tx, profileID, true); err != nil {
		return 0, err
	}
	var current, count int64
	err = tx.QueryRowContext(ctx, `SELECT position,total FROM (SELECT id,row_number() OVER (ORDER BY "order",id) AS position,count(*) OVER () AS total FROM tasks WHERE profile_tasks=$1) ranked WHERE id=$2`, profileID, taskID).Scan(&current, &count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if current != from {
		return 0, ErrTaskOrderChanged
	}
	if to > count {
		return 0, ErrTaskInvalid
	}
	result, err := tx.ExecContext(ctx, `WITH ranked AS (SELECT id,row_number() OVER (ORDER BY "order",id) AS position FROM tasks WHERE profile_tasks=$1)
UPDATE tasks t SET "order"=CASE WHEN t.id=$2 THEN $4::bigint WHEN $3::bigint<$4::bigint AND r.position>$3::bigint AND r.position<=$4::bigint THEN r.position-1 WHEN $3::bigint>$4::bigint AND r.position>=$4::bigint AND r.position<$3::bigint THEN r.position+1 ELSE r.position END
FROM ranked r WHERE t.id=r.id AND t.profile_tasks=$1`, profileID, taskID, from, to)
	if err != nil {
		return 0, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if changed != count {
		return 0, ErrTaskOrderChanged
	}
	resource := fmt.Sprintf("%d/profile/%d/from/%d/to/%d/tasks/%d", taskID, profileID, from, to, count)
	if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.reorder',$4)", scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return profileID, nil
}

type LegacyTaskPage struct {
	ProfileID int64
	Total     int
	Page      int
	PageSize  int
	Tasks     []*ent.Task
}

func ReadLegacyTaskPage(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, page, size int) (*LegacyTaskPage, error) {
	if page <= 0 || page > 1000000 || size <= 0 || size > 1000 {
		return nil, ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = lockProfileTasks(ctx, tx, profileID, false); err != nil {
		return nil, err
	}
	result := &LegacyTaskPage{ProfileID: profileID, Page: page, PageSize: size, Tasks: []*ent.Task{}}
	err = tx.QueryRowContext(ctx, "SELECT count(*) FROM tasks WHERE profile_tasks=$1", profileID).Scan(&result.Total)
	if err != nil {
		return nil, err
	}
	last := max(1, (result.Total+size-1)/size)
	result.Page = min(page, last)
	offset := (result.Page - 1) * size
	// Load bounded display summaries only; scripts and credentials never enter
	// this page result. An ellipsis identifies a shortened legacy value.
	rows, err := tx.QueryContext(ctx, `SELECT id,type,coalesce(version,0),disabled,coalesce(agent_type,''),CASE WHEN char_length(name)>512 THEN left(name,512)||'…' ELSE coalesce(name,'') END,CASE WHEN char_length(package_name)>512 THEN left(package_name,512)||'…' ELSE coalesce(package_name,'') END,CASE WHEN char_length(package_version)>512 THEN left(package_version,512)||'…' ELSE coalesce(package_version,'') END,CASE WHEN char_length(registry_key)>512 THEN left(registry_key,512)||'…' ELSE coalesce(registry_key,'') END,CASE WHEN char_length(registry_key_value_name)>512 THEN left(registry_key_value_name,512)||'…' ELSE coalesce(registry_key_value_name,'') END,CASE WHEN char_length(local_user_username)>512 THEN left(local_user_username,512)||'…' ELSE coalesce(local_user_username,'') END,CASE WHEN char_length(local_group_name)>512 THEN left(local_group_name,512)||'…' ELSE coalesce(local_group_name,'') END,CASE WHEN char_length(local_group_members)>512 THEN left(local_group_members,512)||'…' ELSE coalesce(local_group_members,'') END,CASE WHEN char_length(local_group_members_to_include)>512 THEN left(local_group_members_to_include,512)||'…' ELSE coalesce(local_group_members_to_include,'') END,CASE WHEN char_length(local_group_members_to_exclude)>512 THEN left(local_group_members_to_exclude,512)||'…' ELSE coalesce(local_group_members_to_exclude,'') END,CASE WHEN char_length(msi_productid)>512 THEN left(msi_productid,512)||'…' ELSE coalesce(msi_productid,'') END FROM tasks WHERE profile_tasks=$1 ORDER BY "order",id OFFSET $2 LIMIT $3`, profileID, offset, size)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		entry := &ent.Task{}
		if err = rows.Scan(&entry.ID, &entry.Type, &entry.Version, &entry.Disabled, &entry.AgentType, &entry.Name, &entry.PackageName, &entry.PackageVersion, &entry.RegistryKey, &entry.RegistryKeyValueName, &entry.LocalUserUsername, &entry.LocalGroupName, &entry.LocalGroupMembers, &entry.LocalGroupMembersToInclude, &entry.LocalGroupMembersToExclude, &entry.MsiProductid); err != nil {
			return nil, err
		}
		entry.Order = offset + len(result.Tasks) + 1
		result.Tasks = append(result.Tasks, entry)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	resource := fmt.Sprintf("%d/page/%d/size/%d", profileID, result.Page, size)
	if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.list',$4)", scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
