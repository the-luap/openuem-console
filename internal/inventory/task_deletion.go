package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type TaskDeletionReview struct {
	ID            int64
	ProfileID     int64
	Name          string
	NameTruncated bool
}

func ReviewTaskDeletion(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID, taskID int64) (*TaskDeletionReview, error) {
	if profileID <= 0 {
		return nil, ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, owner, err := beginLegacyTaskTransaction(ctx, db, permissions, actor, scope, taskID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if owner != profileID {
		return nil, ErrNotFound
	}
	review := &TaskDeletionReview{ID: taskID, ProfileID: owner}
	if err = tx.QueryRowContext(ctx, `SELECT coalesce(left(name,512),''),coalesce(char_length(name)>512,false) FROM tasks WHERE id=$1 AND profile_tasks=$2`, taskID, owner).Scan(&review.Name, &review.NameTruncated); err != nil {
		return nil, err
	}
	resource := fmt.Sprintf("%d/profile/%d", taskID, owner)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.delete_review',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return review, nil
}

func DeleteLegacyTask(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID, taskID int64) error {
	if profileID <= 0 {
		return ErrTaskInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, owner, err := beginLegacyTaskTransaction(ctx, db, permissions, actor, scope, taskID)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Bind the mutation to the parent shown during review, even if the task has
	// since moved to another profile with the same audience.
	if owner != profileID {
		return ErrNotFound
	}
	if err = lockProfileTasks(ctx, tx, owner, true); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM tasks WHERE id=$1 AND profile_tasks=$2`, taskID, owner)
	if err != nil {
		return err
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if removed != 1 {
		return ErrNotFound
	}
	result, err = tx.ExecContext(ctx, `WITH ranked AS (SELECT id,row_number() OVER (ORDER BY "order",id) AS position FROM tasks WHERE profile_tasks=$1) UPDATE tasks t SET "order"=r.position FROM ranked r WHERE t.id=r.id AND t.profile_tasks=$1`, owner)
	if err != nil {
		return err
	}
	remaining, err := result.RowsAffected()
	if err != nil {
		return err
	}
	resource := fmt.Sprintf("%d/profile/%d/remaining/%d", taskID, owner, remaining)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.delete',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return err
	}
	return tx.Commit()
}
