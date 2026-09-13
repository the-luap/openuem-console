package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type ProfileDeletionReview struct {
	ID            int64
	Name          string
	NameTruncated bool
}

func ReviewProfileDeletion(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64) (*ProfileDeletionReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	review := &ProfileDeletionReview{ID: profileID}
	if err = tx.QueryRowContext(ctx, `SELECT left(name,512),char_length(name)>512 FROM profiles WHERE id=$1`, profileID).Scan(&review.Name, &review.NameTruncated); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return review, nil
}

func DeleteLegacyProfile(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileAudienceTransaction(ctx, db, permissions, actor, scope, profileID, true)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM tasks WHERE profile_tasks=$1`, profileID)
	if err != nil {
		return err
	}
	tasks, err := result.RowsAffected()
	if err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM profiles WHERE id=$1`, profileID)
	if err != nil {
		return err
	}
	profiles, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if profiles != 1 {
		return ErrNotFound
	}
	resource := fmt.Sprintf("%d/tasks/%d", profileID, tasks)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.profiles.delete',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return err
	}
	return tx.Commit()
}
