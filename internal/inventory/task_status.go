package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrTaskInvalid = errors.New("invalid legacy profile task")

func beginLegacyTaskTransaction(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, taskID int64) (*sql.Tx, int64, error) {
	if taskID <= 0 {
		return nil, 0, ErrTaskInvalid
	}
	tx, err := beginLegacyProfileScopeTransaction(ctx, db, permissions, actor, scope)
	if err != nil {
		return nil, 0, err
	}
	fail := func(err error) (*sql.Tx, int64, error) { tx.Rollback(); return nil, 0, err }
	var parent sql.NullInt64
	err = tx.QueryRowContext(ctx, "SELECT profile_tasks FROM tasks WHERE id=$1", taskID).Scan(&parent)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(ErrNotFound)
	}
	if err != nil {
		return fail(err)
	}
	if !parent.Valid || parent.Int64 <= 0 {
		return fail(ErrNotFound)
	}
	// Keep the profile-before-task lock order used by profile cloning/deletion.
	// Parent discovery is only a candidate: recheck task ownership after locking
	// that parent's complete current audience and profile row.
	if err = lockLegacyProfileAudience(ctx, tx, scope, parent.Int64, false); err != nil {
		return fail(err)
	}
	var current int64
	err = tx.QueryRowContext(ctx, "SELECT id FROM tasks WHERE id=$1 AND profile_tasks=$2 FOR UPDATE", taskID, parent.Int64).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(ErrNotFound)
	}
	if err != nil {
		return fail(err)
	}
	return tx, parent.Int64, nil
}

func SetTaskEnabled(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, taskID int64, enabled bool) (int64, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, profileID, err := beginLegacyTaskTransaction(ctx, db, permissions, actor, scope, taskID)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET disabled=$1 WHERE id=$2 AND profile_tasks=$3", !enabled, taskID, profileID); err != nil {
		return 0, err
	}
	action := "inventory.tasks.disable"
	if enabled {
		action = "inventory.tasks.enable"
	}
	resource := fmt.Sprintf("%d/profile/%d", taskID, profileID)
	if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,$4,$5)", scope.TenantID, scope.SiteID, actor, action, resource); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return profileID, nil
}
