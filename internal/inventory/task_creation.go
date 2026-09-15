package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats/tasksecrets"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskconfig"
)

var ErrTaskSecretStorage = errors.New("task secret storage is unavailable")

type TaskCreationReview struct {
	ProfileID     int64
	ProfileName   string
	NameTruncated bool
}

func ReviewTaskCreation(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64) (*TaskCreationReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	review := &TaskCreationReview{ProfileID: profileID}
	if err = tx.QueryRowContext(ctx, `SELECT left(name,512),char_length(name)>512 FROM profiles WHERE id=$1`, profileID).Scan(&review.ProfileName, &review.NameTruncated); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.create_review',$4)`, scope.TenantID, scope.SiteID, actor, fmt.Sprint(profileID)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return review, nil
}

func CreateLegacyTask(parent context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, profileID int64, cfg taskconfig.Config, masterKey string) (int64, error) {
	if !cfg.Supported() || !(ProfileMetadata{Name: cfg.Description, Assignment: "dontApplyToAll"}).Valid() {
		return 0, ErrTaskInvalid
	}
	if cfg.TaskType == task.TypeNetbirdRegister.String() && scope.TenantID == 0 {
		return 0, ErrProfileCloneProviderScope
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := beginLegacyProfileTransaction(ctx, db, permissions, actor, scope, profileID)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if cfg.LocalUserPassword != "" {
		if masterKey == "" {
			return 0, ErrTaskSecretStorage
		}
		cfg.LocalUserPassword, err = tasksecrets.SealPassword(cfg.LocalUserPassword, masterKey)
		if err != nil {
			return 0, ErrTaskSecretStorage
		}
	}
	if cfg.LocalUserSSHKeyPassphrase != "" {
		cfg.LocalUserSSHKeyPassphrase, err = tasksecrets.SealSSH(cfg.LocalUserSSHKeyPassphrase, masterKey)
		if err != nil {
			return 0, ErrTaskSecretStorage
		}
	}
	if err = lockProfileTasks(ctx, tx, profileID, true); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `WITH ranked AS (SELECT id,row_number() OVER (ORDER BY "order",id) position FROM tasks WHERE profile_tasks=$1) UPDATE tasks t SET "order"=r.position FROM ranked r WHERE t.id=r.id AND t.profile_tasks=$1`, profileID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	// The factory inserts one row with its M2O parent FK and no external edges.
	// Ent's single-statement create uses this held transaction directly. Do not
	// close this client or begin an Ent transaction on its SQL-transaction driver.
	client := ent.NewClient(ent.Driver(entsql.NewDriver(dialect.Postgres, entsql.Conn{ExecQuerier: tx})))
	created, err := taskconfig.Create(ctx, client, int(profileID), scope.TenantID, int(count+1), cfg)
	if err != nil {
		if errors.Is(err, taskconfig.ErrInvalid) || ent.IsValidationError(err) {
			return 0, ErrTaskInvalid
		}
		return 0, err
	}
	resource := fmt.Sprintf("%d/profile/%d/position/%d", created.ID, profileID, count+1)
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.tasks.create',$4)`, scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return int64(created.ID), nil
}
