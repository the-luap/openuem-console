package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/open-uem/nats/tasksecrets"
)

var ErrTaskSecretMigration = errors.New("task secret migration is incomplete")

// MigrateTaskSecrets runs only during console startup, after audit migrations
// and before task dispatch or HTTP handlers start. Deploy compatible workers
// first. Representation changes preserve task version, ordering and audiences.
// Each bounded batch commits with its audit entries; restart verifies already
// sealed values and resumes remaining work without double encryption.
func MigrateTaskSecrets(ctx context.Context, db *sql.DB, masterKey string) error {
	var upper int64
	if err := db.QueryRowContext(ctx, "SELECT coalesce(max(id),0) FROM tasks").Scan(&upper); err != nil {
		return ErrTaskSecretMigration
	}
	var after int64
	for after < upper {
		next, count, err := migrateTaskSecretBatch(ctx, db, masterKey, after, upper)
		if err != nil {
			return err
		}
		if count == 0 {
			break
		}
		after = next
	}
	return nil
}

func migrateTaskSecretBatch(ctx context.Context, db *sql.DB, masterKey string, after, upper int64) (int64, int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return after, 0, ErrTaskSecretMigration
	}
	defer tx.Rollback()
	// Do not transfer oversized legacy values into application memory. Invalid
	// rows remain locked and cause the whole current batch to roll back.
	rows, err := tx.QueryContext(ctx, `SELECT id,
 coalesce(octet_length(local_user_password),0)<=$3 AND coalesce(octet_length(local_user_ssh_key_passphrase),0)<=$4,
 CASE WHEN octet_length(local_user_password)<=$3 THEN local_user_password END,
 CASE WHEN octet_length(local_user_ssh_key_passphrase)<=$4 THEN local_user_ssh_key_passphrase END
 FROM tasks WHERE id>$1 AND id<=$2 AND (coalesce(local_user_password,'')<>'' OR coalesce(local_user_ssh_key_passphrase,'')<>'') ORDER BY id LIMIT 64 FOR UPDATE`, after, upper, tasksecrets.MaxPasswordStoredSize, tasksecrets.MaxSSHStoredSize)
	if err != nil {
		return after, 0, ErrTaskSecretMigration
	}
	type entry struct {
		id            int64
		bounded       bool
		password, ssh sql.NullString
	}
	batch := make([]entry, 0, 64)
	for rows.Next() {
		var current entry
		if err = rows.Scan(&current.id, &current.bounded, &current.password, &current.ssh); err != nil {
			rows.Close()
			return after, 0, ErrTaskSecretMigration
		}
		batch = append(batch, current)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return after, 0, ErrTaskSecretMigration
	}
	for _, current := range batch {
		failure := fmt.Errorf("%w at task %d", ErrTaskSecretMigration, current.id)
		if !current.bounded {
			return after, 0, failure
		}
		password, changePassword, err := tasksecrets.MigratePassword(current.password.String, masterKey)
		if err != nil {
			return after, 0, failure
		}
		ssh, changeSSH, err := tasksecrets.MigrateSSH(current.ssh.String, masterKey)
		if err != nil {
			return after, 0, failure
		}
		if changePassword || changeSSH {
			if _, err = tx.ExecContext(ctx, `UPDATE tasks SET local_user_password=CASE WHEN $2 THEN $3 ELSE local_user_password END,local_user_ssh_key_passphrase=CASE WHEN $4 THEN $5 ELSE local_user_ssh_key_passphrase END WHERE id=$1`, current.id, changePassword, password, changeSSH, ssh); err != nil {
				return after, 0, ErrTaskSecretMigration
			}
			resource := fmt.Sprintf("%d/password/%t/ssh/%t", current.id, changePassword, changeSSH)
			if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES(0,0,'system:task-secret-migration','inventory.tasks.secrets_migrate',$1)`, resource); err != nil {
				return after, 0, ErrTaskSecretMigration
			}
		}
		after = current.id
	}
	if err = tx.Commit(); err != nil {
		return after, 0, ErrTaskSecretMigration
	}
	return after, len(batch), nil
}
