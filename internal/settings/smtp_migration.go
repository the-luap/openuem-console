package settings

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrMigration = errors.New("SMTP secret migration is incomplete")

// MigrateSecrets encrypts legacy plaintext in bounded transactions with audit.
// Existing ciphertext must authenticate and remains byte-for-byte unchanged.
func (s *SMTPStore) MigrateSecrets(ctx context.Context) error {
	var upper int64
	if err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(id),0) FROM settings").Scan(&upper); err != nil {
		return ErrMigration
	}
	var after int64
	for after < upper {
		next, count, err := s.migrateSecretBatch(ctx, after, upper)
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

func (s *SMTPStore) migrateSecretBatch(ctx context.Context, after, upper int64) (int64, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return after, 0, ErrMigration
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,coalesce(tenant_settings,0),octet_length(smtp_password)<=$3,CASE WHEN octet_length(smtp_password)<=$3 THEN smtp_password ELSE '' END FROM settings WHERE id>$1 AND id<=$2 AND coalesce(smtp_password,'')<>'' ORDER BY id LIMIT 64 FOR UPDATE`, after, upper, legacysecret.MaxStoredSize)
	if err != nil {
		return after, 0, ErrMigration
	}
	type entry struct {
		id      int64
		tenant  int
		bounded bool
		value   string
	}
	batch := make([]entry, 0, 64)
	for rows.Next() {
		var current entry
		if err = rows.Scan(&current.id, &current.tenant, &current.bounded, &current.value); err != nil {
			rows.Close()
			return after, 0, ErrMigration
		}
		batch = append(batch, current)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return after, 0, ErrMigration
	}
	for _, current := range batch {
		failure := fmt.Errorf("%w at settings %d", ErrMigration, current.id)
		if !current.bounded {
			return after, 0, failure
		}
		stored, changed, err := legacysecret.Migrate(current.value, s.key)
		if err != nil {
			return after, 0, failure
		}
		if changed {
			if _, err = tx.ExecContext(ctx, `UPDATE settings SET smtp_password=$2 WHERE id=$1`, current.id, stored); err != nil {
				return after, 0, ErrMigration
			}
			if err = smtpAudit(ctx, tx, "system:smtp-secret-migration", access.Scope{TenantID: current.tenant}, "settings.smtp.secrets_migrate", fmt.Sprint(current.id), "success"); err != nil {
				return after, 0, ErrMigration
			}
		}
		after = current.id
	}
	if err = tx.Commit(); err != nil {
		return after, 0, ErrMigration
	}
	return after, len(batch), nil
}
