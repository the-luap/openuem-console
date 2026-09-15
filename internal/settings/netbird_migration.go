package settings

import (
	"context"
	"fmt"

	"github.com/open-uem/nats/legacysecret"
)

// MigrateSecrets encrypts legacy plaintext in bounded transactions with audit.
// Existing ciphertext must authenticate and remains byte-for-byte unchanged.
func (s *NetbirdStore) MigrateSecrets(ctx context.Context) error {
	var upper int64
	if err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(id),0) FROM netbird_settings").Scan(&upper); err != nil {
		return ErrNetbirdMigration
	}
	var after int64
	for after < upper {
		next, count, err := s.migrateNetbirdSecretBatch(ctx, after, upper)
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

func (s *NetbirdStore) migrateNetbirdSecretBatch(ctx context.Context, after, upper int64) (int64, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return after, 0, ErrNetbirdMigration
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,octet_length(access_token)<=$3,CASE WHEN octet_length(access_token)<=$3 THEN access_token ELSE '' END FROM netbird_settings WHERE id>$1 AND id<=$2 AND coalesce(access_token,'')<>'' ORDER BY id LIMIT 64 FOR UPDATE`, after, upper, legacysecret.MaxStoredSize)
	if err != nil {
		return after, 0, ErrNetbirdMigration
	}
	type entry struct {
		id      int64
		bounded bool
		value   string
	}
	batch := make([]entry, 0, 64)
	for rows.Next() {
		var current entry
		if err = rows.Scan(&current.id, &current.bounded, &current.value); err != nil {
			rows.Close()
			return after, 0, ErrNetbirdMigration
		}
		batch = append(batch, current)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return after, 0, ErrNetbirdMigration
	}
	for _, current := range batch {
		failure := fmt.Errorf("%w at NetBird settings %d", ErrNetbirdMigration, current.id)
		if !current.bounded {
			return after, 0, failure
		}
		stored, changed, err := legacysecret.Migrate(current.value, s.key)
		if err != nil {
			return after, 0, failure
		}
		if changed {
			if _, err = tx.ExecContext(ctx, `UPDATE netbird_settings SET access_token=$2 WHERE id=$1`, current.id, stored); err != nil {
				return after, 0, ErrNetbirdMigration
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO uem_settings_audit(tenant_id,site_id,actor,action,resource_id,result)
 SELECT id,0,'system:netbird-secret-migration','settings.netbird.secrets_migrate',($1::bigint)::text,'success' FROM tenants WHERE tenant_netbird=$1::bigint
 UNION ALL SELECT 0,0,'system:netbird-secret-migration','settings.netbird.secrets_migrate',($1::bigint)::text,'success' WHERE NOT EXISTS(SELECT 1 FROM tenants WHERE tenant_netbird=$1::bigint)`, current.id); err != nil {
				return after, 0, ErrNetbirdMigration
			}
		}
		after = current.id
	}
	if err = tx.Commit(); err != nil {
		return after, 0, ErrNetbirdMigration
	}
	return after, len(batch), nil
}
