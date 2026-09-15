package apple

import (
	"context"
	"database/sql"
)

func (s *Store) stageUserIdentityToken(ctx context.Context, tx *sql.Tx, d *Device, u *UserChannel, renewalID string, token []byte, magic string, notOnConsole bool, short, long string) error {
	purpose := renewalID + "/" + u.ID
	encrypted, err := s.secrets.seal(token, secretPurpose(d.TenantID, purpose, "user_renewal_token"))
	if err != nil {
		return err
	}
	encryptedMagic, err := s.secrets.seal([]byte(magic), secretPurpose(d.TenantID, purpose, "user_renewal_magic"))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_user_renewal_tokens(renewal_id,tenant_id,device_id,user_channel_id,encrypted_token,encrypted_magic,not_on_console,short_name,long_name) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(renewal_id,user_channel_id) DO UPDATE SET encrypted_token=excluded.encrypted_token,encrypted_magic=excluded.encrypted_magic,not_on_console=excluded.not_on_console,short_name=excluded.short_name,long_name=excluded.long_name,updated_at=clock_timestamp()`, renewalID, d.TenantID, d.ID, u.ID, encrypted, encryptedMagic, notOnConsole, short, long)
	return err
}

// Device confirmation promotes user tokens from the same candidate atomically.
// A user request alone must never retire the previous device certificate.
func (s *Store) confirmUserIdentityTokens(ctx context.Context, tx *sql.Tx, d *Device, renewalID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT t.user_channel_id,t.encrypted_token,t.encrypted_magic,t.not_on_console,t.short_name,t.long_name FROM mdm_apple_user_renewal_tokens t JOIN mdm_apple_users u ON u.id=t.user_channel_id WHERE t.renewal_id=$1 AND t.device_id=$2 AND t.tenant_id=$3 AND u.status IN ('pending','enrolled') ORDER BY u.id FOR UPDATE OF u`, renewalID, d.ID, d.TenantID)
	if err != nil {
		return err
	}
	type staged struct {
		id, short, long string
		token, magic    []byte
		notOnConsole    bool
	}
	list := []staged{}
	for rows.Next() {
		var entry staged
		if err = rows.Scan(&entry.id, &entry.token, &entry.magic, &entry.notOnConsole, &entry.short, &entry.long); err != nil {
			rows.Close()
			return err
		}
		list = append(list, entry)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, entry := range list {
		purpose := renewalID + "/" + entry.id
		token, err := s.secrets.open(entry.token, secretPurpose(d.TenantID, purpose, "user_renewal_token"))
		if err != nil {
			return err
		}
		magic, err := s.secrets.open(entry.magic, secretPurpose(d.TenantID, purpose, "user_renewal_magic"))
		if err != nil {
			clear(token)
			return err
		}
		u := &UserChannel{ID: entry.id, TenantID: d.TenantID, DeviceID: d.ID}
		err = s.saveUserToken(ctx, tx, u, token, string(magic), entry.notOnConsole)
		clear(token)
		clear(magic)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET short_name=COALESCE(NULLIF($2,''),short_name),long_name=COALESCE(NULLIF($3,''),long_name) WHERE id=$1`, entry.id, entry.short, entry.long); err != nil {
			return err
		}
		if err = s.queueUserProfileInventory(ctx, tx, u); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_user_renewal_tokens WHERE renewal_id=$1`, renewalID)
	return err
}
