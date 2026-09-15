package apple

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
)

// The native row is always locked before its user rows. Each loop advances a
// durable cursor or expires work, so one offline user cannot monopolize a sweep.
func (s *Store) MaintainUserChannels(ctx context.Context) error {
	for i := 0; i < 50; i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		err = s.maintainUserChannels(ctx, tx)
		if errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) maintainUserChannels(ctx context.Context, tx *sql.Tx) error {
	var deviceID string
	var tenantID, siteID int
	err := tx.QueryRowContext(ctx, `SELECT d.id FROM mdm_apple_devices d WHERE EXISTS(
 SELECT 1 FROM mdm_apple_users u WHERE u.device_id=d.id AND (
 EXISTS(SELECT 1 FROM mdm_apple_user_commands c WHERE c.user_channel_id=u.id AND c.status IN ('queued','sent','not_now') AND c.expires_at<=clock_timestamp())
 OR (u.status='enrolled' AND NOT u.not_on_console AND u.next_inventory_at<=clock_timestamp() AND d.status='enrolled' AND d.certificate_expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM sites WHERE id=d.site_id AND tenant_sites=d.tenant_id)))) ORDER BY d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED`).Scan(&deviceID)
	if err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT tenant_id,site_id FROM mdm_apple_devices WHERE id=$1`, deviceID).Scan(&tenantID, &siteID); err != nil {
		return err
	}
	var owner int
	err = tx.QueryRowContext(ctx, `SELECT tenant_sites FROM sites WHERE id=$1 FOR SHARE`, siteID).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	owned := err == nil && owner == tenantID
	rows, err := tx.QueryContext(ctx, `SELECT `+userColumns+` FROM mdm_apple_users WHERE device_id=$1 ORDER BY id FOR UPDATE`, deviceID)
	if err != nil {
		return err
	}
	users := []*UserChannel{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return err
		}
		users = append(users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, u := range users {
		if err = expireUserCommands(ctx, tx, u.ID); err != nil {
			return err
		}
		var due bool
		if err = tx.QueryRowContext(ctx, `SELECT u.status='enrolled' AND NOT u.not_on_console AND u.next_inventory_at<=clock_timestamp() AND d.status='enrolled' AND d.certificate_expires_at>clock_timestamp() FROM mdm_apple_users u JOIN mdm_apple_devices d ON d.id=u.device_id WHERE u.id=$1`, u.ID).Scan(&due); err != nil {
			return err
		}
		if due && owned {
			if err = s.queueUserProfileInventory(ctx, tx, u); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET next_inventory_at=clock_timestamp()+interval '6 hours' WHERE id=$1`, u.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

type userPush struct {
	id, deviceID string
	tenant       int
	token, magic []byte
}

func (s *Store) leaseUserPush(ctx context.Context) (*userPush, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var deviceID string
	var tenantID, siteID int
	const due = `u.status='enrolled' AND NOT u.not_on_console AND u.push_token IS NOT NULL AND u.next_push_at<=clock_timestamp() AND EXISTS(SELECT 1 FROM mdm_apple_user_commands c WHERE c.user_channel_id=u.id AND c.status IN ('queued','sent','not_now') AND c.expires_at>clock_timestamp() AND c.available_at<=clock_timestamp())`
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.tenant_id,d.site_id FROM mdm_apple_devices d WHERE d.status='enrolled' AND d.certificate_expires_at>clock_timestamp() AND d.per_user_connections AND EXISTS(SELECT 1 FROM sites WHERE id=d.site_id AND tenant_sites=d.tenant_id) AND EXISTS(SELECT 1 FROM mdm_apple_users u WHERE u.device_id=d.id AND `+due+`) ORDER BY d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED`).Scan(&deviceID, &tenantID, &siteID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := &userPush{deviceID: deviceID}
	var owner int
	err = tx.QueryRowContext(ctx, `SELECT tenant_sites FROM sites WHERE id=$1 FOR SHARE`, siteID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != tenantID) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	err = tx.QueryRowContext(ctx, `SELECT u.id,u.tenant_id,u.push_token,u.push_magic FROM mdm_apple_users u WHERE u.device_id=$1 AND `+due+` ORDER BY u.next_push_at,u.id LIMIT 1 FOR UPDATE`, deviceID).Scan(&p.id, &p.tenant, &p.token, &p.magic)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET next_push_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, p.id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) PushUserPending(ctx context.Context) error {
	for i := 0; i < 25; i++ {
		p, err := s.leaseUserPush(ctx)
		if err != nil {
			return err
		}
		if p == nil {
			return nil
		}
		c, err := s.Settings(ctx, p.tenant)
		var token, magic []byte
		if err == nil {
			token, err = s.secrets.open(p.token, secretPurpose(p.tenant, p.id, "user_push_token"))
		}
		if err == nil {
			magic, err = s.secrets.open(p.magic, secretPurpose(p.tenant, p.id, "user_push_magic"))
		}
		if err == nil {
			var client *http.Client
			client, err = pushClient(c)
			if err == nil {
				err = Push(ctx, client, "https://"+apnsProductionHost, c.Topic, token, string(magic))
				client.CloseIdleConnections()
			}
		}
		clear(token)
		clear(magic)
		status, detail := "accepted", ""
		if err != nil {
			status, detail = "failed", "Unable to wake user channel"
		}
		var pushErr *PushError
		if errors.As(err, &pushErr) && (pushErr.Status == 410 || pushErr.Reason == "BadDeviceToken" || pushErr.Reason == "DeviceTokenNotForTopic") {
			status, detail = "invalid_token", "User push token is no longer valid; wait for a new TokenUpdate"
		}
		if err = s.recordUserPushOutcome(ctx, p, status, detail); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) recordUserPushOutcome(ctx context.Context, p *userPush, status, detail string) error {
	// Taking the native lock first prevents a late APNs reply from racing
	// certificate promotion, checkout, or revocation while updating a user row.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT status='enrolled' AND certificate_expires_at>clock_timestamp() FROM mdm_apple_devices WHERE id=$1 FOR UPDATE`, p.deviceID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if active {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET push_status=$2,push_error=$3,next_push_at=CASE WHEN $2='invalid_token' THEN clock_timestamp()+interval '1 day' ELSE next_push_at END WHERE id=$1 AND device_id=$4 AND status='enrolled' AND push_token=$5 AND push_magic=$6`, p.id, status, detail, p.deviceID, p.token, p.magic)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
