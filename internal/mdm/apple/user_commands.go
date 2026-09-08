package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (s *Store) enqueueUserCommand(ctx context.Context, tx *sql.Tx, u *UserChannel, kind string, args map[string]any, profileID, revision any) (string, error) {
	if kind != "ProfileList" && kind != "InstallProfile" && kind != "RemoveProfile" {
		return "", errors.New("unsupported user-channel command")
	}
	data, id, err := commandPayload(kind, args)
	if err != nil {
		return "", err
	}
	defer clear(data)
	encrypted, err := s.secrets.seal(data, secretPurpose(u.TenantID, id, "user_command"))
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_user_commands(id,tenant_id,device_id,user_channel_id,request_type,payload,profile_id,profile_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, u.TenantID, u.DeviceID, u.ID, kind, encrypted, profileID, revision)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET next_push_at=clock_timestamp(),push_status='pending',push_error='' WHERE id=$1`, u.ID)
	return id, err
}

func (s *Store) queueUserProfileInventory(ctx context.Context, tx *sql.Tx, u *UserChannel) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_user_commands WHERE user_channel_id=$1 AND request_type='ProfileList' AND status IN ('queued','sent','not_now') AND expires_at>clock_timestamp())`, u.ID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := s.enqueueUserCommand(ctx, tx, u, "ProfileList", nil, nil, nil); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_users SET next_inventory_at=clock_timestamp()+interval '6 hours' WHERE id=$1`, u.ID)
	return err
}

// A new UUID makes an in-flight snapshot from before an assignment harmless.
func (s *Store) resetUserProfileInventory(ctx context.Context, tx *sql.Tx, u *UserChannel) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_user_commands SET status='cancelled',payload=''::bytea,completed_at=clock_timestamp() WHERE user_channel_id=$1 AND request_type='ProfileList' AND status IN ('queued','sent','not_now')`, u.ID); err != nil {
		return err
	}
	return s.queueUserProfileInventory(ctx, tx, u)
}

func expireUserCommands(ctx context.Context, tx *sql.Tx, userID string) error {
	_, err := tx.ExecContext(ctx, `WITH expired AS (
 UPDATE mdm_apple_user_commands SET status='expired',payload=''::bytea,error='Command expired before completion',completed_at=clock_timestamp()
 WHERE user_channel_id=$1 AND status IN ('queued','sent','not_now') AND expires_at<=clock_timestamp() RETURNING id
) UPDATE mdm_apple_user_assignments SET status='failed',error='Command expired before completion',updated_at=clock_timestamp()
 WHERE user_channel_id=$1 AND command_id IN (SELECT id FROM expired)`, userID)
	return err
}

// UserConnect authenticates both the shared native identity and the OS-reported
// user handle. Every command lookup also includes the separate user channel.
func (s *Store) UserConnect(ctx context.Context, d *Device, message map[string]any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if d == nil || stringValue(message, "UDID") != d.UDID {
		return nil, ErrUnauthorized
	}
	userID, err := userMessageID(message)
	if err != nil {
		return nil, err
	}
	status := stringValue(message, "Status")
	switch status {
	case "Idle", "Acknowledged", "Error", "CommandFormatError", "NotNow":
	default:
		return nil, ErrUnauthorized
	}
	if status == "Idle" && stringValue(message, "CommandUUID") != "" {
		return nil, ErrUnauthorized
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, peer, err := s.lockUserParent(ctx, tx, d)
	if err != nil {
		return nil, err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM mdm_apple_users WHERE device_id=$1 AND user_id=$2 FOR UPDATE`, current.ID, userID))
	if err != nil {
		return nil, err
	}
	if u.Status == "blocked" || u.Status == "not_managed" {
		return nil, ErrUserChannelDeclined
	}
	// Only device-channel traffic can promote a candidate identity. The client
	// can retry its user receipt once the device has confirmed the new identity.
	if peer.kind == "candidate" {
		return nil, tx.Commit()
	}
	if current.Status != "enrolled" || u.Status != "enrolled" {
		return nil, ErrUnauthorized
	}
	if value, present := message["NotOnConsole"]; present {
		var ok bool
		u.NotOnConsole, ok = value.(bool)
		if !ok {
			return nil, ErrUnauthorized
		}
	}
	if err = expireUserCommands(ctx, tx, u.ID); err != nil {
		return nil, err
	}
	if status != "Idle" {
		id, parseErr := uuid.Parse(stringValue(message, "CommandUUID"))
		if parseErr != nil {
			return nil, ErrUnauthorized
		}
		var kind, previous string
		var attempts int
		var created time.Time
		err = tx.QueryRowContext(ctx, `SELECT request_type,status,attempts,created_at FROM mdm_apple_user_commands WHERE id=$1 AND tenant_id=$2 AND device_id=$3 AND user_channel_id=$4 FOR UPDATE`, id.String(), u.TenantID, u.DeviceID, u.ID).Scan(&kind, &previous, &attempts, &created)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnauthorized
		}
		if err != nil {
			return nil, err
		}
		if attempts == 0 {
			return nil, ErrUnauthorized
		}
		if previous == "sent" || previous == "not_now" {
			next, detail := "acknowledged", ""
			if status == "NotNow" {
				next = "not_now"
			} else if status != "Acknowledged" {
				next, detail = "failed", "User-channel command failed"
			}
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_user_commands SET status=$2,error=$3,payload=CASE WHEN $2='not_now' THEN payload ELSE ''::bytea END,available_at=clock_timestamp()+interval '1 minute',completed_at=CASE WHEN $2='not_now' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, id.String(), next, detail)
			if err != nil {
				return nil, err
			}
			if status == "Acknowledged" && kind == "ProfileList" {
				if err = s.ingestUserProfiles(ctx, tx, u, created, message); err != nil {
					return nil, err
				}
			}
			if kind == "InstallProfile" || kind == "RemoveProfile" {
				if status != "NotNow" {
					assignmentStatus := "verifying"
					if next == "failed" {
						assignmentStatus = "failed"
					}
					result, err := tx.ExecContext(ctx, `UPDATE mdm_apple_user_assignments SET status=$2,error=$3,updated_at=clock_timestamp() WHERE command_id=$1 AND user_channel_id=$4`, id.String(), assignmentStatus, detail, u.ID)
					if err != nil {
						return nil, err
					}
					count, err := result.RowsAffected()
					if err != nil {
						return nil, err
					}
					if count > 0 && status == "Acknowledged" {
						if err = s.resetUserProfileInventory(ctx, tx, u); err != nil {
							return nil, err
						}
					}
				}
			}
			if err = audit(ctx, tx, u.TenantID, "device:"+current.ID, "apple.user.command."+next, id.String()); err != nil {
				return nil, err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET last_seen=clock_timestamp(),not_on_console=$2 WHERE id=$1`, u.ID, u.NotOnConsole); err != nil {
		return nil, err
	}
	var payload []byte
	// NotNow must have an empty response so macOS can finish the user's login.
	if status != "NotNow" && !u.NotOnConsole {
		var id string
		err = tx.QueryRowContext(ctx, `SELECT id,payload FROM mdm_apple_user_commands WHERE user_channel_id=$1 AND status IN ('queued','sent','not_now') AND available_at<=clock_timestamp() AND expires_at>clock_timestamp() ORDER BY CASE WHEN status='sent' THEN 0 ELSE 1 END,created_at,id LIMIT 1 FOR UPDATE`, u.ID).Scan(&id, &payload)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			payload, err = s.secrets.open(payload, secretPurpose(u.TenantID, id, "user_command"))
			if err != nil {
				return nil, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_user_commands SET status='sent',attempts=attempts+1 WHERE id=$1`, id); err != nil {
				clear(payload)
				return nil, err
			}
		}
	}
	if peer, err = s.deviceIdentityPeer(ctx, tx, d); err != nil || peer.kind != "active" {
		clear(payload)
		if err != nil {
			return nil, err
		}
		return nil, ErrUnauthorized
	}
	if err = tx.Commit(); err != nil {
		clear(payload)
		return nil, err
	}
	return payload, nil
}

func (s *Store) ingestUserProfiles(ctx context.Context, tx *sql.Tx, u *UserChannel, created time.Time, message map[string]any) error {
	value, ok := message["ProfileList"].([]any)
	if !ok || len(value) > 10000 {
		return ErrUnauthorized
	}
	profiles := []InstalledProfile{}
	if err := decodePlistValue(value, &profiles); err != nil {
		return ErrUnauthorized
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		if p.Identifier == "" || len(p.Identifier) > 255 || len(p.Name) > 1024 || len(p.UUID) > 36 || len(p.Payloads) > 100 || seen[p.Identifier] {
			return ErrUnauthorized
		}
		seen[p.Identifier] = true
		for _, payload := range p.Payloads {
			if len(payload.Identifier) > 255 || len(payload.UUID) > 36 || len(payload.Type) > 255 {
				return ErrUnauthorized
			}
		}
	}
	data, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET installed_profiles=$2,profiles_at=clock_timestamp(),next_inventory_at=clock_timestamp()+interval '6 hours' WHERE id=$1`, u.ID, data); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.profile_id,a.desired,p.identifier,p.payload_uuid FROM mdm_apple_user_assignments a JOIN mdm_apple_profiles p ON p.id=a.profile_id WHERE a.user_channel_id=$1 AND a.revision=p.revision AND a.status IN ('verifying','verified','drifted') AND a.updated_at<=$2`, u.ID, created)
	if err != nil {
		return err
	}
	type change struct{ id, status string }
	changes := []change{}
	for rows.Next() {
		var id, desired, identifier, profileUUID string
		if err = rows.Scan(&id, &desired, &identifier, &profileUUID); err != nil {
			rows.Close()
			return err
		}
		present, exact := false, false
		for _, p := range profiles {
			if p.Identifier == identifier {
				present = true
				exact = p.Managed && strings.EqualFold(p.UUID, profileUUID)
			}
		}
		status := "drifted"
		if (desired == "installed" && exact) || (desired == "removed" && !present) {
			status = "verified"
		}
		changes = append(changes, change{id, status})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range changes {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_user_assignments SET status=$2,error='' WHERE user_channel_id=$1 AND profile_id=$3`, u.ID, c.status, c.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UserCommands(ctx context.Context, scope Scope, deviceID, userID string) ([]Command, error) {
	u, err := s.User(ctx, scope, deviceID, userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,request_type,status,attempts,error,created_at,completed_at FROM mdm_apple_user_commands WHERE tenant_id=$1 AND device_id=$2 AND user_channel_id=$3 ORDER BY created_at DESC,id LIMIT 100`, u.TenantID, u.DeviceID, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Command{}
	for rows.Next() {
		var c Command
		if err = rows.Scan(&c.ID, &c.DeviceID, &c.RequestType, &c.Status, &c.Attempts, &c.Error, &c.CreatedAt, &c.CompletedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (s *Store) RefreshUserInventory(ctx context.Context, scope Scope, deviceID, userID, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, u, err := s.lockManagedUser(ctx, tx, scope, deviceID, userID)
	if err != nil {
		return err
	}
	if err = s.resetUserProfileInventory(ctx, tx, u); err != nil {
		return err
	}
	if err = audit(ctx, tx, u.TenantID, actor, "apple.user.inventory.refresh", u.ID); err != nil {
		return err
	}
	return tx.Commit()
}
