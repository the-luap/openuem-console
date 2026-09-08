package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) stageIdentityToken(ctx context.Context, tx *sql.Tx, d *Device, renewalID string, token []byte, magic string) error {
	encryptedToken, err := s.secrets.seal(token, secretPurpose(d.TenantID, renewalID, "renewal_token"))
	if err != nil {
		return err
	}
	encryptedMagic, err := s.secrets.seal([]byte(magic), secretPurpose(d.TenantID, renewalID, "renewal_magic"))
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `UPDATE mdm_apple_identity_renewals SET encrypted_token=$2,encrypted_magic=$3,token_updated_at=clock_timestamp() WHERE id=$1 AND device_id=$4 AND certificate_fingerprint=$5 AND status='issued'`, renewalID, encryptedToken, encryptedMagic, d.ID, d.peerFingerprint)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrUnauthorized
	}
	return audit(ctx, tx, d.TenantID, "device:"+d.ID, "apple.identity.renewal.token", renewalID)
}

func (s *Store) confirmIdentity(ctx context.Context, tx *sql.Tx, d *Device, renewalID string) error {
	var token, magic []byte
	var commandID, identityUUID, caUUID string
	var expires, baseExpires time.Time
	err := tx.QueryRowContext(ctx, `SELECT encrypted_token,encrypted_magic,command_id,identity_uuid,ca_uuid,certificate_expires_at,base_expires_at FROM mdm_apple_identity_renewals WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND status='issued' AND certificate_fingerprint=$4 AND token_updated_at IS NOT NULL AND certificate_expires_at>clock_timestamp() FOR UPDATE`, renewalID, d.ID, d.TenantID, d.peerFingerprint).Scan(&token, &magic, &commandID, &identityUUID, &caUUID, &expires, &baseExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	token, err = s.secrets.open(token, secretPurpose(d.TenantID, renewalID, "renewal_token"))
	if err != nil {
		return err
	}
	magic, err = s.secrets.open(magic, secretPurpose(d.TenantID, renewalID, "renewal_magic"))
	if err != nil {
		return err
	}
	token, err = s.secrets.seal(token, secretPurpose(d.TenantID, d.ID, "push_token"))
	if err != nil {
		return err
	}
	magic, err = s.secrets.seal(magic, secretPurpose(d.TenantID, d.ID, "push_magic"))
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET certificate_fingerprint=$2,certificate_expires_at=$3,push_token=$4,push_magic=$5,push_status='pending',push_error='',next_push_at=clock_timestamp(),next_identity_renewal_at=clock_timestamp()+interval '6 hours',identity_renewal_error='',last_seen=clock_timestamp() WHERE id=$1`, d.ID, d.peerFingerprint, expires, token, magic); err != nil {
		return err
	}
	layoutResult, err := tx.ExecContext(ctx, `UPDATE mdm_apple_enrollment_layouts SET identity_uuid=$2,ca_uuid=$3,identity_type='com.apple.security.scep',updated_at=clock_timestamp() WHERE device_id=$1 AND tenant_id=$4`, d.ID, identityUUID, caUUID, d.TenantID)
	if err != nil {
		return err
	}
	if n, err := layoutResult.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrConflict
	}
	if err = s.confirmUserIdentityTokens(ctx, tx, d, renewalID); err != nil {
		return err
	}
	grace := time.Now().Add(10 * time.Minute)
	if baseExpires.Before(grace) {
		grace = baseExpires
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_identity_renewals SET status='confirmed',confirmed_at=clock_timestamp(),completed_at=clock_timestamp(),grace_until=$2,encrypted_token=NULL,encrypted_magic=NULL WHERE id=$1`, renewalID, grace); err != nil {
		return err
	}
	// A new-key TokenUpdate plus command-channel request proves the effect, but
	// is not an Apple command ACK. Record verified and stop redelivering a profile
	// whose replacement is already in use. A later exact ACK may still be recorded.
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='verified',completed_at=clock_timestamp(),error='' WHERE id=$1 AND status IN ('queued','sent','not_now','expired')`, commandID); err != nil {
		return err
	}
	return audit(ctx, tx, d.TenantID, "device:"+d.ID, "apple.identity.renewal.confirm", renewalID)
}

func (s *Store) acknowledgeRetiredIdentity(ctx context.Context, tx *sql.Tx, d *Device, peer identityPeer, message map[string]any) error {
	if stringValue(message, "Status") != "Acknowledged" {
		return ErrUnauthorized
	}
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT command_id FROM mdm_apple_identity_renewals WHERE id=$1 AND device_id=$2 AND status='confirmed'`, peer.renewalID, d.ID).Scan(&id); err != nil {
		return err
	}
	if stringValue(message, "CommandUUID") != id {
		return ErrUnauthorized
	}
	r, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='acknowledged',completed_at=COALESCE(completed_at,clock_timestamp()),error='' WHERE id=$1 AND device_id=$2 AND status IN ('sent','not_now','verified')`, id, d.ID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		var acknowledged bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_commands WHERE id=$1 AND device_id=$2 AND status='acknowledged')`, id, d.ID).Scan(&acknowledged); err != nil {
			return err
		}
		if !acknowledged {
			return ErrUnauthorized
		}
		return tx.Commit()
	}
	if err = audit(ctx, tx, d.TenantID, "device:"+d.ID, "apple.command.acknowledged", id); err != nil {
		return err
	}
	// The retired certificate never receives another command or changes device
	// inventory, push data, declarations, checkout, or another command's result.
	return tx.Commit()
}

func (s *Store) finishIdentityRenewal(ctx context.Context, tx *sql.Tx, d *Device, id, state, code string) error {
	var commandID string
	err := tx.QueryRowContext(ctx, `UPDATE mdm_apple_identity_renewals SET status=$2,error=$3,challenge_hash=NULL,encrypted_token=NULL,encrypted_magic=NULL,completed_at=clock_timestamp() WHERE id=$1 AND device_id=$4 AND tenant_id=$5 AND status IN ('queued','issued') RETURNING command_id`, id, state, code, d.ID, d.TenantID).Scan(&commandID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_user_renewal_tokens WHERE renewal_id=$1`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',completed_at=clock_timestamp(),error='Identity renewal is no longer available' WHERE id=$1 AND status IN ('queued','sent','not_now')`, commandID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET identity_renewal_error=$2,next_identity_renewal_at=clock_timestamp()+interval '6 hours' WHERE id=$1`, d.ID, code); err != nil {
		return err
	}
	result := "failure"
	if state == "cancelled" {
		result = "cancelled"
	}
	return auditOutcome(ctx, tx, d.TenantID, "identity-renewal-service", "apple.identity.renewal."+state, id, result)
}

func (s *Store) cancelDeviceRenewal(ctx context.Context, tx *sql.Tx, d *Device) error {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_identity_renewals WHERE device_id=$1 AND status IN ('queued','issued')`, d.ID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.finishIdentityRenewal(ctx, tx, d, id, "cancelled", "enrollment_inactive")
}

// Issued candidates do not expire merely because the command or challenge does.
// An offline device may already have installed its new certificate. Retain that
// route to confirmation until explicit failure/revocation or certificate expiry.
func (s *Store) ReconcileIdentityRenewals(ctx context.Context) error {
	for range 25 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE EXISTS(SELECT 1 FROM mdm_apple_identity_renewals r JOIN mdm_apple_commands c ON c.id=r.command_id WHERE r.device_id=mdm_apple_devices.id AND r.status IN ('queued','issued') AND (mdm_apple_devices.status<>'enrolled' OR c.status IN ('failed','cancelled') OR (r.status='queued' AND (r.expires_at<=clock_timestamp() OR c.status='expired')) OR r.certificate_expires_at<=clock_timestamp())) ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		var id, state, commandState string
		var expires *time.Time
		err = tx.QueryRowContext(ctx, `SELECT r.id,r.status,r.certificate_expires_at,c.status FROM mdm_apple_identity_renewals r JOIN mdm_apple_commands c ON c.id=r.command_id WHERE r.device_id=$1 AND r.status IN ('queued','issued')`, d.ID).Scan(&id, &state, &expires, &commandState)
		if err == nil {
			terminal, code := "expired", "authorization_expired"
			if d.Status != "enrolled" {
				terminal, code = "cancelled", "enrollment_inactive"
			} else if commandState == "failed" || commandState == "cancelled" {
				terminal, code = "failed", "command_failed"
			} else if state == "issued" && expires != nil && !time.Now().Before(*expires) {
				code = "candidate_expired"
			}
			err = s.finishIdentityRenewal(ctx, tx, d, id, terminal, code)
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
