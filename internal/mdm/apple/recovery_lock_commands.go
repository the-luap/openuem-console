package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) finishRecoveryLock(ctx context.Context, tx *sql.Tx, d *Device, a *RecoveryLockAttempt, status, code string) error {
	if a.Status == status && a.Error == code {
		return nil
	}
	terminal := status != "uncertain"
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_attempts SET status=$2,error=$3,completed_at=CASE WHEN $4 THEN clock_timestamp() ELSE NULL END,next_check_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, a.ID, status, code, terminal); err != nil {
		return err
	}
	if terminal {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands c SET status=CASE WHEN $2='verified' AND c.request_type='SetRecoveryLock' THEN 'verified' ELSE 'cancelled' END,payload='\x',completed_at=COALESCE(completed_at,clock_timestamp()) FROM mdm_apple_recovery_lock_commands r WHERE r.command_id=c.id AND r.attempt_id=$1 AND c.status IN ('queued','sent','not_now','expired','cancelled')`, a.ID, status); err != nil {
			return err
		}
	}
	a.Status = status
	a.Error = code
	outcome := "success"
	switch status {
	case "failed":
		outcome = "failure"
	case "uncertain":
		outcome = "deferred"
	case "cancelled":
		outcome = "cancelled"
	}
	return auditOutcome(ctx, tx, d.TenantID, "recovery-lock-service", "apple.recovery_lock."+status, a.ID, outcome)
}

func (s *Store) recordRecoveryLockKeyEvidence(ctx context.Context, tx *sql.Tx, d *Device, key string, verified bool, dispatched time.Time) error {
	// Dispatch is a conservative lower bound on when the check ran. A delayed
	// response must never make a days-old check look newly performed.
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_keys SET verified_at=CASE WHEN $4 THEN $5 ELSE verified_at END,rejected_at=CASE WHEN $4 THEN rejected_at ELSE $5 END WHERE id=$1 AND device_id=$2 AND tenant_id=$3`, key, d.ID, d.TenantID, verified, dispatched)
	return err
}

func (s *Store) promoteRecoveryLockKey(ctx context.Context, tx *sql.Tx, d *Device, key string) error {
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_state SET current_key_id=$2,evidence='verified',updated_at=clock_timestamp() WHERE device_id=$1 AND tenant_id=$3`, d.ID, key, d.TenantID)
	return err
}

// A sent mutation's old password is not a stopping proof. Only a result for the
// exact mutation, or verification of its distinct new password, can release it.
func (s *Store) recoveryLockCommandResult(ctx context.Context, tx *sql.Tx, d *Device, id, status string, message map[string]any) (bool, error) {
	var attempt, purpose, result string
	var dispatched *time.Time
	var expires time.Time
	err := tx.QueryRowContext(ctx, `SELECT r.attempt_id,r.purpose,r.result,r.dispatched_at,c.expires_at FROM mdm_apple_recovery_lock_commands r JOIN mdm_apple_commands c ON c.id=r.command_id WHERE r.command_id=$1 AND r.device_id=$2 AND r.tenant_id=$3`, id, d.ID, d.TenantID).Scan(&attempt, &purpose, &result, &dispatched, &expires)
	if err != nil {
		return false, notFound(err)
	}
	if dispatched == nil {
		return false, ErrConflict
	}
	a, err := scanRecoveryLockAttempt(tx.QueryRowContext(ctx, `SELECT `+recoveryLockAttemptColumns+` FROM mdm_apple_recovery_lock_attempts WHERE id=$1 AND device_id=$2`, attempt, d.ID))
	if err != nil {
		return false, err
	}
	// Identical receipts cannot refresh timestamps. Superseded read-only replies
	// cannot promote historical keys, including after a newer mutation completed.
	if result != "" || !a.Active() || (purpose != "set" && a.command != id) {
		return false, nil
	}
	if dispatched.After(time.Now()) {
		return false, ErrRecoveryLock
	}
	if purpose == "current" && !time.Now().Before(expires) {
		return false, s.finishRecoveryLock(ctx, tx, d, a, "failed", "current_password_check_expired")
	}
	if status == "NotNow" {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='not_now',available_at=clock_timestamp()+interval '1 minute',error='' WHERE id=$1 AND status IN ('sent','not_now')`, id)
		return true, err
	}
	result = "error"
	commandStatus := "failed"
	code := "command_failed"
	if status == "Acknowledged" {
		if purpose == "set" {
			result = "acknowledged"
			commandStatus = "acknowledged"
			code = ""
		} else if verified, ok := message["PasswordVerified"].(bool); ok {
			result = "rejected"
			if verified {
				result = "verified"
			}
			commandStatus = "acknowledged"
			code = ""
		} else {
			code = "invalid_verification_response"
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_commands SET result=$2,result_at=clock_timestamp() WHERE command_id=$1 AND result=''`, id, result); err != nil {
		return false, err
	}
	// Device errors can contain submitted passwords. Retain only fixed codes.
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status=$2,error=$3,payload='\x',completed_at=clock_timestamp() WHERE id=$1`, id, commandStatus, code); err != nil {
		return false, err
	}
	outcome := "success"
	if result == "error" || result == "rejected" {
		outcome = "failure"
	}
	if err = auditOutcome(ctx, tx, d.TenantID, "device:"+d.ID, "apple.recovery_lock.command."+result, id, outcome); err != nil {
		return false, err
	}
	if purpose == "set" {
		if a.Operation == "remove" {
			if result == "acknowledged" {
				if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_state SET current_key_id=NULL,evidence='removal_acknowledged',updated_at=clock_timestamp() WHERE device_id=$1`, d.ID); err != nil {
					return false, err
				}
				return false, s.finishRecoveryLock(ctx, tx, d, a, "removed", "")
			}
			return false, s.finishRecoveryLock(ctx, tx, d, a, "failed", "removal_failed")
		}
		return false, s.reconcileRecoveryLock(ctx, tx, d, true)
	}
	key := a.CandidateKeyID
	if purpose == "current" || purpose == "previous" {
		key = a.PreviousKeyID
	}
	if result == "verified" || result == "rejected" {
		if err = s.recordRecoveryLockKeyEvidence(ctx, tx, d, key, result == "verified", *dispatched); err != nil {
			return false, err
		}
	}
	if result == "verified" {
		if purpose == "current" {
			if err = s.promoteRecoveryLockKey(ctx, tx, d, key); err != nil {
				return false, err
			}
			if err = s.recoveryLockEligible(ctx, tx, d); err != nil {
				return false, s.finishRecoveryLock(ctx, tx, d, a, "failed", "device_unavailable")
			}
			return false, s.queueRecoveryLockCommand(ctx, tx, d, a, "set")
		}
		if purpose == "previous" {
			var stopped bool
			if err = tx.QueryRowContext(ctx, `SELECT result IN ('acknowledged','error') FROM mdm_apple_recovery_lock_commands WHERE command_id=$1`, a.setCommand).Scan(&stopped); err != nil {
				return false, err
			}
			if !stopped {
				return false, ErrConflict
			}
		}
		if err = s.promoteRecoveryLockKey(ctx, tx, d, key); err != nil {
			return false, err
		}
		final := "verified"
		if purpose == "previous" {
			final = "resolved"
		}
		return false, s.finishRecoveryLock(ctx, tx, d, a, final, "")
	}
	if result == "rejected" {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_state SET evidence='unknown',updated_at=clock_timestamp() WHERE device_id=$1 AND current_key_id=$2`, d.ID, key); err != nil {
			return false, err
		}
		code = "password_not_verified"
	}
	if a.setCommand != "" {
		var failed bool
		if err = tx.QueryRowContext(ctx, `SELECT result='error' FROM mdm_apple_recovery_lock_commands WHERE command_id=$1`, a.setCommand).Scan(&failed); err != nil {
			return false, err
		}
		if failed && result == "rejected" && purpose == "candidate" {
			return false, s.finishRecoveryLock(ctx, tx, d, a, "failed", "mutation_failed")
		}
		return false, s.finishRecoveryLock(ctx, tx, d, a, "uncertain", code)
	}
	return false, s.finishRecoveryLock(ctx, tx, d, a, "failed", code)
}

func (s *Store) reconcileRecoveryLock(ctx context.Context, tx *sql.Tx, device *Device, connected bool) error {
	// Result ingestion may have just replaced inventory in this transaction.
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2`, device.ID, device.TenantID))
	if err != nil {
		return err
	}
	a, err := scanRecoveryLockAttempt(tx.QueryRowContext(ctx, `SELECT `+recoveryLockAttemptColumns+` FROM mdm_apple_recovery_lock_attempts WHERE device_id=$1 AND status IN ('checking','queued','sent','verifying','uncertain')`, d.ID))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_attempts SET next_check_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, a.ID); err != nil {
		return err
	}
	if d.Status != "enrolled" {
		return s.finishRecoveryLock(ctx, tx, d, a, "cancelled", "enrollment_ended")
	}
	var purpose, state, result string
	var dispatched *time.Time
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT r.purpose,c.status,r.result,r.dispatched_at,c.expires_at FROM mdm_apple_recovery_lock_commands r JOIN mdm_apple_commands c ON c.id=r.command_id WHERE r.command_id=$1 AND r.attempt_id=$2`, a.command, a.ID).Scan(&purpose, &state, &result, &dispatched, &expires)
	if err != nil {
		return err
	}
	expired := !time.Now().Before(expires)
	if expired && (state == "queued" || state == "sent" || state == "not_now") {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='expired',payload='\x',error='Recovery Lock command expired',completed_at=clock_timestamp() WHERE id=$1`, a.command); err != nil {
			return err
		}
		state = "expired"
	}
	if purpose == "set" && dispatched != nil {
		if a.Operation == "remove" {
			return s.finishRecoveryLock(ctx, tx, d, a, "uncertain", "awaiting_removal_result")
		}
		if connected || state == "expired" || state == "failed" || state == "acknowledged" || state == "not_now" {
			if err = s.recoveryLockEligible(ctx, tx, d); err != nil {
				return s.finishRecoveryLock(ctx, tx, d, a, "uncertain", "device_unavailable")
			}
			return s.queueRecoveryLockCommand(ctx, tx, d, a, "candidate")
		}
		return nil
	}
	if purpose == "candidate" && result == "rejected" && a.setCommand != "" {
		var failed bool
		if err = tx.QueryRowContext(ctx, `SELECT result='error' FROM mdm_apple_recovery_lock_commands WHERE command_id=$1`, a.setCommand).Scan(&failed); err != nil {
			return err
		}
		if failed {
			return s.finishRecoveryLock(ctx, tx, d, a, "failed", "mutation_failed")
		}
	}
	if a.Status == "uncertain" {
		return nil
	}
	if state == "expired" || state == "cancelled" || s.recoveryLockEligible(ctx, tx, d) != nil {
		status := "failed"
		if a.setCommand != "" {
			var sent bool
			if err = tx.QueryRowContext(ctx, `SELECT dispatched_at IS NOT NULL FROM mdm_apple_recovery_lock_commands WHERE command_id=$1`, a.setCommand).Scan(&sent); err != nil {
				return err
			}
			if sent {
				status = "uncertain"
			}
		}
		return s.finishRecoveryLock(ctx, tx, d, a, status, "device_or_command_unavailable")
	}
	return nil
}

func (s *Store) prepareRecoveryLockDelivery(ctx context.Context, tx *sql.Tx, device *Device, command string) (bool, error) {
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2`, device.ID, device.TenantID))
	if err != nil {
		return false, err
	}
	var id, purpose string
	var dispatched *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT attempt_id,purpose,dispatched_at FROM mdm_apple_recovery_lock_commands WHERE command_id=$1 AND device_id=$2`, command, d.ID).Scan(&id, &purpose, &dispatched); err != nil {
		return false, err
	}
	a, err := scanRecoveryLockAttempt(tx.QueryRowContext(ctx, `SELECT `+recoveryLockAttemptColumns+` FROM mdm_apple_recovery_lock_attempts WHERE id=$1 AND device_id=$2`, id, d.ID))
	if err != nil {
		return false, err
	}
	if !a.Active() || a.command != command || (purpose == "set" && dispatched != nil) {
		return false, ErrConflict
	}
	if err = s.recoveryLockEligible(ctx, tx, d); err != nil {
		status := "failed"
		if a.setCommand != "" && purpose != "set" {
			status = "uncertain"
		}
		return false, s.finishRecoveryLock(ctx, tx, d, a, status, "device_unavailable")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_commands SET dispatched_at=COALESCE(dispatched_at,clock_timestamp()) WHERE command_id=$1`, command); err != nil {
		return false, err
	}
	if purpose == "set" {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_attempts SET status='sent' WHERE id=$1`, a.ID)
	}
	return err == nil, err
}

func (s *Store) ReconcileRecoveryLocks(ctx context.Context) error {
	for i := 0; i < 25; i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE EXISTS(SELECT 1 FROM mdm_apple_recovery_lock_attempts r WHERE r.device_id=mdm_apple_devices.id AND r.status IN ('checking','queued','sent','verifying','uncertain') AND r.next_check_at<=clock_timestamp()) ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = s.reconcileRecoveryLock(ctx, tx, d, false); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
