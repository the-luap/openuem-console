package apple

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"strings"
	"time"
)

// Once a mutation was sent, an Idle request must not redeliver it. NotNow is
// an explicit non-execution response and may defer the same candidate/UUID.
func (s *Store) macAdminCommandResult(ctx context.Context, tx *sql.Tx, d *Device, id, status string) (bool, error) {
	var key, operation, previous string
	var dispatched *time.Time
	err := tx.QueryRowContext(ctx, `SELECT id,operation,status,dispatched_at FROM mdm_apple_mac_admin_keys WHERE device_id=$1 AND tenant_id=$2 AND command_id=$3`, d.ID, d.TenantID, id).Scan(&key, &operation, &previous, &dispatched)
	if err != nil {
		return false, err
	}
	if dispatched == nil {
		return false, ErrConflict
	}
	if previous != "sent" && previous != "not_now" && previous != "uncertain" {
		return false, nil
	}
	if previous == "not_now" && status == "NotNow" {
		return true, nil
	}
	next, detail := "acknowledged", ""
	switch status {
	case "NotNow":
		next = "not_now"
	case "Error", "CommandFormatError":
		next, detail = "failed", "command_failed"
	case "Acknowledged":
	default:
		return false, ErrMacAdmin
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status=$2,error=$3,available_at=CASE WHEN $2='not_now' THEN clock_timestamp()+interval '1 minute' ELSE available_at END,completed_at=CASE WHEN $2='not_now' THEN NULL ELSE clock_timestamp() END,payload=CASE WHEN $2='not_now' THEN payload ELSE '\x'::bytea END WHERE id=$1`, id, next, detail); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_keys SET status=$2,completed_at=CASE WHEN $2='not_now' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, key, next); err != nil {
		return false, err
	}
	creation := next
	if next == "acknowledged" {
		creation = "accepted"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET creation_state=CASE WHEN $2='create' THEN $3 ELSE creation_state END,error=$4,current_key_id=CASE WHEN $3='accepted' THEN $5::uuid ELSE current_key_id END,accepted_at=CASE WHEN $2='create' AND $3='accepted' THEN clock_timestamp() ELSE accepted_at END,next_rotation_at=CASE WHEN $3='accepted' AND NOT rotation_paused AND (options->>'rotation_days')::int>0 THEN clock_timestamp()+((options->>'rotation_days')::int * interval '1 day') ELSE NULL END,next_check_at=clock_timestamp() WHERE device_id=$1`, d.ID, operation, creation, detail, key); err != nil {
		return false, err
	}
	outcome := "success"
	if next == "not_now" {
		outcome = "deferred"
	} else if next == "failed" {
		outcome = "failure"
	}
	if err = auditOutcome(ctx, tx, d.TenantID, "device:"+d.ID, "apple.mac_admin."+next, id, outcome); err != nil {
		return false, err
	}
	if next == "acknowledged" {
		var inventoryID string
		inventoryID, err = s.enqueue(ctx, tx, d, "DeviceInformation", map[string]any{"Queries": inventoryQueriesFor(*d)}, nil, nil)
		// PostgreSQL now() is the transaction start, before acceptance above. Mark
		// this follow-up with its actual creation time for the evidence boundary.
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET created_at=clock_timestamp() WHERE id=$1`, inventoryID)
		}
	}
	return next == "not_now", err
}

func (s *Store) reconcileMacAdminExpiry(ctx context.Context, tx *sql.Tx, d *Device) error {
	rows, err := tx.QueryContext(ctx, `SELECT k.id,k.command_id,k.operation,k.status FROM mdm_apple_mac_admin_keys k JOIN mdm_apple_commands c ON c.id=k.command_id WHERE k.device_id=$1 AND k.status IN ('queued','sent','not_now') AND (c.expires_at<=clock_timestamp() OR c.status IN ('expired','cancelled'))`, d.ID)
	if err != nil {
		return err
	}
	type item struct{ id, command, operation, status string }
	list := []item{}
	for rows.Next() {
		var v item
		if err = rows.Scan(&v.id, &v.command, &v.operation, &v.status); err != nil {
			rows.Close()
			return err
		}
		list = append(list, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range list {
		next := "expired"
		if v.status == "sent" {
			next = "uncertain"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_keys SET status=$2,completed_at=clock_timestamp() WHERE id=$1`, v.id, next); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='expired',payload='\x',error='Administrator command expired',completed_at=clock_timestamp() WHERE id=$1`, v.command); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET creation_state=CASE WHEN $2='create' THEN $3 ELSE creation_state END,error=$3,next_rotation_at=NULL WHERE device_id=$1`, d.ID, v.operation, next); err != nil {
			return err
		}
		if err = auditOutcome(ctx, tx, d.TenantID, "system", "apple.mac_admin."+next, v.command, "failure"); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) prepareMacAdminDelivery(ctx context.Context, tx *sql.Tx, d *Device, id string) (bool, error) {
	a, err := macAdminAccountTx(ctx, tx, d)
	if err != nil {
		return false, err
	}
	if a == nil {
		return false, ErrMacAdmin
	}
	// Read inventory again: this Connect may just have acknowledged newer data.
	d, err = scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1`, d.ID))
	if err != nil {
		return false, err
	}
	var operation string
	if err = tx.QueryRowContext(ctx, `SELECT operation FROM mdm_apple_mac_admin_keys WHERE command_id=$1 AND device_id=$2 AND status IN ('queued','not_now')`, id, d.ID).Scan(&operation); err != nil {
		return false, err
	}
	var awaiting, complete bool
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(awaiting_configuration,false),setup_state='complete' FROM mdm_apple_ade_admissions WHERE device_id=$1`, d.ID).Scan(&awaiting, &complete); err != nil {
		return false, err
	}
	ready := macAdminDeviceReady(*d, time.Now())
	if operation == "create" {
		ready = ready && awaiting && !complete
	} else {
		ready = ready && complete && !awaiting && a.GUID != "" && a.InventoryState == "present" && a.ObservedAt != nil && !a.ObservedAt.After(time.Now()) && a.ObservedAt.After(time.Now().Add(-24*time.Hour))
	}
	if !ready {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',payload='\x',error='Administrator delivery prerequisites changed',completed_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_keys SET status='cancelled',completed_at=clock_timestamp() WHERE command_id=$1`, id); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET creation_state=CASE WHEN $2='create' THEN 'expired' ELSE creation_state END,error='delivery_changed',next_rotation_at=NULL WHERE device_id=$1`, d.ID, operation); err != nil {
			return false, err
		}
		return false, auditOutcome(ctx, tx, d.TenantID, "system", "apple.mac_admin.delivery.cancel", id, "cancelled")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_keys SET status='sent',dispatched_at=clock_timestamp() WHERE command_id=$1`, id); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET creation_state=CASE WHEN $2='create' THEN 'sent' ELSE creation_state END WHERE device_id=$1`, d.ID, operation); err != nil {
		return false, err
	}
	return true, nil
}

// Bind the account identity only from a post-acceptance inventory request. The
// request creation time is the conservative observation time, so delayed replies
// neither refresh stale evidence nor replace newer observations.
func (s *Store) recordMacAdminInventory(ctx context.Context, tx *sql.Tx, d *Device, command string, info map[string]any) error {
	a, err := macAdminAccountTx(ctx, tx, d)
	if err != nil || a == nil || a.CreationState != "accepted" {
		return err
	}
	var requested time.Time
	if err = tx.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND request_type='DeviceInformation' AND status='acknowledged'`, command, d.ID, d.TenantID).Scan(&requested); err != nil {
		return err
	}
	if requested.After(time.Now()) || a.AcceptedAt == nil || requested.Before(*a.AcceptedAt) || (a.ObservedAt != nil && !requested.After(*a.ObservedAt)) {
		return nil
	}
	state, guid := "unknown", ""
	if value, exists := info["AutoSetupAdminAccounts"]; exists {
		state = "missing"
		accounts, ok := value.([]any)
		if !ok || len(accounts) > 32 {
			state = "conflict"
		} else {
			matches := 0
			for _, value := range accounts {
				account, ok := value.(map[string]any)
				if !ok {
					state = "conflict"
					break
				}
				if stringValue(account, "shortName") != a.Options.ShortName {
					continue
				}
				matches++
				raw := stringValue(account, "GUID")
				parsed, e := uuid.Parse(raw)
				if e != nil || parsed == uuid.Nil || !strings.EqualFold(parsed.String(), raw) || matches > 1 {
					state = "conflict"
					break
				}
				guid = parsed.String()
				state = "present"
			}
		}
	}
	if state == "present" && a.GUID != "" && a.GUID != guid {
		state = "conflict"
	}
	if state != "present" {
		guid = ""
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET inventory_state=$2,guid=COALESCE(guid,NULLIF($3,'')::uuid),observed_at=$4,next_check_at=clock_timestamp() WHERE device_id=$1`, d.ID, state, guid, requested)
	return err
}

func (s *Store) reconcileMacAdmin(ctx context.Context, tx *sql.Tx, d *Device) error {
	if d.EnrollmentMethod != "automated_device" || d.Status != "enrolled" {
		return nil
	}
	if err := s.reconcileMacAdminExpiry(ctx, tx, d); err != nil {
		return err
	}
	a, err := macAdminAccountTx(ctx, tx, d)
	if err != nil || a == nil {
		return err
	}
	d, err = scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1`, d.ID))
	if err != nil {
		return err
	}
	var awaiting *bool
	var complete bool
	if err = tx.QueryRowContext(ctx, `SELECT awaiting_configuration,setup_state='complete' FROM mdm_apple_ade_admissions WHERE device_id=$1`, d.ID).Scan(&awaiting, &complete); err != nil {
		return err
	}
	if a.CreationState == "planned" {
		if awaiting != nil && (!*awaiting || complete) {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET creation_state='cancelled',error='setup_ended' WHERE device_id=$1`, d.ID)
			return err
		}
		if awaiting != nil && *awaiting && macAdminDeviceReady(*d, time.Now()) {
			return s.queueMacAdmin(ctx, tx, d, a, false, "system")
		}
		return nil
	}
	if a.CreationState != "accepted" || !complete {
		return nil
	}
	// Inventory runs on the existing six-hour schedule. A missing account never
	// becomes a new rotation target and failed/uncertain mutations stop scheduling.
	if !a.RotationPaused && a.NextRotationAt != nil && !a.NextRotationAt.After(time.Now()) && a.RotationReason(*d, time.Now()) == "" && a.LatestStatus == "acknowledged" {
		err = s.queueMacAdmin(ctx, tx, d, a, true, "system")
		if errors.Is(err, ErrConflict) {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET next_rotation_at=NULL,error='history_limit' WHERE device_id=$1`, d.ID)
		}
	}
	return err
}
func (s *Store) ReconcileMacAdmins(ctx context.Context) error {
	for range 25 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE status='enrolled' AND id IN (SELECT device_id FROM mdm_apple_mac_admin_accounts WHERE creation_state='planned' AND next_check_at<=clock_timestamp()
 UNION SELECT device_id FROM mdm_apple_mac_admin_accounts WHERE NOT rotation_paused AND next_rotation_at<=clock_timestamp() AND next_check_at<=clock_timestamp()
 UNION SELECT k.device_id FROM mdm_apple_mac_admin_keys k JOIN mdm_apple_commands c ON c.id=k.command_id JOIN mdm_apple_mac_admin_accounts a ON a.device_id=k.device_id WHERE k.status IN ('queued','sent','not_now') AND (c.expires_at<=clock_timestamp() OR c.status IN ('expired','cancelled')) AND a.next_check_at<=clock_timestamp()) ORDER BY (SELECT next_check_at FROM mdm_apple_mac_admin_accounts WHERE device_id=mdm_apple_devices.id),id LIMIT 1 FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			return nil
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET next_check_at=clock_timestamp()+interval '1 minute' WHERE device_id=$1`, d.ID)
		}
		if err == nil {
			err = s.reconcileMacAdmin(ctx, tx, d)
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback()
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) cancelMacAdmin(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_keys SET status=CASE WHEN status IN ('sent','uncertain') THEN 'uncertain' ELSE 'cancelled' END,completed_at=clock_timestamp() WHERE device_id=$1 AND status IN ('queued','sent','not_now','uncertain')`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET payload='\x' WHERE device_id=$1 AND mac_admin`, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET creation_state=CASE WHEN creation_state='accepted' THEN creation_state WHEN creation_state IN ('sent','uncertain') THEN 'uncertain' ELSE 'cancelled' END,next_rotation_at=NULL,error='enrollment_ended' WHERE device_id=$1`, id)
	return err
}
