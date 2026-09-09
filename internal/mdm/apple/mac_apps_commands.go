package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) enqueueMacApp(ctx context.Context, tx *sql.Tx, d *Device, attempt, kind string, args map[string]any) (string, error) {
	request := map[string]string{"install": "InstallEnterpriseApplication", "remove": "RemoveApplication", "managed": "ManagedApplicationList", "installed": "InstalledApplicationList"}[kind]
	if request == "" {
		return "", ErrMacApp
	}
	id, err := s.enqueue(ctx, tx, d, request, args, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET managed_app=true,created_at=clock_timestamp(),expires_at=clock_timestamp()+CASE WHEN $2 IN ('install','remove') THEN interval '1 day' ELSE interval '10 minutes' END WHERE id=$1`, id, kind)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_app_commands(command_id,tenant_id,device_id,attempt_id,kind) VALUES($1,$2,$3,$4,$5)`, id, d.TenantID, d.ID, attempt, kind)
	return id, err
}

func (s *Store) finishMacApp(ctx context.Context, tx *sql.Tx, attempt, state, detail string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET status=$2,error=$3 WHERE id=$1`, attempt, state, detail); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET status=$2,updated_at=clock_timestamp(),next_check_at=clock_timestamp()+interval '15 minutes' WHERE current_attempt_id=$1`, attempt, state); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands c SET status='cancelled',payload='\x',completed_at=clock_timestamp() FROM mdm_apple_app_commands m WHERE m.command_id=c.id AND m.attempt_id=$1 AND c.status IN ('queued','sent','not_now')`, attempt)
	return err
}

func (s *Store) reconcileMacAppExpiry(ctx context.Context, tx *sql.Tx, d *Device) error {
	rows, err := tx.QueryContext(ctx, `SELECT t.id,t.status FROM mdm_apple_app_attempts t JOIN mdm_apple_app_commands m ON m.attempt_id=t.id AND m.kind IN ('install','remove') JOIN mdm_apple_commands c ON c.id=m.command_id WHERE t.device_id=$1 AND t.tenant_id=$2 AND t.status IN ('queued','sent','not_now') AND (c.expires_at<=clock_timestamp() OR c.status IN ('expired','cancelled'))`, d.ID, d.TenantID)
	if err != nil {
		return err
	}
	type expired struct{ id, status string }
	items := []expired{}
	for rows.Next() {
		var item expired
		if err = rows.Scan(&item.id, &item.status); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range items {
		state := "expired"
		if item.status == "sent" {
			state = "uncertain"
		}
		if err = s.finishMacApp(ctx, tx, item.id, state, "command_expired"); err != nil {
			return err
		}
		if err = auditOutcome(ctx, tx, d.TenantID, "system", "apple.software."+state, item.id, "failure"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) queueMacAppObservation(ctx context.Context, tx *sql.Tx, d *Device, a *MacAppAssignment) error {
	for _, kind := range []string{"managed", "installed"} {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_app_commands m JOIN mdm_apple_commands c ON c.id=m.command_id WHERE m.attempt_id=$1 AND m.kind=$2 AND c.status IN ('queued','sent','not_now') AND c.expires_at>clock_timestamp() AND ($3::timestamptz IS NULL OR c.created_at>=$3))`, a.AttemptID, kind, a.AcceptedAt).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands c SET status='cancelled',payload='\x',completed_at=clock_timestamp() FROM mdm_apple_app_commands m WHERE m.command_id=c.id AND m.attempt_id=$1 AND m.kind=$2 AND c.status IN ('queued','sent','not_now')`, a.AttemptID, kind); err != nil {
			return err
		}
		args := map[string]any{"Identifiers": []string{a.Version.Identifier}}
		if kind == "installed" {
			// Include unmanaged matches so absence of a managed record cannot
			// incorrectly prove that an app and its data were removed.
			args["ManagedAppsOnly"] = false
		}
		if _, err := s.enqueueMacApp(ctx, tx, d, a.AttemptID, kind, args); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET next_check_at=clock_timestamp()+CASE WHEN status IN ('verified','drifted') THEN interval '6 hours' WHEN status='verifying' THEN interval '1 minute' ELSE interval '15 minutes' END WHERE id=$1`, a.ID)
	return err
}

func (s *Store) prepareMacAppDelivery(ctx context.Context, tx *sql.Tx, d *Device, command string) (bool, error) {
	var kind, attempt string
	if err := tx.QueryRowContext(ctx, `SELECT kind,attempt_id FROM mdm_apple_app_commands WHERE command_id=$1 AND device_id=$2 AND tenant_id=$3`, command, d.ID, d.TenantID).Scan(&kind, &attempt); err != nil {
		return false, err
	}
	a, err := scanMacApp(tx.QueryRowContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.current_attempt_id=$1 AND a.device_id=$2`, attempt, d.ID))
	if errors.Is(err, ErrNotFound) {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',payload='\x',completed_at=clock_timestamp() WHERE id=$1`, command)
		return false, err
	}
	if err != nil {
		return false, err
	}
	if kind == "managed" || kind == "installed" {
		return true, nil
	}
	current, err := s.lockMacAppDevice(ctx, tx, Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) {
		return false, err
	}
	ready := err == nil && (a.Status == "queued" || a.Status == "not_now")
	if ready && kind == "install" {
		// Lock the approval against concurrent withdrawal until delivery commits.
		var withdrawn *time.Time
		if err = tx.QueryRowContext(ctx, `SELECT withdrawn_at FROM uem_software_versions WHERE id=$1 FOR SHARE`, a.Version.ID).Scan(&withdrawn); err != nil {
			return false, err
		}
		ready = withdrawn == nil && macAppCompatible(*current, a.Version)
	}
	if !ready {
		if err = s.finishMacApp(ctx, tx, attempt, "cancelled", "delivery_prerequisites_changed"); err != nil {
			return false, err
		}
		return false, auditOutcome(ctx, tx, d.TenantID, "system", "apple.software.delivery.cancel", attempt, "cancelled")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET status='sent',dispatched_at=clock_timestamp() WHERE id=$1`, attempt); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET status='sent',updated_at=clock_timestamp() WHERE current_attempt_id=$1`, attempt)
	return true, err
}

func (s *Store) macAppCommandResult(ctx context.Context, tx *sql.Tx, d *Device, command, status string, message map[string]any) (bool, error) {
	var kind, attempt, previous string
	var attempts int
	var requested, expires time.Time
	err := tx.QueryRowContext(ctx, `SELECT m.kind,m.attempt_id,c.status,c.attempts,c.created_at,c.expires_at FROM mdm_apple_app_commands m JOIN mdm_apple_commands c ON c.id=m.command_id WHERE m.command_id=$1 AND m.device_id=$2 AND m.tenant_id=$3`, command, d.ID, d.TenantID).Scan(&kind, &attempt, &previous, &attempts, &requested, &expires)
	if err != nil {
		return false, err
	}
	if attempts == 0 {
		return false, ErrConflict
	}
	a, err := scanMacApp(tx.QueryRowContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.current_attempt_id=$1 AND a.device_id=$2`, attempt, d.ID))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	mutation := kind == "install" || kind == "remove"
	if mutation {
		if a.AcceptedAt != nil || (a.Status != "sent" && a.Status != "not_now" && a.Status != "uncertain") {
			return false, nil
		}
	} else if previous != "sent" && previous != "not_now" {
		return false, nil
	}
	if status == "NotNow" {
		if previous == "not_now" {
			return true, nil
		}
		if !expires.After(time.Now()) {
			if mutation {
				err = s.finishMacApp(ctx, tx, attempt, "expired", "deferred_beyond_deadline")
				if err == nil {
					err = auditOutcome(ctx, tx, d.TenantID, "device:"+d.ID, "apple.software.expired", attempt, "cancelled")
				}
			}
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='not_now',available_at=clock_timestamp()+interval '1 minute',completed_at=NULL WHERE id=$1`, command); err != nil {
			return false, err
		}
		if mutation {
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET status='not_now' WHERE id=$1`, attempt); err != nil {
				return false, err
			}
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET status='not_now',updated_at=clock_timestamp() WHERE current_attempt_id=$1`, attempt)
		}
		if err == nil {
			err = auditOutcome(ctx, tx, d.TenantID, "device:"+d.ID, "apple.software.command.not_now", attempt, "deferred")
		}
		return true, err
	}
	if status != "Acknowledged" && status != "Error" && status != "CommandFormatError" {
		return false, ErrMacApp
	}
	next, detail, outcome := "acknowledged", "", "success"
	if status != "Acknowledged" {
		next, detail, outcome = "failed", "Managed application command failed", "failure"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status=$2,error=$3,payload='\x',completed_at=clock_timestamp() WHERE id=$1`, command, next, detail); err != nil {
		return false, err
	}
	if mutation {
		if next == "failed" {
			err = s.finishMacApp(ctx, tx, attempt, "failed", "command_failed")
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET status='verifying',accepted_at=clock_timestamp(),error='' WHERE id=$1`, attempt)
			if err == nil {
				_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET status='verifying',updated_at=clock_timestamp(),next_check_at=clock_timestamp() WHERE current_attempt_id=$1`, attempt)
			}
		}
	} else if next == "acknowledged" {
		err = s.recordMacAppObservation(ctx, tx, a, kind, requested, message)
		if errors.Is(err, ErrMacApp) {
			next, outcome = "failed", "failure"
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='failed',error='Invalid application inventory' WHERE id=$1`, command)
			if err == nil {
				_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET error='invalid_application_inventory' WHERE id=$1`, attempt)
			}
		}
	}
	if err != nil {
		return false, err
	}
	return false, auditOutcome(ctx, tx, d.TenantID, "device:"+d.ID, "apple.software.command."+next, attempt, outcome)
}

func (s *Store) recordMacAppObservation(ctx context.Context, tx *sql.Tx, a *MacAppAssignment, kind string, requested time.Time, message map[string]any) error {
	previous := a.ManagedAt
	if kind == "installed" {
		previous = a.InstalledAt
	}
	if requested.After(time.Now()) || a.DispatchedAt == nil || requested.Before(*a.DispatchedAt) || (previous != nil && !requested.After(*previous)) {
		return nil
	}
	var observation macAppObservation
	var err error
	if kind == "managed" {
		observation, err = macAppManagedObservation(message["ManagedApplicationList"], a.Version.Identifier)
	} else {
		observation, err = macAppInstalledObservation(message["InstalledApplicationList"], a.Version.Identifier)
	}
	if err != nil {
		// Do not retain untrusted errors or retry the same malformed response.
		return ErrMacApp
	}
	if kind == "managed" {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET managed_state=$2,managed_at=$3 WHERE id=$1`, a.AttemptID, observation.State, requested)
		a.ManagedState, a.ManagedAt = observation.State, &requested
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET installed_state=$2,installed_version=$3,installed_at=$4 WHERE id=$1`, a.AttemptID, observation.State, observation.Version, requested)
		a.InstalledState, a.InstalledVersion, a.InstalledAt = observation.State, observation.Version, &requested
	}
	if err == nil && kind == "managed" && observation.State == "failed" && a.Status == "verifying" && a.AcceptedAt != nil && !requested.Before(*a.AcceptedAt) {
		return s.failMacAppObservation(ctx, tx, a)
	}
	if err != nil || a.AcceptedAt == nil || a.ManagedAt == nil || a.InstalledAt == nil || a.ManagedAt.Before(time.Now().Add(-24*time.Hour)) || a.InstalledAt.Before(time.Now().Add(-24*time.Hour)) || a.ManagedAt.Before(*a.AcceptedAt) || a.InstalledAt.Before(*a.AcceptedAt) {
		return err
	}
	if a.Status != "verifying" && a.Status != "verified" && a.Status != "drifted" && a.Status != "uncertain" {
		return nil
	}
	state := "verifying"
	ready := a.Operation == "install" && a.ManagedState == "managed" && a.InstalledState == "installed" && a.InstalledVersion == a.Version.Version
	ready = ready || (a.Operation == "remove" && (a.ManagedState == "absent" || a.ManagedState == "uninstalled") && a.InstalledState == "absent")
	if ready {
		state = "verified"
	} else if a.Status == "verified" || a.Status == "drifted" {
		state = "drifted"
	} else if a.ManagedState == "failed" {
		return s.failMacAppObservation(ctx, tx, a)
	} else if time.Since(*a.AcceptedAt) > 24*time.Hour {
		state = "uncertain"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET status=$2,error='' WHERE id=$1`, a.AttemptID, state); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET status=$2,updated_at=clock_timestamp(),next_check_at=clock_timestamp()+CASE WHEN $2 IN ('verified','drifted') THEN interval '6 hours' WHEN $2='uncertain' THEN interval '15 minutes' ELSE interval '1 minute' END WHERE current_attempt_id=$1`, a.AttemptID, state); err != nil {
		return err
	}
	if state != a.Status {
		outcome := "success"
		if state == "drifted" || state == "uncertain" {
			outcome = "failure"
		}
		return auditOutcome(ctx, tx, a.TenantID, "device:"+a.DeviceID, "apple.software."+state, a.AttemptID, outcome)
	}
	return nil
}

func (s *Store) failMacAppObservation(ctx context.Context, tx *sql.Tx, a *MacAppAssignment) error {
	if err := s.finishMacApp(ctx, tx, a.AttemptID, "failed", "installation_failed"); err != nil {
		return err
	}
	return auditOutcome(ctx, tx, a.TenantID, "device:"+a.DeviceID, "apple.software.failed", a.AttemptID, "failure")
}

func (s *Store) reconcileMacApps(ctx context.Context, tx *sql.Tx, d *Device) error {
	if err := s.reconcileMacAppExpiry(ctx, tx, d); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.device_id=$1 AND a.tenant_id=$2 AND a.next_check_at<=clock_timestamp() AND a.status IN ('queued','sent','not_now','verifying','verified','drifted','uncertain') ORDER BY a.next_check_at,a.id LIMIT 25`, d.ID, d.TenantID)
	if err != nil {
		return err
	}
	items := []*MacAppAssignment{}
	for rows.Next() {
		a, e := scanMacApp(rows)
		if e != nil {
			rows.Close()
			return e
		}
		items = append(items, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, a := range items {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET next_check_at=clock_timestamp()+interval '15 minutes' WHERE id=$1`, a.ID); err != nil {
			return err
		}
		if a.DispatchedAt != nil && macAppDeviceReady(*d, time.Now()) {
			if err = s.queueMacAppObservation(ctx, tx, d, a); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) ReconcileMacApps(ctx context.Context) error {
	for range 25 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE status='enrolled' AND id IN (SELECT device_id FROM mdm_apple_app_assignments WHERE status IN ('queued','sent','not_now','verifying','verified','drifted','uncertain') AND next_check_at<=clock_timestamp()) ORDER BY (SELECT min(next_check_at) FROM mdm_apple_app_assignments WHERE device_id=mdm_apple_devices.id AND status IN ('queued','sent','not_now','verifying','verified','drifted','uncertain')),id LIMIT 1 FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			return nil
		}
		if err == nil {
			err = s.reconcileMacApps(ctx, tx, d)
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

func (s *Store) cancelMacApps(ctx context.Context, tx *sql.Tx, device string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_app_attempts SET status=CASE WHEN status IN ('sent','verifying','uncertain') THEN 'uncertain' ELSE 'cancelled' END,error='enrollment_ended' WHERE device_id=$1 AND status IN ('queued','sent','not_now','verifying','uncertain')`, device); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET status='not_managed',updated_at=clock_timestamp() WHERE device_id=$1`, device); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET payload='\x',status=CASE WHEN status IN ('queued','sent','not_now') THEN 'cancelled' ELSE status END WHERE device_id=$1 AND managed_app`, device)
	return err
}
