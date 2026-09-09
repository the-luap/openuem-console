package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type ADEDeviceEnrollment struct {
	ServerID, ProfileID, ProfileName, SetupState, SetupError string
	Removable                                                bool
	CreatedAt, ExpiresAt                                     time.Time
	AwaitingConfiguration                                    *bool
	SetupUpdatedAt                                           *time.Time
}

func (s *Store) ADEDeviceEnrollment(ctx context.Context, scope Scope, id string) (*ADEDeviceEnrollment, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	var v ADEDeviceEnrollment
	err := s.db.QueryRowContext(ctx, `SELECT a.server_id,a.profile_id,p.name,a.setup_state,a.setup_error,p.removable,a.created_at,a.expires_at,a.awaiting_configuration,a.setup_updated_at FROM mdm_apple_ade_admissions a JOIN mdm_apple_ade_profiles p ON p.id=a.profile_id AND p.tenant_id=a.tenant_id JOIN mdm_apple_devices d ON d.id=a.device_id AND d.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.device_id=$2 AND ($3=0 OR d.site_id=$3)`, scope.TenantID, id, scope.SiteID).Scan(&v.ServerID, &v.ProfileID, &v.ProfileName, &v.SetupState, &v.SetupError, &v.Removable, &v.CreatedAt, &v.ExpiresAt, &v.AwaitingConfiguration, &v.SetupUpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &v, err
}

// A false report means the MDM hold ended, not that every Setup Assistant pane
// or account setup finished. Once released, late true reports cannot reopen this
// enrollment; a new activation requires a separately armed admission.
func (s *Store) recordADEAwaiting(ctx context.Context, tx *sql.Tx, d *Device, message map[string]any) error {
	if d.EnrollmentMethod != "automated_device" {
		return nil
	}
	v, present := message["AwaitingConfiguration"]
	if !present {
		return nil
	}
	awaiting, ok := v.(bool)
	if !ok {
		return ErrUnauthorized
	}
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT setup_state FROM mdm_apple_ade_admissions WHERE tenant_id=$1 AND device_id=$2`, d.TenantID, d.ID).Scan(&state); err != nil {
		return err
	}
	if state == "complete" {
		return nil
	}
	next := state
	if !awaiting && state != "not_requested" {
		next = "complete"
	} else if awaiting && (state == "pending" || state == "not_requested") {
		next = "awaiting"
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET awaiting_configuration=$3,awaiting_reported_at=clock_timestamp(),setup_state=$4,setup_error=CASE WHEN $4='complete' THEN '' ELSE setup_error END,setup_updated_at=clock_timestamp(),next_setup_at=clock_timestamp() WHERE tenant_id=$1 AND device_id=$2`, d.TenantID, d.ID, awaiting, next)
	if err != nil {
		return err
	}
	if !awaiting {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',completed_at=clock_timestamp() WHERE tenant_id=$1 AND device_id=$2 AND ade_setup AND status IN ('queued','sent','not_now')`, d.TenantID, d.ID); err != nil {
			return err
		}
	}
	if next != state {
		return audit(ctx, tx, d.TenantID, "device:"+d.ID, "apple.enrollment.ade.setup."+next, d.ID)
	}
	return nil
}

func (s *Store) reconcileADESetup(ctx context.Context, tx *sql.Tx, d *Device) error {
	if d.EnrollmentMethod != "automated_device" || d.Status != "enrolled" {
		return nil
	}
	var state, commandID, commandState string
	var awaiting, reportedFresh bool
	err := tx.QueryRowContext(ctx, `SELECT a.setup_state,COALESCE(a.awaiting_configuration,false),COALESCE(a.awaiting_reported_at>=a.setup_verify_after,false),COALESCE(a.setup_command_id::text,''),COALESCE(c.status,'') FROM mdm_apple_ade_admissions a LEFT JOIN mdm_apple_commands c ON c.id=a.setup_command_id WHERE a.tenant_id=$1 AND a.device_id=$2`, d.TenantID, d.ID).Scan(&state, &awaiting, &reportedFresh, &commandID, &commandState)
	if err != nil {
		return err
	}
	if !awaiting || !reportedFresh || state == "complete" || state == "not_requested" || state == "failed" {
		return nil
	}
	if commandID != "" && (commandState == "failed" || commandState == "expired" || commandState == "cancelled") {
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET setup_state='failed',setup_error='command_failed',setup_updated_at=clock_timestamp() WHERE device_id=$1`, d.ID)
		return err
	}
	if commandState == "acknowledged" {
		return nil
	}
	var platform Platform
	var version string
	if err = tx.QueryRowContext(ctx, `SELECT platform,os_version FROM mdm_apple_devices WHERE id=$1`, d.ID).Scan(&platform, &version); err != nil {
		return err
	}
	supported := platform == PlatformMacOS && CompareVersions(version, "10.11") >= 0 || (platform == PlatformIOS || platform == PlatformIPadOS) && CompareVersions(version, "9.0") >= 0
	if !supported {
		return nil
	}
	var ready bool
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(d.inventory_at>=a.created_at AND d.profiles_at>=a.created_at AND NOT EXISTS(SELECT 1 FROM mdm_apple_profile_assignments p WHERE p.device_id=d.id AND p.status<>'verified') AND NOT EXISTS(SELECT 1 FROM mdm_apple_mac_admin_accounts ma WHERE ma.device_id=d.id AND ma.creation_state<>'accepted'),false) FROM mdm_apple_devices d JOIN mdm_apple_ade_admissions a ON a.device_id=d.id AND a.tenant_id=d.tenant_id WHERE d.tenant_id=$1 AND d.id=$2`, d.TenantID, d.ID).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET setup_error='configuration_pending',next_setup_at=clock_timestamp()+interval '1 minute' WHERE device_id=$1`, d.ID); err != nil {
			return err
		}
		if commandID != "" {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET available_at=clock_timestamp()+interval '15 seconds' WHERE id=$1 AND status IN ('queued','sent','not_now')`, commandID)
		}
		return err
	}
	if commandID != "" {
		return nil
	}
	commandID, err = s.enqueue(ctx, tx, d, "DeviceConfigured", nil, nil, nil)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET ade_setup=true WHERE id=$1`, commandID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET setup_state='releasing',setup_command_id=$2,setup_error='',setup_updated_at=clock_timestamp() WHERE device_id=$1`, d.ID, commandID); err != nil {
		return err
	}
	return audit(ctx, tx, d.TenantID, "system", "apple.enrollment.ade.setup.release", d.ID)
}

func (s *Store) adeSetupCommandResult(ctx context.Context, tx *sql.Tx, d *Device, id, status string) error {
	var current bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_ade_admissions WHERE tenant_id=$1 AND device_id=$2 AND setup_command_id=$3 AND setup_state<>'complete')`, d.TenantID, d.ID, id).Scan(&current); err != nil {
		return err
	}
	if !current {
		return nil
	}
	switch status {
	case "failed":
		_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET setup_state='failed',setup_error='command_failed',setup_updated_at=clock_timestamp() WHERE device_id=$1`, d.ID)
		return err
	case "acknowledged":
		// Delivery acknowledgement is insufficient. Ask for the actual hold
		// state before describing the MDM configuration phase as released.
		_, err := s.enqueue(ctx, tx, d, "DeviceInformation", map[string]any{"Queries": inventoryQueriesFor(*d)}, nil, nil)
		return err
	}
	return nil
}

func (s *Store) RetryADESetup(ctx context.Context, scope Scope, id, actor string, permissions *access.Store) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if permissions == nil {
		return access.ErrDenied
	}
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.EnrollDevices, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		return err
	}
	return s.retryADESetupTx(ctx, tx, scope, id, actor)
}

func (s *Store) retryADESetupTx(ctx context.Context, tx *sql.Tx, scope Scope, id, actor string) error {
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, scope.TenantID, id, scope.SiteID))
	if err != nil {
		return err
	}
	if d.Status != "enrolled" || d.EnrollmentMethod != "automated_device" {
		return ErrConflict
	}
	r, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET setup_state='awaiting',setup_command_id=NULL,setup_error='',setup_verify_after=clock_timestamp(),setup_updated_at=clock_timestamp(),next_setup_at=clock_timestamp() WHERE device_id=$1 AND setup_state='failed' AND awaiting_configuration=true`, id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if _, err = s.enqueue(ctx, tx, d, "DeviceInformation", map[string]any{"Queries": inventoryQueriesFor(*d)}, nil, nil); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.enrollment.ade.setup.retry", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReconcileADESetups(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions a SET retry_profile=NULL FROM mdm_apple_devices d WHERE d.id=a.device_id AND a.retry_profile IS NOT NULL AND (a.expires_at<=clock_timestamp() OR d.status<>'authenticating')`); err != nil {
		return err
	}
	for range 25 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE status='enrolled' AND id IN (SELECT device_id FROM mdm_apple_ade_admissions WHERE awaiting_configuration=true AND setup_state IN ('awaiting','releasing') AND next_setup_at<=clock_timestamp()) ORDER BY (SELECT next_setup_at FROM mdm_apple_ade_admissions WHERE device_id=mdm_apple_devices.id),id LIMIT 1 FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET next_setup_at=clock_timestamp()+interval '1 minute' WHERE device_id=$1`, d.ID); err == nil {
			err = s.reconcileADESetup(ctx, tx, d)
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

func (s *Store) cancelADESetup(ctx context.Context, tx *sql.Tx, id string) error {
	if err := s.cancelMacAdmin(ctx, tx, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET retry_profile=NULL,setup_state=CASE WHEN setup_state IN ('complete','not_requested') THEN setup_state ELSE 'cancelled' END,setup_error='',setup_updated_at=clock_timestamp() WHERE device_id=$1`, id)
	return err
}
