package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// Metadata never contains a password or hash. Acknowledgement means that macOS
// processed the command, not that login or Secure Token authentication was tested.
type MacAdminAccount struct {
	Options                                                  MacAdminOptions
	CreationState, GUID, InventoryState, CurrentKeyID, Error string
	LatestStatus, LatestOperation                            string
	ObservedAt, AcceptedAt, NextRotationAt                   *time.Time
}
type MacAdminKey struct {
	ID, Operation, Status string
	Current               bool
	CreatedAt             time.Time
	CompletedAt           *time.Time
}

const macAdminColumns = `options,creation_state,COALESCE(guid::text,''),inventory_state,COALESCE(current_key_id::text,''),error,observed_at,accepted_at,next_rotation_at,COALESCE((SELECT status FROM mdm_apple_mac_admin_keys k WHERE k.device_id=a.device_id ORDER BY created_at DESC,id DESC LIMIT 1),''),COALESCE((SELECT operation FROM mdm_apple_mac_admin_keys k WHERE k.device_id=a.device_id ORDER BY created_at DESC,id DESC LIMIT 1),'')`

func scanMacAdmin(row scanner) (*MacAdminAccount, error) {
	var a MacAdminAccount
	var options []byte
	err := row.Scan(&options, &a.CreationState, &a.GUID, &a.InventoryState, &a.CurrentKeyID, &a.Error, &a.ObservedAt, &a.AcceptedAt, &a.NextRotationAt, &a.LatestStatus, &a.LatestOperation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(options, &a.Options) != nil || a.Options.Validate() != nil {
		return nil, ErrMacAdmin
	}
	return &a, nil
}
func (s *Store) MacAdmin(ctx context.Context, scope Scope, id string) (*MacAdminAccount, error) {
	if scope.Validate() != nil {
		return nil, ErrMacAdmin
	}
	return scanMacAdmin(s.db.QueryRowContext(ctx, `SELECT `+macAdminColumns+` FROM mdm_apple_mac_admin_accounts a JOIN mdm_apple_devices d ON d.id=a.device_id AND d.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.device_id=$2 AND ($3=0 OR d.site_id=$3)`, scope.TenantID, id, scope.SiteID))
}
func macAdminAccountTx(ctx context.Context, tx *sql.Tx, d *Device) (*MacAdminAccount, error) {
	return scanMacAdmin(tx.QueryRowContext(ctx, `SELECT `+macAdminColumns+` FROM mdm_apple_mac_admin_accounts a WHERE tenant_id=$1 AND device_id=$2`, d.TenantID, d.ID))
}
func (s *Store) MacAdminKeys(ctx context.Context, scope Scope, id string) ([]MacAdminKey, error) {
	if _, err := s.Device(ctx, scope, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT k.id,k.operation,k.status,COALESCE(k.id=a.current_key_id,false),k.created_at,k.completed_at FROM mdm_apple_mac_admin_keys k JOIN mdm_apple_mac_admin_accounts a ON a.device_id=k.device_id JOIN mdm_apple_devices d ON d.id=k.device_id AND d.tenant_id=k.tenant_id WHERE k.tenant_id=$1 AND k.device_id=$2 AND ($3=0 OR d.site_id=$3) ORDER BY k.created_at DESC,k.id DESC LIMIT 128`, scope.TenantID, id, scope.SiteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MacAdminKey{}
	for rows.Next() {
		var k MacAdminKey
		if err = rows.Scan(&k.ID, &k.Operation, &k.Status, &k.Current, &k.CreatedAt, &k.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
func (a *MacAdminAccount) RotationReason(d Device, now time.Time) string {
	if a == nil {
		return "This enrollment has no managed administrator policy."
	}
	if !macAdminDeviceReady(d, now) {
		return "Refresh inventory on an enrolled, supervised ADE Mac with a valid management identity."
	}
	if a.CreationState != "accepted" || a.CurrentKeyID == "" || a.GUID == "" || a.InventoryState != "present" || a.ObservedAt == nil || a.ObservedAt.After(now) || a.ObservedAt.Before(now.Add(-24*time.Hour)) {
		return "Wait for a current report of the administrator created by this enrollment."
	}
	if a.LatestStatus == "queued" || a.LatestStatus == "sent" || a.LatestStatus == "not_now" || a.LatestStatus == "uncertain" {
		return "The previous password operation remains unresolved."
	}
	return ""
}
func macAdminDeviceReady(d Device, now time.Time) bool {
	return d.Status == "enrolled" && d.EnrollmentMethod == "automated_device" && d.Family() == PlatformMacOS && versionPattern.MatchString(d.OSVersion) && CompareVersions(d.OSVersion, "10.11") >= 0 && d.SupervisedReported && d.Supervised && d.InventoryAt != nil && !d.InventoryAt.After(now) && d.InventoryAt.After(now.Add(-24*time.Hour)) && d.CertificateExpiresAt.After(now.Add(time.Minute))
}
func (s *Store) RequestMacAdmin(ctx context.Context, scope Scope, id, operation, actor string, permissions *access.Store) error {
	return s.requestMacAdmin(ctx, scope, id, operation, actor, recoveryLockAuthorize(scope, actor, permissions, access.ManageDeviceSecurity))
}
func (s *Store) requestMacAdmin(ctx context.Context, scope Scope, id, operation, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if actor == "" || len(actor) > 255 || (operation != "rotate" && operation != "retry_creation") {
		return ErrMacAdmin
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			return err
		}
	}
	d, err := lockFileVaultDevice(ctx, tx, scope, id)
	if err != nil {
		return err
	}
	if err = s.reconcileMacAdminExpiry(ctx, tx, d); err != nil {
		return err
	}
	a, err := macAdminAccountTx(ctx, tx, d)
	if err != nil {
		return err
	}
	if a == nil {
		return ErrMacAdmin
	}
	if operation == "rotate" {
		if a.RotationReason(*d, time.Now()) != "" {
			return ErrConflict
		}
	} else if a.CreationState != "failed" && a.CreationState != "expired" {
		return ErrConflict
	}
	if err = s.queueMacAdmin(ctx, tx, d, a, operation == "rotate", actor); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) queueMacAdmin(ctx context.Context, tx *sql.Tx, d *Device, a *MacAdminAccount, rotate bool, actor string) error {
	if !macAdminDeviceReady(*d, time.Now()) {
		return ErrMacAdmin
	}
	var awaiting, complete, active bool
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(awaiting_configuration,false),setup_state='complete',EXISTS(SELECT 1 FROM mdm_apple_mac_admin_keys WHERE device_id=$1 AND status IN ('queued','sent','not_now','uncertain')),(SELECT count(*) FROM mdm_apple_mac_admin_keys WHERE device_id=$1) FROM mdm_apple_ade_admissions WHERE tenant_id=$2 AND device_id=$1`, d.ID, d.TenantID).Scan(&awaiting, &complete, &active, &count)
	if err != nil {
		return err
	}
	if active || count >= 128 || (rotate && (!complete || awaiting || a.RotationReason(*d, time.Now()) != "")) || (!rotate && (!awaiting || complete || a.CreationState == "accepted")) {
		return ErrConflict
	}
	password, err := newRecoveryLockPassword()
	if err != nil {
		return ErrMacAdmin
	}
	defer clear(password)
	key := uuid.NewString()
	sealed, err := s.secrets.seal(password, secretPurpose(d.TenantID, key, "mac_admin_password"))
	if err != nil {
		return err
	}
	hash, err := macAdminPasswordHash(password)
	if err != nil {
		return err
	}
	defer clear(hash)
	kind, operation, guid := "AccountConfiguration", "create", ""
	if rotate {
		kind, operation, guid = "SetAutoAdminPassword", "rotate", a.GUID
	}
	args, err := macAdminCommandArguments(kind, a.Options, guid, hash)
	if err != nil {
		return err
	}
	command, err := s.enqueue(ctx, tx, d, kind, args, nil, nil)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET mac_admin=true,expires_at=clock_timestamp()+interval '1 day' WHERE id=$1`, command); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_mac_admin_keys(id,tenant_id,device_id,password,operation,status,command_id) VALUES($1,$2,$3,$4,$5,'queued',$6)`, key, d.TenantID, d.ID, sealed, operation, command); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_admin_accounts SET creation_state=CASE WHEN $2 THEN creation_state ELSE 'queued' END,error='',next_rotation_at=NULL WHERE device_id=$1`, d.ID, rotate); err != nil {
		return err
	}
	return audit(ctx, tx, d.TenantID, actor, "apple.mac_admin."+operation, command)
}
func (s *Store) RevealMacAdminPassword(ctx context.Context, scope Scope, device, key, actor string, permissions *access.Store) ([]byte, error) {
	return s.revealMacAdminPassword(ctx, scope, device, key, actor, recoveryLockAuthorize(scope, actor, permissions, access.RetrieveRecoveryKeys))
}
func (s *Store) revealMacAdminPassword(ctx context.Context, scope Scope, device, key, actor string, authorize func(context.Context, *sql.Tx) error) ([]byte, error) {
	parsed, err := uuid.Parse(key)
	if err != nil || parsed == uuid.Nil || parsed.String() != key || actor == "" || len(actor) > 255 {
		return nil, ErrMacAdmin
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			return nil, err
		}
	}
	d, err := lockFileVaultDevice(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	var sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT password FROM mdm_apple_mac_admin_keys WHERE tenant_id=$1 AND device_id=$2 AND id=$3`, d.TenantID, d.ID, key).Scan(&sealed); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(sealed, secretPurpose(d.TenantID, key, "mac_admin_password"))
	if err != nil {
		return nil, ErrMacAdmin
	}
	if !validMacAdminPassword(plain) {
		clear(plain)
		return nil, ErrMacAdmin
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.mac_admin.password.reveal", key); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(plain)
		return nil, err
	}
	return plain, nil
}
