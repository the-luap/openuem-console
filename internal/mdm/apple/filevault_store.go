package apple

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// FileVault contains lifecycle metadata only. Neither CMS envelopes nor
// decrypted keys are part of device inventory, command history or this model.
type FileVault struct {
	HistoricalRotationsPending       int                  `json:"historical_rotations_pending"`
	HistoricalRotationsNeedAttention bool                 `json:"historical_rotations_need_attention"`
	Rotation                         *FileVaultRotation   `json:"rotation,omitempty"`
	RotationReady                    bool                 `json:"rotation_ready"`
	Validation                       *FileVaultValidation `json:"validation,omitempty"`
	ValidationReady                  bool                 `json:"validation_ready"`
	DeviceID                         string               `json:"device_id"`
	Desired                          string               `json:"desired"`
	Phase                            string               `json:"phase"`
	Error                            string               `json:"error"`
	RecoveryError                    string               `json:"recovery_error"`
	KeyID                            string               `json:"key_id,omitempty"`
	EscrowedAt                       *time.Time           `json:"escrowed_at"`
	ObservedAt                       *time.Time           `json:"observed_at"`
	VerifiedAt                       *time.Time           `json:"verified_at"`
	UpdatedAt                        time.Time            `json:"updated_at"`
}

type FileVaultKeyHistory struct {
	ID         string     `json:"id"`
	Current    bool       `json:"current"`
	CreatedAt  time.Time  `json:"created_at"`
	ObservedAt time.Time  `json:"observed_at"`
	VerifiedAt *time.Time `json:"verified_at"`
}

func (s *Store) FileVaultKeyHistory(ctx context.Context, scope Scope, device string) ([]FileVaultKeyHistory, error) {
	if _, err := s.Device(ctx, scope, device); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT k.id,k.id=p.current_key_id,k.created_at,k.observed_at,k.verified_at FROM mdm_apple_filevault_keys k JOIN mdm_apple_filevault_policies p ON p.device_id=k.device_id WHERE p.device_id=$1 AND p.tenant_id=$2 AND ($3=0 OR p.site_id=$3) ORDER BY k.created_at DESC,k.id DESC LIMIT 128`, device, scope.TenantID, scope.SiteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []FileVaultKeyHistory{}
	for rows.Next() {
		var key FileVaultKeyHistory
		if err = rows.Scan(&key.ID, &key.Current, &key.CreatedAt, &key.ObservedAt, &key.VerifiedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) FileVault(ctx context.Context, scope Scope, id string) (*FileVault, error) {
	d, err := s.Device(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	v := &FileVault{}
	err = s.db.QueryRowContext(ctx, `SELECT p.device_id,p.desired,
 CASE WHEN c.status IN ('failed','expired','cancelled') AND p.phase NOT IN ('active','removed','not_managed','failed') THEN 'failed' ELSE p.phase END,
 CASE WHEN c.status IN ('failed','expired','cancelled') AND p.error='' THEN 'command_failed' ELSE p.error END,
 p.recovery_error,COALESCE(p.current_key_id::text,''),k.created_at,k.observed_at,k.verified_at,p.updated_at
 FROM mdm_apple_filevault_policies p LEFT JOIN mdm_apple_commands c ON c.id=p.command_id
 LEFT JOIN mdm_apple_filevault_keys k ON k.id=p.current_key_id
 WHERE p.device_id=$1 AND p.tenant_id=$2 AND ($3=0 OR p.site_id=$3)`, id, scope.TenantID, scope.SiteID).Scan(&v.DeviceID, &v.Desired, &v.Phase, &v.Error, &v.RecoveryError, &v.KeyID, &v.EscrowedAt, &v.ObservedAt, &v.VerifiedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err == nil {
		err = s.fileVaultValidationMetadata(ctx, d, v)
	}
	if err == nil {
		err = s.fileVaultRotationMetadata(ctx, d, v)
	}
	if err == nil {
		err = s.fileVaultHistoryMetadata(ctx, d, v)
	}
	return v, err
}

func lockFileVaultDevice(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*Device, error) {
	if scope.Validate() != nil {
		return nil, ErrFileVault
	}
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrFileVault
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	var site int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, d.SiteID, d.TenantID).Scan(&site); err != nil {
		return nil, ErrFileVault
	}
	return d, nil
}

// SetFileVault stages two separate profiles. A fresh, explicitly requested
// ProfileList must confirm escrow before deferred encryption can be delivered.
// Removing these profiles does not disable FileVault or delete recovery keys.
func (s *Store) SetFileVault(ctx context.Context, scope Scope, id, desired, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.setFileVault(ctx, scope, id, desired, actor, func(ctx context.Context, tx *sql.Tx) error {
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageDeviceSecurity, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
	})
}

func (s *Store) setFileVault(ctx context.Context, scope Scope, id, desired, actor string, authorize func(context.Context, *sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if actor == "" || len(actor) > 255 || (desired != "enabled" && desired != "removed") {
		return ErrFileVault
	}
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
	var rotating bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_filevault_rotations WHERE device_id=$1 AND status IN ('queued','uncertain'))`, d.ID).Scan(&rotating); err != nil {
		return err
	}
	if rotating {
		return ErrFileVault
	}
	if desired == "enabled" {
		if reason := d.FileVaultReason(time.Now()); reason != "" {
			return errors.New(reason)
		}
	} else if d.Status != "enrolled" || d.Family() != PlatformMacOS || !d.CertificateExpiresAt.After(time.Now()) {
		return ErrFileVault
	}
	if err = s.reconcileFileVault(ctx, tx, d); err != nil {
		return err
	}
	var oldDesired, phase string
	err = tx.QueryRowContext(ctx, `SELECT desired,phase FROM mdm_apple_filevault_policies WHERE device_id=$1`, id).Scan(&oldDesired, &phase)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && oldDesired == desired && phase != "failed" && phase != "not_managed" {
		return tx.Commit()
	}
	if errors.Is(err, sql.ErrNoRows) {
		if desired == "removed" {
			return ErrNotFound
		}
		escrow := uuid.NewString()
		certificate, private, err := newFileVaultCertificate(escrow)
		if err != nil {
			return err
		}
		defer clear(private)
		encrypted, err := s.secrets.seal(private, secretPurpose(d.TenantID, d.ID+"/"+escrow, "filevault_private_key"))
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_filevault_escrow(id,tenant_id,site_id,device_id,certificate,private_key,enable_uuid) VALUES($1,$2,$3,$4,$5,$6,$7)`, escrow, d.TenantID, d.SiteID, d.ID, certificate, encrypted, uuid.NewString()); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_filevault_policies(device_id,tenant_id,site_id,escrow_id,desired,phase) VALUES($1,$2,$3,$4,'enabled','preflight')`, d.ID, d.TenantID, d.SiteID, escrow); err != nil {
			return err
		}
	}
	if desired == "enabled" {
		var conflict bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_profile_assignments a JOIN mdm_apple_profiles p ON p.id=a.profile_id WHERE a.device_id=$1 AND (a.desired='installed' OR a.status<>'verified') AND p.payload_types ?| ARRAY['com.apple.security.FDERecoveryKeyEscrow','com.apple.security.FDERecoveryRedirect','com.apple.MCX.FileVault2','com.apple.MCX'])`, d.ID).Scan(&conflict); err != nil {
			return err
		}
		if conflict {
			return errors.New("Remove existing FileVault profile assignments and verify their removal first")
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET desired=$2,error='',updated_at=clock_timestamp() WHERE device_id=$1`, id, desired); err != nil {
		return err
	}
	phase = "preflight"
	if desired == "removed" {
		phase = "removing_enable"
	}
	if err = s.queueFileVaultPhase(ctx, tx, d, phase); err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.filevault."+desired, d.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) queueFileVaultPhase(ctx context.Context, tx *sql.Tx, d *Device, phase string) error {
	var escrow, enable string
	var certificate []byte
	if err := tx.QueryRowContext(ctx, `SELECT e.id,e.enable_uuid,e.certificate FROM mdm_apple_filevault_policies p JOIN mdm_apple_filevault_escrow e ON e.id=p.escrow_id WHERE p.device_id=$1 AND p.tenant_id=$2 AND p.site_id=$3`, d.ID, d.TenantID, d.SiteID).Scan(&escrow, &enable, &certificate); err != nil {
		return err
	}
	kind := "ProfileList"
	var args map[string]any
	switch phase {
	case "preflight", "verifying_escrow", "verifying_enable", "verifying_enable_removal", "verifying_removal":
	case "installing_escrow", "installing_enable":
		kind = "InstallProfile"
		profile, err := fileVaultProfile(d.ID, escrow, enable, certificate, phase == "installing_enable")
		if err != nil {
			return err
		}
		args = map[string]any{"Payload": profile}
	case "removing_enable", "removing_escrow":
		kind = "RemoveProfile"
		suffix := ".enable"
		if phase == "removing_escrow" {
			suffix = ".escrow"
		}
		args = map[string]any{"Identifier": fileVaultDomain + "." + d.ID + suffix}
	default:
		return ErrFileVault
	}
	// Every phase receives a new UUID. Late and duplicate receipts for earlier
	// attempts cannot advance the policy or supply its verification evidence.
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',payload='\x',completed_at=clock_timestamp() WHERE device_id=$1 AND filevault AND status IN ('queued','sent','not_now')`, d.ID); err != nil {
		return err
	}
	command, err := s.enqueue(ctx, tx, d, kind, args, nil, nil)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET filevault=true WHERE id=$1`, command); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET phase=$2,command_id=$3,error='',updated_at=clock_timestamp() WHERE device_id=$1`, d.ID, phase, command)
	return err
}

func (s *Store) reconcileFileVault(ctx context.Context, tx *sql.Tx, d *Device) error {
	var owned bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_filevault_policies WHERE device_id=$1)`, d.ID).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return nil
	}
	if d.Status == "enrolled" {
		if err := fileVaultSite(ctx, tx, d); err != nil {
			return err
		}
	}
	if d.Status != "enrolled" {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET phase='not_managed',command_id=NULL,error='',updated_at=clock_timestamp() WHERE device_id=$1 AND phase<>'not_managed'`, d.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',completed_at=clock_timestamp() WHERE device_id=$1 AND filevault AND status IN ('queued','sent','not_now')`, d.ID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET payload='\x' WHERE device_id=$1 AND filevault AND status NOT IN ('queued','sent','not_now') AND octet_length(payload)>0`, d.ID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies p SET phase='failed',error='command_failed',updated_at=clock_timestamp() FROM mdm_apple_commands c WHERE p.device_id=$1 AND c.id=p.command_id AND c.status IN ('failed','expired','cancelled') AND p.phase NOT IN ('failed','active','removed','not_managed')`, d.ID)
	return err
}

func (s *Store) fileVaultFailure(ctx context.Context, tx *sql.Tx, d *Device, code string) error {
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET phase='failed',error=$2,updated_at=clock_timestamp() WHERE device_id=$1`, d.ID, code)
	return err
}

func (s *Store) fileVaultCommandResult(ctx context.Context, tx *sql.Tx, d *Device, command, status string, message map[string]any) error {
	if status == "not_now" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET payload='\x' WHERE id=$1 AND filevault`, command); err != nil {
		return err
	}
	var phase, escrow, enable string
	err := tx.QueryRowContext(ctx, `SELECT p.phase,e.id,e.enable_uuid FROM mdm_apple_filevault_policies p JOIN mdm_apple_filevault_escrow e ON e.id=p.escrow_id WHERE p.device_id=$1 AND p.command_id=$2 AND p.tenant_id=$3 AND p.site_id=$4`, d.ID, command, d.TenantID, d.SiteID).Scan(&phase, &escrow, &enable)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = fileVaultSite(ctx, tx, d); err != nil {
		return err
	}
	if status != "acknowledged" {
		return s.fileVaultFailure(ctx, tx, d, "command_failed")
	}
	next := ""
	switch phase {
	case "installing_escrow":
		next = "verifying_escrow"
	case "installing_enable":
		next = "verifying_enable"
	case "removing_enable":
		next = "verifying_enable_removal"
	case "removing_escrow":
		next = "verifying_removal"
	case "preflight", "verifying_escrow", "verifying_enable", "verifying_enable_removal", "verifying_removal":
		var profiles []InstalledProfile
		if err = decodePlistValue(message["ProfileList"], &profiles); err != nil {
			return s.fileVaultFailure(ctx, tx, d, "invalid_profile_inventory")
		}
		escrowID, enableID := fileVaultDomain+"."+d.ID+".escrow", fileVaultDomain+"."+d.ID+".enable"
		escrowPresent, enablePresent, conflict := fileVaultProfileEvidence(profiles, escrowID, enableID, escrow, enable)
		if phase == "verifying_removal" || phase == "verifying_enable_removal" {
			for _, p := range profiles {
				if strings.EqualFold(p.Identifier, enableID) || (phase == "verifying_removal" && strings.EqualFold(p.Identifier, escrowID)) {
					return s.fileVaultFailure(ctx, tx, d, "profile_still_present")
				}
			}
			next = "removed"
			if phase == "verifying_enable_removal" {
				next = "removing_escrow"
			}
		} else {
			if conflict {
				return s.fileVaultFailure(ctx, tx, d, "conflicting_profile")
			}
			switch phase {
			case "preflight":
				next = "installing_escrow"
			case "verifying_escrow":
				if !escrowPresent {
					return s.fileVaultFailure(ctx, tx, d, "escrow_profile_missing")
				}
				if reason := d.FileVaultReason(time.Now()); reason != "" {
					return s.fileVaultFailure(ctx, tx, d, "security_inventory_required")
				}
				next = "installing_enable"
			case "verifying_enable":
				if !escrowPresent || !enablePresent {
					return s.fileVaultFailure(ctx, tx, d, "profile_missing")
				}
				next = "active"
			}
		}
	}
	if next == "active" || next == "removed" {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET phase=$2,command_id=NULL,error='',updated_at=clock_timestamp() WHERE device_id=$1`, d.ID, next); err != nil {
			return err
		}
		_, err = s.enqueue(ctx, tx, d, "SecurityInfo", nil, nil, nil)
		return err
	}
	if next == "" {
		return nil
	}
	return s.queueFileVaultPhase(ctx, tx, d, next)
}

func fileVaultProfileEvidence(profiles []InstalledProfile, escrowID, enableID, escrowUUID, enableUUID string) (escrow, enable, conflict bool) {
	seen := map[string]bool{}
	for _, p := range profiles {
		own := strings.EqualFold(p.Identifier, escrowID) || strings.EqualFold(p.Identifier, enableID)
		if own {
			id := strings.ToLower(p.Identifier)
			if seen[id] || !p.Managed {
				conflict = true
			}
			seen[id] = true
			if strings.EqualFold(p.Identifier, escrowID) {
				escrow = p.Managed && strings.EqualFold(p.UUID, escrowUUID)
				conflict = conflict || !escrow
			} else {
				enable = p.Managed && strings.EqualFold(p.UUID, enableUUID)
				conflict = conflict || !enable
			}
			continue
		}
		for _, payload := range p.Payloads {
			if fileVaultPayloadType(payload.Type) {
				conflict = true
			}
		}
	}
	return
}

func (s *Store) checkFileVaultProfiles(ctx context.Context, tx *sql.Tx, d *Device, command string, profiles []InstalledProfile) error {
	var escrow, enable string
	err := tx.QueryRowContext(ctx, `SELECT e.id,e.enable_uuid FROM mdm_apple_filevault_policies p JOIN mdm_apple_filevault_escrow e ON e.id=p.escrow_id JOIN mdm_apple_commands c ON c.id=$2 AND c.device_id=p.device_id AND c.created_at>=p.updated_at WHERE p.device_id=$1 AND p.phase='active'`, d.ID, command).Scan(&escrow, &enable)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	a, b, conflict := fileVaultProfileEvidence(profiles, fileVaultDomain+"."+d.ID+".escrow", fileVaultDomain+"."+d.ID+".enable", escrow, enable)
	if !a || !b || conflict {
		return s.fileVaultFailure(ctx, tx, d, "profile_drifted")
	}
	return nil
}

// ingestFileVaultRecovery accepts CMS only from this device's authenticated
// SecurityInfo receipt. A successfully decrypted key is escrowed, not verified:
// only an independent check against the volume may set verified_at.
func (s *Store) ingestFileVaultRecovery(ctx context.Context, tx *sql.Tx, d *Device, info map[string]any, command string) error {
	var escrow, current string
	err := tx.QueryRowContext(ctx, `SELECT escrow_id,COALESCE(current_key_id::text,'') FROM mdm_apple_filevault_policies WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3`, d.ID, d.TenantID, d.SiteID).Scan(&escrow, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = fileVaultSite(ctx, tx, d); err != nil {
		return err
	}
	value, exists := info["FDE_PersonalRecoveryKeyCMS"]
	if !exists {
		return nil
	}
	// An older queued inventory request may complete after a newer one. It
	// must not replace the current key with an earlier recovery observation.
	var requested time.Time
	err = tx.QueryRowContext(ctx, `SELECT c.created_at FROM mdm_apple_commands c JOIN mdm_apple_filevault_policies p ON p.device_id=c.device_id WHERE c.id::text=$1 AND c.device_id=$2 AND c.request_type='SecurityInfo' AND (p.recovery_requested_at IS NULL OR c.created_at>p.recovery_requested_at)`, command, d.ID).Scan(&requested)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	cms, ok := value.([]byte)
	if ok {
		defer clear(cms)
	}
	fail := func(code string) error {
		_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET recovery_error=$2 WHERE device_id=$1`, d.ID, code)
		return err
	}
	if !ok || len(cms) == 0 || len(cms) > maxFileVaultCMSBytes || stringValue(info, "FDE_PersonalRecoveryKeyDeviceKey") != d.ID {
		return fail("invalid_recovery_envelope")
	}
	certificate, private, err := s.fileVaultEscrowKey(ctx, tx, d, escrow)
	if err != nil {
		return err
	}
	key, err := decryptFileVaultRecoveryKey(cms, certificate, private)
	if err != nil {
		return fail("invalid_recovery_envelope")
	}
	defer clear(key)
	if current != "" {
		previous, err := s.openFileVaultKey(ctx, tx, d, current)
		if err != nil {
			return err
		}
		equal := subtle.ConstantTimeCompare(previous, key) == 1
		clear(previous)
		if equal {
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_keys SET observed_at=clock_timestamp() WHERE id=$1`, current); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET recovery_error='',recovery_requested_at=$2 WHERE device_id=$1`, d.ID, requested)
			return err
		}
	}
	id, err := s.retainFileVaultCandidate(ctx, tx, d, escrow, key, false, time.Now(), "escrow")
	if errors.Is(err, errRotationHistoryFull) {
		return fail("recovery_history_full")
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET current_key_id=$2,recovery_error='',recovery_requested_at=$3 WHERE device_id=$1`, d.ID, id, requested)
	return err
}

func (s *Store) fileVaultEscrowKey(ctx context.Context, tx *sql.Tx, d *Device, id string) (*x509.Certificate, *rsa.PrivateKey, error) {
	var certificate, encrypted []byte
	if err := tx.QueryRowContext(ctx, `SELECT certificate,private_key FROM mdm_apple_filevault_escrow WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND device_id=$4`, id, d.TenantID, d.SiteID, d.ID).Scan(&certificate, &encrypted); err != nil {
		return nil, nil, err
	}
	private, err := s.secrets.open(encrypted, secretPurpose(d.TenantID, d.ID+"/"+id, "filevault_private_key"))
	if err != nil {
		return nil, nil, ErrFileVault
	}
	defer clear(private)
	key, err := x509.ParsePKCS1PrivateKey(private)
	if err != nil {
		return nil, nil, ErrFileVault
	}
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, nil, ErrFileVault
	}
	return cert, key, nil
}

func (s *Store) openFileVaultKey(ctx context.Context, tx *sql.Tx, d *Device, id string) ([]byte, error) {
	var encrypted []byte
	if err := tx.QueryRowContext(ctx, `SELECT recovery_key FROM mdm_apple_filevault_keys WHERE id=$1 AND tenant_id=$2 AND device_id=$3`, id, d.TenantID, d.ID).Scan(&encrypted); err != nil {
		return nil, err
	}
	key, err := s.secrets.open(encrypted, secretPurpose(d.TenantID, d.ID+"/"+id, "filevault_recovery_key"))
	if err != nil {
		return nil, ErrFileVault
	}
	return key, nil
}

func fileVaultSite(ctx context.Context, tx *sql.Tx, d *Device) error {
	var site int
	if err := tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, d.SiteID, d.TenantID).Scan(&site); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthorized
		}
		return err
	}
	return nil
}

// RevealFileVaultKey returns a single explicitly selected history entry only
// after its audit event commits. Permission replacement is serialized with this
// read. The caller authenticates the session, enforces a non-cacheable
// CSRF-protected POST response, and clears the returned bytes.
func (s *Store) RevealFileVaultKey(ctx context.Context, scope Scope, device, keyID, actor string, permissions *access.Store) ([]byte, error) {
	if permissions == nil {
		return nil, access.ErrDenied
	}
	return s.revealFileVaultKey(ctx, scope, device, keyID, actor, func(ctx context.Context, tx *sql.Tx) error {
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.RetrieveRecoveryKeys, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
	})
}

func (s *Store) revealFileVaultKey(ctx context.Context, scope Scope, device, keyID, actor string, authorize func(context.Context, *sql.Tx) error) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if actor == "" || len(actor) > 255 {
		return nil, ErrFileVault
	}
	if _, err := uuid.Parse(keyID); err != nil {
		return nil, ErrFileVault
	}
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
	key, err := s.openFileVaultKey(ctx, tx, d, keyID)
	if err != nil {
		return nil, notFound(err)
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.filevault.key.reveal", keyID); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}
