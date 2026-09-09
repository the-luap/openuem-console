package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

func commandPayload(kind string, arguments map[string]any) ([]byte, string, error) {
	id := uuid.NewString()
	body := map[string]any{"RequestType": kind}
	for k, v := range arguments {
		if k == "RequestType" {
			return nil, "", errors.New("request type cannot be overridden")
		}
		body[k] = v
	}
	data, err := plist.Marshal(map[string]any{"CommandUUID": id, "Command": body}, plist.XMLFormat)
	return data, id, err
}

func (s *Store) enqueue(ctx context.Context, tx *sql.Tx, d *Device, kind string, args map[string]any, profileID any, revision any) (string, error) {
	data, id, err := commandPayload(kind, args)
	if err != nil {
		return "", err
	}
	data, err = s.secrets.seal(data, secretPurpose(d.TenantID, id, "command"))
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_commands(id,tenant_id,device_id,request_type,payload,profile_id,profile_revision) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, d.TenantID, d.ID, kind, data, profileID, revision)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_push_at=now() WHERE id=$1`, d.ID)
	return id, err
}

func (s *Store) RefreshInventory(ctx context.Context, scope Scope, id, actor string) error {
	d, err := s.Device(ctx, scope, id)
	if err != nil {
		return err
	}
	if d.Status != "enrolled" {
		return errors.New("device must be enrolled before inventory can be requested")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	d, err = scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if d.Status != "enrolled" {
		return errors.New("device is no longer enrolled")
	}
	if err = s.queueInventory(ctx, tx, d); err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.inventory.refresh", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) queueInventory(ctx context.Context, tx *sql.Tx, d *Device) error {
	return s.queuePlatformInventory(ctx, tx, d, true)
}

func (s *Store) queuePlatformInventory(ctx context.Context, tx *sql.Tx, d *Device, includeDevice bool) error {
	kinds := []string{}
	if includeDevice {
		kinds = append(kinds, "DeviceInformation")
	}
	kinds = append(kinds, inventoryKindsFor(*d)...)
	for _, kind := range kinds {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_commands WHERE device_id=$1 AND request_type=$2 AND status IN ('queued','sent','not_now') AND expires_at>now())`, d.ID, kind).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		args := map[string]any{}
		if kind == "DeclarativeManagement" {
			p, err := scanPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM mdm_apple_update_policies WHERE device_id=$1`, d.ID))
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			data, err := json.Marshal(Tokens(Declarations(*d, p)))
			if err != nil {
				return err
			}
			args["Data"] = data
		}
		if kind == "DeviceInformation" {
			args["Queries"] = inventoryQueriesFor(*d)
		}
		if kind == "InstalledApplicationList" && d.Family() != PlatformMacOS && CompareVersions(d.OSVersion, "7.0") >= 0 {
			args["ManagedAppsOnly"] = false
		}
		if _, err := s.enqueue(ctx, tx, d, kind, args, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Commands(ctx context.Context, scope Scope, id string) ([]Command, error) {
	if _, err := s.Device(ctx, scope, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,request_type,status,attempts,error,created_at,completed_at,EXISTS(SELECT 1 FROM mdm_apple_identity_renewals r WHERE r.command_id=mdm_apple_commands.id),mac_binding,filevault,recovery_lock,ade_setup,mac_admin FROM mdm_apple_commands WHERE tenant_id=$1 AND device_id=$2 ORDER BY created_at DESC LIMIT 100`, scope.TenantID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Command{}
	for rows.Next() {
		var c Command
		if err = rows.Scan(&c.ID, &c.DeviceID, &c.RequestType, &c.Status, &c.Attempts, &c.Error, &c.CreatedAt, &c.CompletedAt, &c.IdentityRenewal, &c.MacBinding, &c.FileVault, &c.RecoveryLock, &c.ADESetup, &c.MacAdmin); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (s *Store) CheckIn(ctx context.Context, d *Device, message map[string]any) error {
	if !deviceChannelMessage(message) {
		return ErrUnauthorized
	}
	udid := stringValue(message, "UDID")
	if udid == "" || len(udid) > 255 {
		return ErrUnauthorized
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 FOR UPDATE`, d.ID))
	if err != nil {
		return err
	}
	peer, err := s.deviceIdentityPeer(ctx, tx, d)
	if err != nil {
		return err
	}
	if peer.kind == "retired" {
		return ErrUnauthorized
	}
	if current.Status != "authenticating" && current.Status != "enrolled" {
		return ErrUnauthorized
	}
	if current.UDID != "" && current.UDID != udid {
		return ErrUnauthorized
	}
	kind := stringValue(message, "MessageType")
	if peer.kind == "candidate" && kind != "Authenticate" && kind != "TokenUpdate" {
		return ErrUnauthorized
	}
	if kind == "Authenticate" || kind == "TokenUpdate" {
		var topic string
		if err = tx.QueryRowContext(ctx, `SELECT topic FROM mdm_apple_settings WHERE tenant_id=$1`, current.TenantID).Scan(&topic); err != nil {
			return err
		}
		if stringValue(message, "Topic") != topic {
			return ErrUnauthorized
		}
	}
	switch kind {
	case "Authenticate":
		if err = s.validateADEIdentity(ctx, tx, current, udid, stringValue(message, "SerialNumber")); err != nil {
			return err
		}
		model, modelErr := reportedModel(message, current.Model)
		if modelErr != nil {
			return modelErr
		}
		if model != "" && DetectPlatform(model) == PlatformUnknown {
			return errors.New("only iPhone, iPad and Mac device enrollment is supported")
		}
		if current.EnrollmentPlatform != "" && model != "" && current.EnrollmentPlatform != DetectPlatform(model) {
			return errors.New("the device does not match the platform selected for enrollment")
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET udid=$1,serial_number=COALESCE(NULLIF($2,''),serial_number),model=$3,os_version=COALESCE(NULLIF($4,''),os_version),build_version=COALESCE(NULLIF($5,''),build_version),last_seen=now() WHERE id=$6`, udid, stringValue(message, "SerialNumber"), model, stringValue(message, "OSVersion"), stringValue(message, "BuildVersion"), current.ID)
	case "TokenUpdate":
		if current.UDID == "" {
			return ErrUnauthorized
		}
		if err = s.validateADEIdentity(ctx, tx, current, udid, ""); err != nil {
			return err
		}
		token, ok := message["Token"].([]byte)
		magic := stringValue(message, "PushMagic")
		if !ok || len(token) == 0 || len(token) > 512 || magic == "" || len(magic) > 1024 {
			return errors.New("TokenUpdate requires a valid push token and PushMagic")
		}
		if peer.kind == "candidate" {
			err = s.stageIdentityToken(ctx, tx, d, peer.renewalID, token, magic)
			break
		}
		token, err = s.secrets.seal(token, secretPurpose(current.TenantID, current.ID, "push_token"))
		if err != nil {
			return err
		}
		magicEncrypted, err := s.secrets.seal([]byte(magic), secretPurpose(current.TenantID, current.ID, "push_magic"))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET push_token=$1,push_magic=$2,status='enrolled',enrolled_at=COALESCE(enrolled_at,now()),last_seen=now(),next_push_at=now(),push_status='pending',push_error='' WHERE id=$3`, token, magicEncrypted, current.ID)
		if err != nil {
			return err
		}
		if current.Status != "enrolled" {
			if err = s.queueInventory(ctx, tx, current); err != nil {
				return err
			}
			// The enrollment batch already refreshes inventory. Avoid another
			// identical batch on the first background sweep after it completes.
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_inventory_at=now()+interval '6 hours' WHERE id=$1`, current.ID); err != nil {
				return err
			}
		}
		if err = s.recordADEAwaiting(ctx, tx, current, message); err != nil {
			return err
		}
	case "CheckOut":
		if current.UDID == "" {
			return ErrUnauthorized
		}
		if err = s.withdrawUserChannels(ctx, tx, current); err != nil {
			return err
		}

		if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_bootstrap_tokens WHERE device_id=$1`, current.ID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='unenrolled',push_token=NULL,push_magic=NULL,last_seen=now() WHERE id=$1`, current.ID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',completed_at=now() WHERE device_id=$1 AND status IN ('queued','sent','not_now')`, current.ID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_profile_assignments SET status='not_managed',updated_at=now() WHERE device_id=$1`, current.ID)
		if err == nil {
			err = s.cancelDeviceRenewal(ctx, tx, current)
		}
		if err == nil {
			err = s.cancelADESetup(ctx, tx, current.ID)
		}
		if err == nil {
			current.Status = "unenrolled"
			err = s.reconcileMacBindingsForDevice(ctx, tx, current)
		}
		if err == nil {
			err = s.reconcileFileVault(ctx, tx, current)
		}
		if err == nil {
			err = s.reconcileRecoveryLock(ctx, tx, current, false)
		}
	default:
		return errors.New("unsupported check-in message")
	}
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, current.TenantID, "device:"+current.ID, "apple.checkin."+kind, current.ID); err != nil {
		return err
	}
	// The device has demonstrated possession. Browser retries must now stop.
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_enrollment_claims SET profile=NULL WHERE device_id=$1`, current.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET retry_profile=NULL WHERE device_id=$1`, current.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func responseError(message map[string]any) string {
	chain, ok := message["ErrorChain"].([]any)
	if !ok {
		return "Device reported " + stringValue(message, "Status")
	}
	parts := []string{}
	for _, entry := range chain {
		if e, ok := entry.(map[string]any); ok {
			desc := stringValue(e, "LocalizedDescription")
			if desc == "" {
				desc = stringValue(e, "USEnglishDescription")
			}
			parts = append(parts, fmt.Sprintf("%s %v: %s", stringValue(e, "ErrorDomain"), e["ErrorCode"], desc))
		}
	}
	text := strings.Join(parts, "; ")
	if len(text) > 4096 {
		text = text[:4096]
	}
	return text
}

// Connect serializes the device's result ingestion and next-command delivery in
// a single transaction. Command IDs are checked against the authenticated device.
func (s *Store) Connect(ctx context.Context, d *Device, message map[string]any) ([]byte, error) {
	if stringValue(message, "UDID") != d.UDID || d.UDID == "" || !deviceChannelMessage(message) {
		return nil, ErrUnauthorized
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 FOR UPDATE`, d.ID))
	if err != nil {
		return nil, err
	}
	if current.Status != "enrolled" || current.UDID != d.UDID {
		return nil, ErrUnauthorized
	}
	peer, err := s.deviceIdentityPeer(ctx, tx, d)
	if err != nil {
		return nil, err
	}
	if peer.kind == "retired" {
		return nil, s.acknowledgeRetiredIdentity(ctx, tx, d, peer, message)
	}
	if peer.kind == "candidate" {
		candidateStatus := stringValue(message, "Status")
		var commandID string
		if candidateStatus != "Idle" {
			if err = tx.QueryRowContext(ctx, `SELECT command_id FROM mdm_apple_identity_renewals WHERE id=$1 AND device_id=$2`, peer.renewalID, d.ID).Scan(&commandID); err != nil {
				return nil, err
			}
			if stringValue(message, "CommandUUID") != commandID {
				return nil, ErrUnauthorized
			}
		}
		if candidateStatus == "Error" || candidateStatus == "CommandFormatError" {
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='failed',error=$2,completed_at=clock_timestamp() WHERE id=$1`, commandID, responseError(message)); err != nil {
				return nil, err
			}
			if err = s.finishIdentityRenewal(ctx, tx, d, peer.renewalID, "failed", "command_failed"); err != nil {
				return nil, err
			}
			if err = auditOutcome(ctx, tx, current.TenantID, "device:"+current.ID, "apple.command.failed", commandID, "failure"); err != nil {
				return nil, err
			}
			return nil, tx.Commit()
		}
		if !peer.tokenUpdated {
			return nil, ErrUnauthorized
		}
		if candidateStatus != "Idle" && candidateStatus != "Acknowledged" && candidateStatus != "NotNow" {
			return nil, ErrUnauthorized
		}
	}
	status := stringValue(message, "Status")
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='expired',payload='\x',error='Command expired before completion',completed_at=clock_timestamp() WHERE device_id=$1 AND (filevault OR recovery_lock) AND expires_at<=clock_timestamp() AND status IN ('queued','sent','not_now')`, current.ID); err != nil {
		return nil, err
	}
	stop := peer.kind == "candidate" && status == "NotNow"
	switch status {
	case "Idle":
	case "Acknowledged", "Error", "CommandFormatError", "NotNow":
		id := stringValue(message, "CommandUUID")
		if _, err := uuid.Parse(id); err != nil {
			return nil, errors.New("response requires a valid CommandUUID")
		}
		var kind, previous string
		var binding, filevault, recoveryLock, adeSetup, macAdmin bool
		var profileID sql.NullString
		var revision sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT request_type,status,profile_id,profile_revision,mac_binding,filevault,recovery_lock,ade_setup,mac_admin FROM mdm_apple_commands WHERE id=$1 AND device_id=$2 FOR UPDATE`, id, current.ID).Scan(&kind, &previous, &profileID, &revision, &binding, &filevault, &recoveryLock, &adeSetup, &macAdmin)
		if err != nil {
			return nil, notFound(err)
		}
		if macAdmin {
			stop, err = s.macAdminCommandResult(ctx, tx, current, id, status)
			if err != nil {
				return nil, err
			}
			break
		}
		if recoveryLock {
			stop, err = s.recoveryLockCommandResult(ctx, tx, current, id, status, message)
			if err != nil {
				return nil, err
			}
			break
		}
		if (previous == "verified" || (previous == "expired" && peer.kind == "candidate")) && status == "Acknowledged" {
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='acknowledged',error='' WHERE id=$1`, id); err != nil {
				return nil, err
			}
			if err = audit(ctx, tx, current.TenantID, "device:"+current.ID, "apple.command.acknowledged", id); err != nil {
				return nil, err
			}
		}
		if previous == "queued" {
			return nil, errors.New("command has not been delivered")
		}
		if previous == "expired" && (status == "Error" || status == "CommandFormatError") {
			// An already-issued candidate survives the command deadline so an
			// offline device can confirm it. An explicit late installation failure
			// still retires that candidate and preserves the working old identity.
			var renewalID string
			renewalErr := tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_identity_renewals WHERE command_id=$1 AND device_id=$2 AND status='issued'`, id, current.ID).Scan(&renewalID)
			if renewalErr != nil && !errors.Is(renewalErr, sql.ErrNoRows) {
				return nil, renewalErr
			}
			if renewalErr == nil {
				if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='failed',error=$2 WHERE id=$1`, id, responseError(message)); err != nil {
					return nil, err
				}
				if err = s.finishIdentityRenewal(ctx, tx, current, renewalID, "failed", "command_failed"); err != nil {
					return nil, err
				}
				if err = auditOutcome(ctx, tx, current.TenantID, "device:"+current.ID, "apple.command.failed", id, "failure"); err != nil {
					return nil, err
				}
			}
		}
		if previous == "sent" || previous == "not_now" {
			next := "acknowledged"
			detail := ""
			if status == "NotNow" {
				next = "not_now"
				stop = true
			} else if status != "Acknowledged" {
				next = "failed"
				detail = responseError(message)
				if binding {
					detail = "Management channel verification command failed"
				}
				if filevault || kind == "SecurityInfo" {
					detail = "Mac security command failed"
				}
				if adeSetup {
					detail = "MDM setup configuration command failed"
				}
			}
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status=$1,error=$2,available_at=CASE WHEN $1='not_now' THEN now()+interval '1 minute' ELSE available_at END,completed_at=CASE WHEN $1='not_now' THEN NULL ELSE now() END WHERE id=$3`, next, detail, id)
			if err != nil {
				return nil, err
			}
			result := "success"
			if next == "failed" {
				result = "failure"
			} else if next == "not_now" {
				result = "deferred"
			}
			if err = auditOutcome(ctx, tx, current.TenantID, "device:"+current.ID, "apple.command."+next, id, result); err != nil {
				return nil, err
			}
			if next == "failed" {
				var renewalID string
				renewalErr := tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_identity_renewals WHERE command_id=$1 AND device_id=$2 AND status IN ('queued','issued')`, id, current.ID).Scan(&renewalID)
				if renewalErr != nil && !errors.Is(renewalErr, sql.ErrNoRows) {
					return nil, renewalErr
				}
				if renewalErr == nil {
					if err = s.finishIdentityRenewal(ctx, tx, current, renewalID, "failed", "command_failed"); err != nil {
						return nil, err
					}
				}
			}
			if status == "Acknowledged" {
				if err = s.ingestInventory(ctx, tx, current, kind, message); err != nil {
					return nil, err
				}
			}
			if binding {
				if err = s.macBindingCommandResult(ctx, tx, current, id, next); err != nil {
					return nil, err
				}
			}
			if filevault {
				if err = s.fileVaultCommandResult(ctx, tx, current, id, next, message); err != nil {
					return nil, err
				}
			}
			if adeSetup {
				if err = s.adeSetupCommandResult(ctx, tx, current, id, next); err != nil {
					return nil, err
				}
			}
			if profileID.Valid {
				assignmentStatus := "verifying"
				if next == "failed" {
					assignmentStatus = "failed"
				}
				if next == "not_now" {
					assignmentStatus = "deferred"
				}
				_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_profile_assignments SET status=$1,error=$2,updated_at=now() WHERE device_id=$3 AND profile_id=$4 AND revision=$5`, assignmentStatus, detail, current.ID, profileID.String, revision.Int64)
				if err != nil {
					return nil, err
				}
				if status == "Acknowledged" {
					if _, err = s.enqueue(ctx, tx, current, "ProfileList", nil, nil, nil); err != nil {
						return nil, err
					}
				}
			}
		}
	default:
		return nil, errors.New("unsupported command response status")
	}
	if peer.kind == "candidate" && (status == "Idle" || status == "Acknowledged") {
		if err = s.confirmIdentity(ctx, tx, d, peer.renewalID); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET last_seen=now() WHERE id=$1`, current.ID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='expired',error='Command expired before completion',completed_at=now() WHERE device_id=$1 AND expires_at<=now() AND status IN ('queued','sent','not_now')`, current.ID); err != nil {
		return nil, err
	}
	if stop {
		return nil, tx.Commit()
	}
	if err = s.reconcileMacBindingsForDevice(ctx, tx, current); err != nil {
		return nil, err
	}
	if err = s.reconcileFileVault(ctx, tx, current); err != nil {
		return nil, err
	}
	if err = s.reconcileRecoveryLock(ctx, tx, current, true); err != nil {
		return nil, err
	}
	if err = s.reconcileMacAdmin(ctx, tx, current); err != nil {
		return nil, err
	}
	if err = s.reconcileADESetup(ctx, tx, current); err != nil {
		return nil, err
	}
	var id string
	var payload []byte
	var recoveryLock, macAdmin bool
	err = tx.QueryRowContext(ctx, `SELECT id,payload,recovery_lock,mac_admin FROM mdm_apple_commands WHERE device_id=$1 AND status IN ('queued','sent','not_now') AND available_at<=now() AND expires_at>now() AND NOT(recovery_lock AND request_type='SetRecoveryLock' AND attempts>0) AND NOT(mac_admin AND status='sent') ORDER BY CASE WHEN status='sent' THEN 0 ELSE 1 END,created_at,id LIMIT 1 FOR UPDATE`, current.ID).Scan(&id, &payload, &recoveryLock, &macAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	if macAdmin {
		ready, e := s.prepareMacAdminDelivery(ctx, tx, current, id)
		if e != nil {
			return nil, e
		}
		if !ready {
			return nil, tx.Commit()
		}
	}
	if recoveryLock {
		ready, e := s.prepareRecoveryLockDelivery(ctx, tx, current, id)
		if e != nil {
			return nil, e
		}
		if !ready {
			return nil, tx.Commit()
		}
	}
	payload, err = s.secrets.open(payload, secretPurpose(current.TenantID, id, "command"))
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			clear(payload)
		}
	}()
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='sent',attempts=attempts+1,payload=CASE WHEN recovery_lock AND request_type='SetRecoveryLock' THEN '\x'::bytea ELSE payload END WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	transferred = true
	return payload, nil
}

func decodePlistValue(value any, target any) error {
	b, err := plist.Marshal(value, plist.BinaryFormat)
	if err != nil {
		return err
	}
	_, err = plist.Unmarshal(b, target)
	return err
}

func (s *Store) ingestInventory(ctx context.Context, tx *sql.Tx, d *Device, kind string, message map[string]any) error {
	switch kind {
	case "DeviceInformation":
		info, ok := message["QueryResponses"].(map[string]any)
		if !ok {
			return errors.New("DeviceInformation response is missing QueryResponses")
		}
		data, err := json.Marshal(info)
		if err != nil {
			return err
		}
		version := stringValue(info, "OSVersion")
		build := stringValue(info, "BuildVersion")
		name := stringValue(info, "DeviceName")
		if err = s.validateADEIdentity(ctx, tx, d, d.UDID, stringValue(info, "SerialNumber")); err != nil {
			return err
		}
		model, err := reportedModel(info, d.Model)
		if err != nil {
			return err
		}
		if d.EnrollmentPlatform != "" && DetectPlatform(model) != PlatformUnknown && d.EnrollmentPlatform != DetectPlatform(model) {
			return errors.New("inventory platform does not match the enrollment")
		}
		supervised, hasSupervised := info["IsSupervised"].(bool)
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET inventory=$1,name=COALESCE(NULLIF($2,''),name),serial_number=COALESCE(NULLIF($3,''),serial_number),model=COALESCE(NULLIF($4,''),model),os_version=COALESCE(NULLIF($5,''),os_version),build_version=COALESCE(NULLIF($6,''),build_version),supervised=CASE WHEN $7 THEN $8 ELSE supervised END,supervised_reported=supervised_reported OR $7,inventory_at=CASE WHEN $5<>'' THEN now() ELSE inventory_at END WHERE id=$9`, data, name, stringValue(info, "SerialNumber"), model, version, build, hasSupervised, supervised, d.ID)
		if err != nil {
			return err
		}
		if err = s.savePlatformInventory(ctx, tx, d, info, model); err != nil {
			return err
		}
		if err = s.recordMacAdminInventory(ctx, tx, d, stringValue(message, "CommandUUID"), info); err != nil {
			return err
		}
		if err = s.recordADEAwaiting(ctx, tx, d, info); err != nil {
			return err
		}
		next, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1`, d.ID))
		if err != nil {
			return err
		}
		// A minimal first check-in can omit the OS version. Once inventory
		// identifies it, request the newly supported fields and commands now.
		if !slices.Equal(inventoryKindsFor(*d), inventoryKindsFor(*next)) || !slices.Equal(inventoryQueriesFor(*d), inventoryQueriesFor(*next)) {
			if err = s.queuePlatformInventory(ctx, tx, next, !slices.Equal(inventoryQueriesFor(*d), inventoryQueriesFor(*next))); err != nil {
				return err
			}
		}
		return s.reconcileDeviceUpdate(ctx, tx, next)
	case "SecurityInfo":
		if err := s.saveSecurityInventory(ctx, tx, d, message); err != nil {
			return err
		}
		return s.reconcileDeviceUpdate(ctx, tx, d)
	case "InstalledApplicationList":
		var apps []Application
		v, exists := message["InstalledApplicationList"]
		if !exists {
			return errors.New("application inventory is missing InstalledApplicationList")
		}
		if err := decodePlistValue(v, &apps); err != nil {
			return err
		}
		if apps == nil {
			apps = []Application{}
		}
		data, err := json.Marshal(apps)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET apps=$1,apps_at=now() WHERE id=$2`, data, d.ID)
		return err
	case "ProfileList":
		var profiles []InstalledProfile
		v, exists := message["ProfileList"]
		if !exists {
			return errors.New("profile inventory is missing ProfileList")
		}
		if err := decodePlistValue(v, &profiles); err != nil {
			return err
		}
		if profiles == nil {
			profiles = []InstalledProfile{}
		}
		data, err := json.Marshal(profiles)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET installed_profiles=$1,profiles_at=now() WHERE id=$2`, data, d.ID); err != nil {
			return err
		}
		if err := s.recoverEnrollmentLayout(ctx, tx, d, profiles); err != nil {
			return err
		}
		if command := stringValue(message, "CommandUUID"); command != "" {
			if err := s.checkFileVaultProfiles(ctx, tx, d, command, profiles); err != nil {
				return err
			}
		}
		return s.verifyProfiles(ctx, tx, d, profiles)
	case "AvailableOSUpdates":
		v, ok := message["AvailableOSUpdates"]
		if !ok {
			return nil
		}
		data, err := json.Marshal(map[string]any{"AvailableOSUpdates": v})
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET inventory=inventory || $1::jsonb WHERE id=$2`, data, d.ID)
		return err
	}
	return nil
}

func (s *Store) verifyProfiles(ctx context.Context, tx *sql.Tx, d *Device, installed []InstalledProfile) error {
	rows, err := tx.QueryContext(ctx, `SELECT a.profile_id,a.desired,p.identifier,p.payload_uuid FROM mdm_apple_profile_assignments a JOIN mdm_apple_profiles p ON p.id=a.profile_id WHERE a.device_id=$1 AND a.revision=p.revision AND a.status IN ('verifying','verified','missing')`, d.ID)
	if err != nil {
		return err
	}
	type result struct{ id, status string }
	results := []result{}
	for rows.Next() {
		var id, desired, identifier, profileUUID string
		if err = rows.Scan(&id, &desired, &identifier, &profileUUID); err != nil {
			rows.Close()
			return err
		}
		present, exact := false, false
		for _, p := range installed {
			if p.Identifier == identifier {
				present = true
				exact = p.UUID == profileUUID
			}
		}
		status := "missing"
		if (desired == "installed" && exact) || (desired == "removed" && !present) {
			status = "verified"
		}
		results = append(results, result{id, status})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, r := range results {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_profile_assignments SET status=$1,error='',updated_at=now() WHERE device_id=$2 AND profile_id=$3`, r.status, d.ID, r.id); err != nil {
			return err
		}
	}
	return nil
}

// RetryCommand preserves the original command payload and ownership. It does not
// allow clients to submit arbitrary raw Apple commands through a retry endpoint.
func (s *Store) RetryCommand(ctx context.Context, scope Scope, deviceID, commandID, actor string) error {
	d, err := s.Device(ctx, scope, deviceID)
	if err != nil {
		return err
	}
	if d.Status != "enrolled" {
		return errors.New("device is not enrolled")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize retries with checkout, revocation and assignment changes. A
	// deleted profile leaves historical commands, which must never be replayed.
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, deviceID, scope.TenantID).Scan(&state); err != nil {
		return notFound(err)
	}
	if state != "enrolled" {
		return ErrConflict
	}
	r, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='queued',error='',available_at=now(),expires_at=now()+interval '7 days',completed_at=NULL WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND status IN ('failed','expired','not_now') AND NOT mac_binding AND NOT filevault AND NOT recovery_lock AND NOT ade_setup AND NOT mac_admin AND ((profile_id IS NULL AND request_type NOT IN ('InstallProfile','RemoveProfile')) OR EXISTS(SELECT 1 FROM mdm_apple_profile_assignments a WHERE a.profile_id=mdm_apple_commands.profile_id AND a.device_id=mdm_apple_commands.device_id AND a.revision=mdm_apple_commands.profile_revision AND ((a.desired='installed' AND mdm_apple_commands.request_type='InstallProfile') OR (a.desired='removed' AND mdm_apple_commands.request_type='RemoveProfile'))))`, commandID, deviceID, scope.TenantID)
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
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_profile_assignments a SET status='pending',error='',updated_at=now() FROM mdm_apple_commands c WHERE c.id=$1 AND a.profile_id=c.profile_id AND a.device_id=c.device_id AND a.revision=c.profile_revision`, commandID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_push_at=$1 WHERE id=$2`, time.Now(), deviceID); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.command.retry", commandID); err != nil {
		return err
	}
	return tx.Commit()
}
