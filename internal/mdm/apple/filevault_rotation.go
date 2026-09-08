package apple

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// FileVaultRotation is public lifecycle metadata. Return keys, nonces, signed
// receipts and encrypted envelopes are never serialized into device inventory.
type FileVaultRotation struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

func rotationSchemaReady(ctx context.Context, q fileVaultQuery) bool {
	if !recoverySchemaReady(ctx, q) {
		return false
	}
	var ready bool
	err := q.QueryRowContext(ctx, `SELECT to_regclass('mdm_apple_filevault_rotations') IS NOT NULL AND to_regclass('uem_agent_rotation_tasks') IS NOT NULL AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='uem_agent_rotation_tasks' AND column_name='resolution_task_id')`).Scan(&ready)
	return err == nil && ready
}

func fileVaultRotationEvidence(d *Device, now time.Time) bool {
	if d == nil || d.FileVaultReason(now) != "" || CompareVersions(d.OSVersion, "10.14") < 0 || d.ProfilesAt == nil || d.ProfilesAt.Before(now.Add(-24*time.Hour)) || d.ProfilesAt.After(now) || d.InventoryAt == nil || d.InventoryAt.After(now) {
		return false
	}
	enabled, _ := d.SecurityInventory["FDE_Enabled"].(bool)
	personal, _ := d.SecurityInventory["FDE_HasPersonalRecoveryKey"].(bool)
	return enabled && personal
}

func (s *Store) RequestFileVaultRotation(ctx context.Context, scope Scope, device, key, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.requestFileVaultRotation(ctx, scope, device, key, actor, func(ctx context.Context, tx *sql.Tx) error {
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageDeviceSecurity, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
	})
}

func (s *Store) requestFileVaultRotation(ctx context.Context, scope Scope, device, key, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if !enrollment.ValidDeviceID(key) || actor == "" || len(actor) > 255 {
		return ErrFileVault
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
	if !rotationSchemaReady(ctx, tx) {
		return ErrFileVault
	}
	d, err := s.lockFileVaultValidationDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	if !fileVaultRotationEvidence(d, time.Now()) {
		return ErrFileVault
	}
	r, cert, entity, err := s.recoveryMac(ctx, tx, d)
	if err != nil {
		return err
	}
	var current, escrow, enable, desired, phase string
	var verified *time.Time
	var policyAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(p.current_key_id::text,''),p.escrow_id,e.enable_uuid,p.desired,p.phase,k.verified_at,p.updated_at FROM mdm_apple_filevault_policies p JOIN mdm_apple_filevault_escrow e ON e.id=p.escrow_id LEFT JOIN mdm_apple_filevault_keys k ON k.id=p.current_key_id WHERE p.device_id=$1 AND p.tenant_id=$2 AND p.site_id=$3`, d.ID, d.TenantID, d.SiteID).Scan(&current, &escrow, &enable, &desired, &phase, &verified, &policyAt)
	now := time.Now()
	if err != nil || current != key || desired != "enabled" || phase != "active" || verified == nil || verified.Before(now.Add(-24*time.Hour)) || verified.After(now) || d.ProfilesAt.Before(policyAt) {
		return ErrFileVault
	}
	if !rotationKeyValidationCurrent(ctx, tx, key, *verified) {
		return ErrFileVault
	}
	a, b, conflict := fileVaultProfileEvidence(d.InstalledProfiles, fileVaultDomain+"."+d.ID+".escrow", fileVaultDomain+"."+d.ID+".enable", escrow, enable)
	if !a || !b || conflict {
		return ErrFileVault
	}
	var pendingKey, pendingStatus string
	err = tx.QueryRowContext(ctx, `SELECT key_id,status FROM mdm_apple_filevault_rotations WHERE device_id=$1 AND status IN ('queued','uncertain')`, d.ID).Scan(&pendingKey, &pendingStatus)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if pendingKey == key && pendingStatus == "queued" {
			return tx.Commit()
		}
		return ErrFileVault
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_filevault_keys WHERE device_id=$1`, d.ID).Scan(&count); err != nil {
		return err
	}
	if count >= 128 {
		return ErrFileVault
	}
	registryAccess, err := registry.NewAccessStore(s.db)
	if err != nil {
		return err
	}
	ordinal, err := registryAccess.NextRotationOrdinal(ctx, tx, registry.Scope{TenantID: d.TenantID, SiteID: d.SiteID}, r.Identity.AgentID)
	if err != nil {
		return ErrFileVault
	}
	expires := now.Add(5 * time.Minute).Truncate(time.Second)
	for _, limit := range []time.Time{cert.NotAfter.Add(-enrollment.RotationReceiptGrace), d.CertificateExpiresAt.Add(-enrollment.RotationReceiptGrace)} {
		if limit.Before(expires) {
			expires = limit.Truncate(time.Second)
		}
	}
	if expires.Before(now.Add(time.Minute)) {
		return ErrFileVault
	}
	reply, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		return ErrFileVault
	}
	defer reply.Close()
	c := enrollment.RotationContext{Binding: enrollment.RecoveryContext{Version: 1, Identity: r.Identity, TaskID: uuid.NewString(), NativeID: d.ID, KeyID: key, RecipientID: r.ID, ExpiresAt: expires.Unix()}, Ordinal: ordinal, EscrowID: escrow, ReplyKey: hex.EncodeToString(reply.PublicKey())}
	private, err := reply.Bytes()
	if err != nil {
		return ErrFileVault
	}
	defer clear(private)
	sealed, err := s.secrets.seal(private, secretPurpose(d.TenantID, d.ID+"/"+c.Binding.TaskID, "filevault_rotation_reply_key"))
	clear(private)
	if err != nil {
		return ErrFileVault
	}
	plain, err := s.openFileVaultKey(ctx, tx, d, key)
	if err != nil {
		return err
	}
	defer clear(plain)
	nonce := make([]byte, 32)
	defer clear(nonce)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	task, err := enrollment.EncryptRotationTask(*r, c, plain, nonce, time.Now())
	clear(plain)
	if err != nil {
		return ErrFileVault
	}
	if err = registryAccess.QueueRotationTask(ctx, tx, *task, digest(nonce)); err != nil {
		return ErrFileVault
	}
	bound, err := json.Marshal(c)
	if err != nil {
		return ErrFileVault
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_filevault_rotations(id,tenant_id,site_id,device_id,key_id,agent_id,entity_id,nonce_hash,context,reply_private,actor,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.Binding.TaskID, d.TenantID, d.SiteID, d.ID, key, r.Identity.AgentID, entity, digest(nonce), bound, sealed, actor, expires); err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.filevault.rotation.request", c.Binding.TaskID); err != nil {
		return err
	}
	return tx.Commit()
}

// Keep historical success timestamps while refusing a subsequently disproven
// key. A newer successful independent validation can make it eligible again.
func rotationKeyValidationCurrent(ctx context.Context, q fileVaultQuery, key string, verified time.Time) bool {
	var invalid bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_filevault_validations WHERE key_id=$1 AND status='invalid' AND completed_at>=$2) OR EXISTS(SELECT 1 FROM mdm_apple_filevault_rotations WHERE key_id=$1 AND status='invalid' AND completed_at>=$2)`, key, verified).Scan(&invalid)
	return err == nil && !invalid
}

func (s *Store) fileVaultRotationMetadata(ctx context.Context, d *Device, v *FileVault) error {
	latest := &FileVaultRotation{}
	err := s.db.QueryRowContext(ctx, `SELECT id,status,created_at,completed_at FROM mdm_apple_filevault_rotations WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 ORDER BY created_at DESC,id DESC LIMIT 1`, d.ID, d.TenantID, d.SiteID).Scan(&latest.ID, &latest.Status, &latest.CreatedAt, &latest.CompletedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		v.Rotation = latest
	}
	if !rotationSchemaReady(ctx, s.db) {
		return nil
	}
	if v.Rotation != nil && (v.Rotation.Status == "queued" || v.Rotation.Status == "uncertain") {
		if v.Rotation.Status == "queued" {
			v.ValidationReady = false
			return nil
		}
		var stopped bool
		if err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_rotation_tasks WHERE id=$1 AND status='uncertain' AND result IS NOT NULL)`, v.Rotation.ID).Scan(&stopped); err != nil {
			return err
		}
		v.ValidationReady = v.ValidationReady && stopped
		return nil
	}
	now := time.Now()
	if !v.ValidationReady || v.KeyID == "" || v.Desired != "enabled" || v.Phase != "active" || v.VerifiedAt == nil || v.VerifiedAt.Before(now.Add(-24*time.Hour)) || v.VerifiedAt.After(now) || !fileVaultRotationEvidence(d, now) || !rotationKeyValidationCurrent(ctx, s.db, v.KeyID, *v.VerifiedAt) {
		return nil
	}
	var escrow, enable string
	var updated time.Time
	if err = s.db.QueryRowContext(ctx, `SELECT p.escrow_id,e.enable_uuid,p.updated_at FROM mdm_apple_filevault_policies p JOIN mdm_apple_filevault_escrow e ON e.id=p.escrow_id WHERE p.device_id=$1`, d.ID).Scan(&escrow, &enable, &updated); err != nil {
		return err
	}
	a, b, conflict := fileVaultProfileEvidence(d.InstalledProfiles, fileVaultDomain+"."+d.ID+".escrow", fileVaultDomain+"."+d.ID+".enable", escrow, enable)
	v.RotationReady = a && b && !conflict && !d.ProfilesAt.Before(updated)
	return nil
}
