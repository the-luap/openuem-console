package apple

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
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

// FileVaultValidation exposes only state and time, never a recipient, nonce,
// certificate, encrypted envelope or recovery key.
type FileVaultValidation struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

type fileVaultExpectation struct {
	Context                     enrollment.RecoveryContext
	EntityID, NonceHash, Status string
	CreatedAt, ExpiresAt        time.Time
}

type fileVaultQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func recoverySchemaReady(ctx context.Context, q fileVaultQuery) bool {
	var ready bool
	err := q.QueryRowContext(ctx, `SELECT to_regclass('uem_mac_devices') IS NOT NULL AND to_regclass('uem_mac_mdm_channels') IS NOT NULL AND to_regclass('uem_mac_agent_channels') IS NOT NULL AND to_regclass('uem_agent_hardware') IS NOT NULL AND to_regclass('uem_agent_recovery_recipients') IS NOT NULL AND to_regclass('uem_agent_recovery_tasks') IS NOT NULL AND to_regclass('agents') IS NOT NULL AND to_regclass('site_agents') IS NOT NULL`).Scan(&ready)
	return err == nil && ready
}

// The site advisory lock matches Mac channel attachment, which can lock both
// former and new channels. Take it before native, agent and canonical row locks.
func (s *Store) lockFileVaultValidationDevice(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*Device, error) {
	if scope.Validate() != nil || !enrollment.ValidDeviceID(id) {
		return nil, ErrFileVault
	}
	var site int
	if err := tx.QueryRowContext(ctx, `SELECT site_id FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3)`, id, scope.TenantID, scope.SiteID).Scan(&site); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627926,$1::integer)`, site); err != nil {
		return nil, err
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, id, scope.TenantID, site))
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, site, scope.TenantID).Scan(&site); errors.Is(err, sql.ErrNoRows) {
		return d, ErrFileVault
	} else if err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Store) recoveryMac(ctx context.Context, tx *sql.Tx, d *Device) (*enrollment.RecoveryRecipient, *x509.Certificate, string, error) {
	if d.Family() != PlatformMacOS || d.Status != "enrolled" || !time.Now().Before(d.CertificateExpiresAt) {
		return nil, nil, "", ErrFileVault
	}
	var agent, entity string
	err := tx.QueryRowContext(ctx, `SELECT ac.device_id,mc.entity_id FROM uem_mac_mdm_channels mc JOIN uem_mac_agent_channels ac ON ac.entity_id=mc.entity_id AND ac.tenant_id=mc.tenant_id AND ac.site_id=mc.site_id WHERE mc.device_id=$1 AND mc.tenant_id=$2 AND mc.site_id=$3 AND mc.retired_at IS NULL AND ac.retired_at IS NULL`, d.ID, d.TenantID, d.SiteID).Scan(&agent, &entity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, "", ErrFileVault
	}
	if err != nil {
		return nil, nil, "", err
	}
	registryAccess, err := registry.NewAccessStore(s.db)
	if err != nil {
		return nil, nil, "", err
	}
	r, cert, err := registryAccess.RecoveryRecipient(ctx, tx, registry.Scope{TenantID: d.TenantID, SiteID: d.SiteID}, agent)
	if err != nil {
		return nil, nil, "", ErrFileVault
	}
	if time.Now().Before(cert.NotBefore) {
		return nil, nil, "", ErrFileVault
	}
	var matches bool
	h := enrollment.HardwareInventory{Version: enrollment.HardwareInventoryVersion, AgentID: agent}
	var observed time.Time
	err = tx.QueryRowContext(ctx, `SELECT h.model,h.serial,h.platform_uuid,h.provisioning_udid,h.observed_at,
 m.model=h.model AND m.serial=h.serial AND m.platform_uuid=h.platform_uuid AND m.provisioning_udid=h.provisioning_udid
 FROM uem_mac_devices m JOIN uem_mac_mdm_channels mc ON mc.entity_id=m.id AND mc.device_id=$1 AND mc.retired_at IS NULL
 JOIN uem_mac_agent_channels ac ON ac.entity_id=m.id AND ac.device_id=$2 AND ac.retired_at IS NULL
 JOIN uem_agent_hardware h ON h.device_id=ac.device_id AND h.tenant_id=m.tenant_id AND h.site_id=m.site_id
 WHERE m.id=$3 AND m.tenant_id=$4 AND m.site_id=$5 AND mc.tenant_id=m.tenant_id AND mc.site_id=m.site_id AND ac.tenant_id=m.tenant_id AND ac.site_id=m.site_id FOR UPDATE OF m`, d.ID, agent, entity, d.TenantID, d.SiteID).Scan(&h.Model, &h.Serial, &h.PlatformUUID, &h.ProvisioningUDID, &observed, &matches)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, "", ErrFileVault
	}
	if err != nil {
		return nil, nil, "", err
	}
	now := time.Now()
	if !matches || observed.Before(now.Add(-24*time.Hour)) || observed.After(now.Add(time.Minute)) || !macHardwareMatches(d, h, now) {
		return nil, nil, "", ErrFileVault
	}
	// The worker also requires a scoped inventory record. Lock its parent and
	// edges so an insertion/deletion cannot change that scope before commit.
	var inventoryID string
	if err = tx.QueryRowContext(ctx, `SELECT oid FROM agents WHERE oid=$1 FOR UPDATE`, agent).Scan(&inventoryID); errors.Is(err, sql.ErrNoRows) {
		return nil, nil, "", ErrFileVault
	} else if err != nil {
		return nil, nil, "", err
	}
	rows, err := tx.QueryContext(ctx, `SELECT site_id FROM site_agents WHERE agent_id=$1 FOR SHARE`, agent)
	if err != nil {
		return nil, nil, "", err
	}
	count := 0
	for rows.Next() {
		var site int
		if err = rows.Scan(&site); err != nil {
			rows.Close()
			return nil, nil, "", err
		}
		count++
		if site != d.SiteID {
			matches = false
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, "", err
	}
	if count != 1 || !matches {
		return nil, nil, "", ErrFileVault
	}
	return r, cert, entity, nil
}

func (s *Store) RequestFileVaultValidation(ctx context.Context, scope Scope, device, key, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.requestFileVaultValidation(ctx, scope, device, key, actor, func(ctx context.Context, tx *sql.Tx) error {
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageDeviceSecurity, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
	})
}

func (s *Store) requestFileVaultValidation(ctx context.Context, scope Scope, device, key, actor string, authorize func(context.Context, *sql.Tx) error) error {
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
	if !recoverySchemaReady(ctx, tx) {
		return ErrFileVault
	}
	d, err := s.lockFileVaultValidationDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	var current string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(current_key_id::text,'') FROM mdm_apple_filevault_policies WHERE device_id=$1`, d.ID).Scan(&current); err != nil || current != key {
		return ErrFileVault
	}
	r, cert, entity, err := s.recoveryMac(ctx, tx, d)
	if err != nil {
		return err
	}
	var pending string
	err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_filevault_validations WHERE device_id=$1 AND status='queued'`, d.ID).Scan(&pending)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if pending != "" {
		if err = s.reconcileFileVaultValidation(ctx, tx, d, pending, r, cert, entity); err != nil {
			return err
		}
		var stillPending bool
		if err = tx.QueryRowContext(ctx, `SELECT status='queued' FROM mdm_apple_filevault_validations WHERE id=$1`, pending).Scan(&stillPending); err != nil {
			return err
		}
		if stillPending {
			return tx.Commit()
		}
	}
	now := time.Now()
	expires := now.Add(15 * time.Minute).Truncate(time.Second)
	for _, limit := range []time.Time{cert.NotAfter, d.CertificateExpiresAt} {
		if limit.Before(expires) {
			expires = limit.Truncate(time.Second)
		}
	}
	if expires.Before(now.Add(30 * time.Second)) {
		return ErrFileVault
	}
	c := enrollment.RecoveryContext{Version: enrollment.RecoveryVersion, Identity: r.Identity, TaskID: uuid.NewString(), NativeID: d.ID, KeyID: key, RecipientID: r.ID, ExpiresAt: expires.Unix()}
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
	envelope, err := enrollment.EncryptRecoveryTask(*r, c, plain, nonce, now)
	clear(plain)
	if err != nil {
		return ErrFileVault
	}
	hash := sha256.Sum256(nonce)
	nonceHash := hex.EncodeToString(hash[:])
	registryAccess, err := registry.NewAccessStore(s.db)
	if err != nil {
		return err
	}
	if err = registryAccess.QueueRecoveryTask(ctx, tx, *envelope, nonceHash); err != nil {
		return ErrFileVault
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_filevault_validations(id,tenant_id,site_id,device_id,key_id,entity_id,agent_id,recipient_id,certificate_hash,nonce_hash,actor,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.TaskID, d.TenantID, d.SiteID, d.ID, key, entity, r.Identity.AgentID, r.ID, r.Identity.CertificateHash, nonceHash, actor, expires)
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.filevault.validation.request", c.TaskID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) finishFileVaultValidation(ctx context.Context, tx *sql.Tx, e fileVaultExpectation, status string, at time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_validations SET status=$2,completed_at=$3 WHERE id=$1 AND status='queued'`, e.Context.TaskID, status, at); err != nil {
		return err
	}
	// Also erase a request that became invalid while its endpoint was offline.
	if _, err := tx.ExecContext(ctx, `UPDATE uem_agent_recovery_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp() WHERE id=$1 AND status='pending'`, e.Context.TaskID); err != nil {
		return err
	}
	outcome := "failure"
	if status == "valid" {
		outcome = "success"
	} else if status == "cancelled" || status == "superseded" {
		outcome = "cancelled"
	} else if status == "unavailable" || status == "unsupported" {
		outcome = "deferred"
	}
	return auditOutcome(ctx, tx, e.Context.Identity.TenantID, "filevault-validation-service", "apple.filevault.validation."+status, e.Context.TaskID, outcome)
}

func (s *Store) reconcileFileVaultValidation(ctx context.Context, tx *sql.Tx, d *Device, id string, r *enrollment.RecoveryRecipient, cert *x509.Certificate, entity string) error {
	var e fileVaultExpectation
	c := &e.Context
	c.Version = enrollment.RecoveryVersion
	err := tx.QueryRowContext(ctx, `SELECT id,tenant_id,site_id,device_id,key_id,entity_id,agent_id,recipient_id,certificate_hash,nonce_hash,status,created_at,expires_at FROM mdm_apple_filevault_validations WHERE id=$1 AND device_id=$2 FOR UPDATE`, id, d.ID).Scan(&c.TaskID, &c.Identity.TenantID, &c.Identity.SiteID, &c.NativeID, &c.KeyID, &e.EntityID, &c.Identity.AgentID, &c.RecipientID, &c.Identity.CertificateHash, &e.NonceHash, &e.Status, &e.CreatedAt, &e.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if e.Status != "queued" {
		return nil
	}
	c.ExpiresAt = e.ExpiresAt.Unix()
	finish := func(status string) error { return s.finishFileVaultValidation(ctx, tx, e, status, time.Now()) }
	var key string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(current_key_id::text,'') FROM mdm_apple_filevault_policies WHERE device_id=$1`, d.ID).Scan(&key); err != nil {
		return err
	}
	if key != c.KeyID {
		return finish("superseded")
	}
	if r == nil || cert == nil || r.Identity != c.Identity || r.ID != c.RecipientID || entity != e.EntityID || d.TenantID != c.Identity.TenantID || d.SiteID != c.Identity.SiteID || d.Status != "enrolled" || !time.Now().Before(d.CertificateExpiresAt) || !time.Now().Before(cert.NotAfter) {
		return finish("cancelled")
	}
	var status string
	var result []byte
	var completed, delivered *time.Time
	err = tx.QueryRowContext(ctx, `SELECT status,result,completed_at,delivered_at FROM uem_agent_recovery_tasks WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND device_id=$4 AND native_id=$5 AND key_id=$6 AND recipient_id=$7 AND certificate_hash=$8 AND nonce_hash=$9 AND expires_at=$10 FOR UPDATE`, c.TaskID, c.Identity.TenantID, c.Identity.SiteID, c.Identity.AgentID, c.NativeID, c.KeyID, c.RecipientID, c.Identity.CertificateHash, e.NonceHash, e.ExpiresAt).Scan(&status, &result, &completed, &delivered)
	if errors.Is(err, sql.ErrNoRows) {
		return finish("rejected")
	}
	if err != nil {
		return err
	}
	// A task row can be busy until after an identity expires. Recheck the
	// database clock after acquiring it, including a shortened DB lifetime.
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_identities WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_hash=$4 AND revoked_at IS NULL AND certificate_expires_at>clock_timestamp())`, c.Identity.AgentID, c.Identity.TenantID, c.Identity.SiteID, c.Identity.CertificateHash).Scan(&active); err != nil {
		return err
	}
	if !active || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) || !time.Now().Before(d.CertificateExpiresAt) {
		return finish("cancelled")
	}
	switch status {
	case "cancelled", "expired":
		return finish(status)
	case "pending":
		if !time.Now().Before(e.ExpiresAt) {
			return finish("expired")
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_validations SET next_check_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id)
		return err
	case "completed":
	default:
		return finish("rejected")
	}
	if completed == nil || delivered == nil || delivered.Before(e.CreatedAt) || completed.Before(*delivered) || !completed.Before(e.ExpiresAt) || completed.After(time.Now().Add(time.Second)) || len(result) > enrollment.MaxRecoveryMessage {
		return finish("rejected")
	}
	var receipt enrollment.RecoveryResult
	if json.Unmarshal(result, &receipt) != nil {
		return finish("rejected")
	}
	canonical, err := json.Marshal(receipt)
	hash := sha256.Sum256(receipt.Nonce)
	if err != nil || !bytes.Equal(canonical, result) || receipt.Context != *c || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(e.NonceHash)) != 1 || enrollment.VerifyRecoveryResult(receipt, cert, *completed) != nil {
		return finish("rejected")
	}
	if receipt.Outcome == "valid" {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_keys SET verified_at=GREATEST(verified_at,$2) WHERE id=$1 AND tenant_id=$3 AND device_id=$4`, c.KeyID, *completed, d.TenantID, d.ID); err != nil {
			return err
		}
	}
	return s.finishFileVaultValidation(ctx, tx, e, receipt.Outcome, *completed)
}

// ReconcileFileVaultValidations accepts a timely signed receipt even if this
// console replica resumes later. The current identity and association must still
// be valid; a previous success is historical evidence, not hardware attestation.
func (s *Store) ReconcileFileVaultValidations(ctx context.Context) error {
	if !recoverySchemaReady(ctx, s.db) {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,tenant_id,site_id FROM mdm_apple_filevault_validations WHERE status='queued' AND next_check_at<=clock_timestamp() ORDER BY next_check_at,id LIMIT 25`)
	if err != nil {
		return err
	}
	type candidate struct {
		id, device string
		scope      Scope
	}
	list := []candidate{}
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.id, &c.device, &c.scope.TenantID, &c.scope.SiteID); err != nil {
			rows.Close()
			return err
		}
		list = append(list, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range list {
		if err = s.checkFileVaultValidation(ctx, c.scope, c.device, c.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) checkFileVaultValidation(ctx context.Context, scope Scope, device, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	d, err := s.lockFileVaultValidationDevice(ctx, tx, scope, device)
	if err != nil && (d == nil || !errors.Is(err, ErrFileVault)) {
		return err
	}
	var r *enrollment.RecoveryRecipient
	var cert *x509.Certificate
	var entity string
	if err == nil {
		r, cert, entity, err = s.recoveryMac(ctx, tx, d)
	}
	if err != nil && !errors.Is(err, ErrFileVault) {
		return err
	}
	if err = s.reconcileFileVaultValidation(ctx, tx, d, id, r, cert, entity); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) fileVaultValidationMetadata(ctx context.Context, d *Device, v *FileVault) error {
	if v.KeyID == "" {
		return nil
	}
	latest := &FileVaultValidation{}
	err := s.db.QueryRowContext(ctx, `SELECT id,status,created_at,completed_at FROM mdm_apple_filevault_validations WHERE device_id=$1 AND key_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, d.ID, v.KeyID).Scan(&latest.ID, &latest.Status, &latest.CreatedAt, &latest.CompletedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		v.Validation = latest
	}
	if !recoverySchemaReady(ctx, s.db) || d.Status != "enrolled" || d.Family() != PlatformMacOS || !time.Now().Before(d.CertificateExpiresAt) {
		return nil
	}
	if d.InventoryAt == nil || d.InventoryAt.Before(time.Now().Add(-24*time.Hour)) || d.InventoryAt.After(time.Now().Add(time.Minute)) {
		return nil
	}
	entity, err := s.MacForMDM(ctx, Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil {
		return err
	}
	if entity == "" {
		return nil
	}
	mac, err := s.MacDevice(ctx, Scope{TenantID: d.TenantID, SiteID: d.SiteID}, entity)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if mac == nil || mac.AgentStatus != "enrolled" || mac.MDMID != d.ID || mac.MDMStatus != "enrolled" {
		return nil
	}
	return s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_recovery_recipients r JOIN uem_agent_identities i ON i.id=r.device_id AND i.certificate_hash=r.certificate_hash JOIN agents a ON a.oid=i.id::text WHERE i.id=$1 AND r.tenant_id=$2 AND r.site_id=$3 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 AND EXISTS(SELECT 1 FROM site_agents WHERE agent_id=a.oid AND site_id=$3))`, mac.AgentID, d.TenantID, d.SiteID).Scan(&v.ValidationReady)
}
