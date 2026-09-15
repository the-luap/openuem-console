package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func historicalRotationSchemaReady(ctx context.Context, q fileVaultQuery) bool {
	var ready bool
	err := q.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_rotation_recovery_checks') IS NOT NULL AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='uem_agent_rotation_reconciliations' AND column_name='recovery_check_id')`).Scan(&ready)
	return err == nil && ready
}

type fileVaultHistoricalRotation struct {
	id, agent, outcome string
	wire               []byte
}

func (h *fileVaultHistoricalRotation) nonKey() bool {
	return h.outcome == "invalid" || h.outcome == "unavailable" || h.outcome == "unsupported"
}

// Selection is only a hint. The registry verifies the signed old receipt with
// its current certificate or authenticated source-certificate history before
// admitting any challenge. Console final states never substitute for that proof.
func loadFileVaultHistoricalRotation(ctx context.Context, tx *sql.Tx, d *Device, r *enrollment.RecoveryRecipient, entity, id string) (*fileVaultHistoricalRotation, error) {
	var selected string
	err := tx.QueryRowContext(ctx, `SELECT v.id FROM mdm_apple_filevault_rotations v JOIN uem_agent_rotation_tasks t ON t.id=v.id AND t.device_id=v.agent_id LEFT JOIN uem_agent_rotation_reconciliations a ON a.task_id=t.id WHERE v.device_id=$1 AND v.tenant_id=$2 AND v.site_id=$3 AND v.agent_id=$4 AND v.entity_id=$5 AND v.status NOT IN ('queued','uncertain') AND t.status='completed' AND t.delivered_at IS NOT NULL AND a.task_id IS NULL AND ($6='' OR v.id=NULLIF($6,'')::uuid) ORDER BY v.created_at,v.id LIMIT 1`, d.ID, d.TenantID, d.SiteID, r.Identity.AgentID, entity, id).Scan(&selected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e, err := loadFileVaultRotation(ctx, tx, d, selected)
	if err != nil || e.EntityID != entity || e.Context.Binding.Identity.AgentID != r.Identity.AgentID {
		return nil, ErrFileVault
	}
	var wire []byte
	if err = tx.QueryRowContext(ctx, `SELECT result FROM uem_agent_rotation_tasks WHERE id=$1 AND device_id=$2`, selected, r.Identity.AgentID).Scan(&wire); err != nil {
		return nil, err
	}
	var receipt enrollment.RotationResult
	if len(wire) > enrollment.MaxRecoveryMessage || json.Unmarshal(wire, &receipt) != nil {
		return nil, ErrFileVault
	}
	canonical, _ := json.Marshal(receipt)
	if !bytes.Equal(wire, canonical) || receipt.Context != e.Context || digest(receipt.Nonce) != e.NonceHash {
		return nil, ErrFileVault
	}
	return &fileVaultHistoricalRotation{id: selected, agent: r.Identity.AgentID, outcome: receipt.Outcome, wire: wire}, nil
}

// Decrypt and validate the exact current ciphertext while retaining its row
// lock. The digest contains neither the plaintext PRK nor a password verifier.
func (s *Store) fileVaultCurrentKeyDigest(ctx context.Context, tx *sql.Tx, d *Device, key string) (string, error) {
	var encrypted []byte
	err := tx.QueryRowContext(ctx, `SELECT k.recovery_key FROM mdm_apple_filevault_keys k JOIN mdm_apple_filevault_policies p ON p.current_key_id=k.id AND p.device_id=k.device_id AND p.tenant_id=k.tenant_id WHERE k.id=$1 AND k.tenant_id=$2 AND k.device_id=$3 FOR SHARE OF k`, key, d.TenantID, d.ID).Scan(&encrypted)
	if err != nil {
		return "", ErrFileVault
	}
	plain, err := s.secrets.open(encrypted, secretPurpose(d.TenantID, d.ID+"/"+key, "filevault_recovery_key"))
	defer clear(plain)
	if err != nil || !enrollment.ValidFileVaultRecoveryKey(plain) {
		return "", ErrFileVault
	}
	return digest(encrypted), nil
}

func (s *Store) acknowledgeFileVaultHistoricalNonKey(ctx context.Context, tx *sql.Tx, d *Device, h *fileVaultHistoricalRotation, actor string, r *enrollment.RecoveryRecipient, cert *x509.Certificate) error {
	if s.agentRegistry == nil || h == nil || !h.nonKey() {
		return ErrFileVault
	}
	if err := s.agentRegistry.AcknowledgeHistoricalRotationWithoutKeyInTransaction(ctx, tx, registry.Scope{TenantID: d.TenantID, SiteID: d.SiteID}, h.agent, d.ID, h.id, digest(h.wire), actor); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_rotations SET history_status='complete' WHERE id=$1`, h.id); err != nil {
		return err
	}
	if err := audit(ctx, tx, d.TenantID, actor, "apple.filevault.rotation.history.non-mutating", h.id); err != nil {
		return err
	}
	return fileVaultHistoryAuthorityCurrent(ctx, tx, d, r, cert)
}

// ReconcileFileVaultHistory schedules at most 25 historical rows per sweep.
// Claiming only scheduling metadata in a short transaction avoids holding a
// rotation before the native/agent locks. Replicas serialize actual work on the
// native device, preserve existing pending checks and back off for an hour.
func (s *Store) ReconcileFileVaultHistory(ctx context.Context) error {
	if s.agentRegistry == nil || !historicalRotationSchemaReady(ctx, s.db) {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `WITH selected AS (SELECT v.id FROM mdm_apple_filevault_rotations v JOIN uem_agent_rotation_tasks t ON t.id=v.id AND t.device_id=v.agent_id LEFT JOIN uem_agent_rotation_reconciliations a ON a.task_id=t.id WHERE v.status NOT IN ('queued','uncertain') AND t.status='completed' AND t.delivered_at IS NOT NULL AND a.task_id IS NULL AND v.history_next_check_at<=clock_timestamp() ORDER BY v.history_next_check_at,v.id LIMIT 25 FOR UPDATE OF v SKIP LOCKED) UPDATE mdm_apple_filevault_rotations v SET history_next_check_at=clock_timestamp()+interval '1 hour' FROM selected WHERE v.id=selected.id RETURNING v.id,v.device_id,v.tenant_id,v.site_id`)
	if err != nil {
		return err
	}
	type candidate struct {
		id, device string
		scope      Scope
	}
	var list []candidate
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
	var failures []error
	for _, c := range list {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		if err = s.checkFileVaultHistory(ctx, c.scope, c.device, c.id); err != nil {
			// Only public state is written outside the failed transaction. This
			// never acknowledges a result or stamps a key as verified.
			_, stateErr := s.db.ExecContext(ctx, `UPDATE mdm_apple_filevault_rotations SET history_status='attention' WHERE id=$1`, c.id)
			failures = append(failures, err, stateErr)
		}
	}
	return errors.Join(failures...)
}

func (s *Store) checkFileVaultHistory(ctx context.Context, scope Scope, device, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	d, err := s.lockFileVaultValidationDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	r, cert, entity, err := s.recoveryMac(ctx, tx, d)
	if err != nil {
		return err
	}
	history, err := loadFileVaultHistoricalRotation(ctx, tx, d, r, entity, id)
	if err != nil || history == nil {
		return err
	}
	const actor = "filevault-history-service"
	if history.nonKey() {
		if err = s.acknowledgeFileVaultHistoricalNonKey(ctx, tx, d, history, actor, r, cert); err != nil {
			return err
		}
		return tx.Commit()
	}
	var pending bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_filevault_validations WHERE device_id=$1 AND status='queued') OR EXISTS(SELECT 1 FROM mdm_apple_filevault_rotations WHERE device_id=$1 AND status IN ('queued','uncertain'))`, device).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return tx.Commit()
	}
	var key string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(current_key_id::text,'') FROM mdm_apple_filevault_policies WHERE device_id=$1`, device).Scan(&key); err != nil {
		return err
	}
	if !enrollment.ValidDeviceID(key) {
		return ErrFileVault
	}
	if err = s.queueFileVaultValidation(ctx, tx, d, key, actor, r, cert, entity, history); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) finishFileVaultHistoricalValidation(ctx context.Context, tx *sql.Tx, e fileVaultExpectation, status string) error {
	if !historicalRotationSchemaReady(ctx, tx) {
		return nil
	}
	historyStatus := "attention"
	if status == "valid" {
		historyStatus = "complete"
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_rotations v SET history_status=$2,history_next_check_at=clock_timestamp()+interval '24 hours' FROM uem_agent_rotation_recovery_checks h WHERE h.id=$1 AND h.rotation_task_id=v.id`, e.Context.TaskID, historyStatus)
	return err
}

func (s *Store) fileVaultHistoryMetadata(ctx context.Context, d *Device, v *FileVault) error {
	if !historicalRotationSchemaReady(ctx, s.db) {
		return nil
	}
	return s.db.QueryRowContext(ctx, `SELECT count(*),COALESCE(bool_or(v.history_status='attention'),false) FROM mdm_apple_filevault_rotations v JOIN uem_agent_rotation_tasks t ON t.id=v.id AND t.device_id=v.agent_id LEFT JOIN uem_agent_rotation_reconciliations a ON a.task_id=t.id WHERE v.device_id=$1 AND v.tenant_id=$2 AND v.site_id=$3 AND v.status NOT IN ('queued','uncertain') AND t.status='completed' AND t.delivered_at IS NOT NULL AND a.task_id IS NULL`, d.ID, d.TenantID, d.SiteID).Scan(&v.HistoricalRotationsPending, &v.HistoricalRotationsNeedAttention)
}

func fileVaultHistoryAuthorityCurrent(ctx context.Context, tx *sql.Tx, d *Device, r *enrollment.RecoveryRecipient, cert *x509.Certificate) error {
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_identities WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_hash=$4 AND revoked_at IS NULL AND certificate_expires_at>clock_timestamp())`, r.Identity.AgentID, d.TenantID, d.SiteID, r.Identity.CertificateHash).Scan(&active); err != nil {
		return err
	}
	now := time.Now()
	if !active || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || !now.Before(d.CertificateExpiresAt) {
		return ErrFileVault
	}
	return nil
}
