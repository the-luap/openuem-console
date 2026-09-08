package apple

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

type fileVaultRotationExpectation struct {
	Context                            enrollment.RotationContext
	EntityID, NonceHash, Actor, Status string
	Private                            []byte
	CreatedAt, ExpiresAt               time.Time
}

func loadFileVaultRotation(ctx context.Context, tx *sql.Tx, d *Device, id string) (*fileVaultRotationExpectation, error) {
	e := &fileVaultRotationExpectation{}
	var bound []byte
	var key, agent string
	err := tx.QueryRowContext(ctx, `SELECT key_id,agent_id,entity_id,nonce_hash,context,reply_private,actor,status,created_at,expires_at FROM mdm_apple_filevault_rotations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, d.ID, d.TenantID, d.SiteID).Scan(&key, &agent, &e.EntityID, &e.NonceHash, &bound, &e.Private, &e.Actor, &e.Status, &e.CreatedAt, &e.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(bound, &e.Context) != nil {
		return nil, ErrFileVault
	}
	c := e.Context
	b := c.Binding
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(canonical, bound) || !c.ValidReceipt() || b.TaskID != id || b.KeyID != key || b.NativeID != d.ID || b.Identity.AgentID != agent || b.Identity.TenantID != d.TenantID || b.Identity.SiteID != d.SiteID || b.ExpiresAt != e.ExpiresAt.Unix() {
		return nil, ErrFileVault
	}
	return e, nil
}

func (s *Store) finishFileVaultRotation(ctx context.Context, tx *sql.Tx, d *Device, e *fileVaultRotationExpectation, status, candidate string, at time.Time, erase bool) error {
	if status == "cancelled" || status == "rejected" {
		if _, err := tx.ExecContext(ctx, `UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp() WHERE id=$1 AND status IN ('pending','uncertain')`, e.Context.Binding.TaskID); err != nil {
			return err
		}
	}
	change, err := tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_rotations SET status=$2,candidate_key_id=NULLIF($3,'')::uuid,completed_at=CASE WHEN $2='uncertain' THEN NULL ELSE $4::timestamptz END,next_check_at=clock_timestamp()+interval '30 seconds',reply_private=CASE WHEN $5 THEN '\x'::bytea ELSE reply_private END WHERE id=$1 AND status IN ('queued','uncertain') AND status<>$2`, e.Context.Binding.TaskID, status, candidate, at, erase)
	if err != nil {
		return err
	}
	n, err := change.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	return audit(ctx, tx, d.TenantID, e.Actor, "apple.filevault.rotation."+status, e.Context.Binding.TaskID)
}

func (s *Store) reconcileFileVaultRotation(ctx context.Context, tx *sql.Tx, d *Device, id string, r *enrollment.RecoveryRecipient, cert *x509.Certificate, entity string) error {
	e, err := loadFileVaultRotation(ctx, tx, d, id)
	if err != nil {
		return err
	}
	if e.Status != "queued" && e.Status != "uncertain" {
		return nil
	}
	c := e.Context
	b := c.Binding
	finish := func(status string) error {
		return s.finishFileVaultRotation(ctx, tx, d, e, status, "", time.Now(), false)
	}
	if r == nil || cert == nil || r.Identity != b.Identity || r.ID != b.RecipientID || entity != e.EntityID || d.Status != "enrolled" || !time.Now().Before(d.CertificateExpiresAt) {
		return finish("cancelled")
	}
	var status, nonceHash string
	var bound, wire []byte
	var delivered, completed *time.Time
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT status,nonce_hash,context,result,delivered_at,completed_at,expires_at FROM uem_agent_rotation_tasks WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND device_id=$4 AND native_id=$5 AND key_id=$6 AND recipient_id=$7 AND certificate_hash=$8 AND ordinal=$9 FOR UPDATE`, id, d.TenantID, d.SiteID, b.Identity.AgentID, d.ID, b.KeyID, b.RecipientID, b.Identity.CertificateHash, c.Ordinal).Scan(&status, &nonceHash, &bound, &wire, &delivered, &completed, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return finish("rejected")
	}
	if err != nil {
		return err
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(canonical, bound) || nonceHash != e.NonceHash || !expires.Equal(e.ExpiresAt) {
		return finish("rejected")
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT certificate_expires_at>clock_timestamp() AND revoked_at IS NULL FROM uem_agent_identities WHERE id=$1`, b.Identity.AgentID).Scan(&active); err != nil {
		return err
	}
	if !active || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) || !time.Now().Before(d.CertificateExpiresAt) {
		return finish("cancelled")
	}
	if status == "cancelled" || status == "expired" {
		return finish(status)
	}
	if status != "pending" && status != "uncertain" && status != "completed" {
		return finish("rejected")
	}
	if len(wire) == 0 {
		if status == "completed" {
			return finish("rejected")
		}
		if !time.Now().Before(expires) && delivered == nil {
			if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_rotation_tasks SET status='expired',envelope='\x',completed_at=clock_timestamp() WHERE id=$1 AND status='pending'`, id); err != nil {
				return err
			}
			return finish("expired")
		}
		if status == "uncertain" || !time.Now().Before(expires) {
			if err = finish("uncertain"); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_rotations SET next_check_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id)
		return err
	}
	if len(wire) > enrollment.MaxRecoveryMessage || delivered == nil || delivered.Before(e.CreatedAt) || !delivered.Before(expires) {
		return finish("rejected")
	}
	var receipt enrollment.RotationResult
	if json.Unmarshal(wire, &receipt) != nil {
		return finish("rejected")
	}
	canonical, _ = json.Marshal(receipt)
	if !bytes.Equal(canonical, wire) || receipt.Context != c || subtle.ConstantTimeCompare([]byte(digest(receipt.Nonce)), []byte(e.NonceHash)) != 1 || enrollment.VerifyRotationResult(receipt, cert, time.Now()) != nil {
		return finish("rejected")
	}
	if receipt.Outcome == "uncertain" {
		if status != "uncertain" || completed != nil {
			return finish("rejected")
		}
		if err = finish("uncertain"); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_rotations SET next_check_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id)
		return err
	}
	if status != "completed" || completed == nil || completed.Before(*delivered) || completed.After(time.Now().Add(time.Second)) {
		return finish("rejected")
	}
	if receipt.Outcome != "rotated" && receipt.Outcome != "unverified" {
		return s.finishFileVaultRotation(ctx, tx, d, e, receipt.Outcome, "", *completed, true)
	}
	private, err := s.secrets.open(e.Private, secretPurpose(d.TenantID, d.ID+"/"+id, "filevault_rotation_reply_key"))
	if err != nil {
		return ErrFileVault
	}
	defer clear(private)
	reply, err := enrollment.ParseRecoveryRecipientKey(private)
	clear(private)
	if err != nil {
		return ErrFileVault
	}
	defer reply.Close()
	if hex.EncodeToString(reply.PublicKey()) != c.ReplyKey {
		return ErrFileVault
	}
	secret, err := reply.OpenRotationResult(receipt, c, e.NonceHash, cert, time.Now())
	if err != nil {
		return finish("rejected")
	}
	defer secret.Close()
	old, err := s.openFileVaultKey(ctx, tx, d, b.KeyID)
	if err != nil {
		return err
	}
	same := subtle.ConstantTimeCompare(old, secret.Key()) == 1
	clear(old)
	if same {
		return finish("rejected")
	}
	key, err := s.retainFileVaultCandidate(ctx, tx, d, c.EscrowID, secret.Key(), receipt.Outcome == "rotated", *completed, "rotation")
	if errors.Is(err, errRotationHistoryFull) {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET recovery_error='recovery_history_full' WHERE device_id=$1`, d.ID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_rotations SET next_check_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, id)
		return err
	}
	if err != nil {
		return err
	}
	var current string
	var requested *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(current_key_id::text,''),recovery_requested_at FROM mdm_apple_filevault_policies WHERE device_id=$1`, d.ID).Scan(&current, &requested); err != nil {
		return err
	}
	outcome := receipt.Outcome
	if current == key || (current == b.KeyID && (requested == nil || !requested.After(*completed))) {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_policies SET current_key_id=$2,recovery_error='',recovery_requested_at=GREATEST(recovery_requested_at,$3) WHERE device_id=$1`, d.ID, key, *completed); err != nil {
			return err
		}
	} else {
		outcome = "superseded"
	}
	return s.finishFileVaultRotation(ctx, tx, d, e, outcome, key, *completed, true)
}

var errRotationHistoryFull = errors.New("FileVault recovery history is full")

func (s *Store) retainFileVaultCandidate(ctx context.Context, tx *sql.Tx, d *Device, escrow string, key []byte, verified bool, at time.Time, source string) (string, error) {
	if source != "escrow" && source != "rotation" {
		return "", ErrFileVault
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM mdm_apple_filevault_keys WHERE device_id=$1 AND tenant_id=$2 ORDER BY created_at,id LIMIT 129`, d.ID, d.TenantID)
	if err != nil {
		return "", err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return "", err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		previous, err := s.openFileVaultKey(ctx, tx, d, id)
		if err != nil {
			return "", err
		}
		equal := subtle.ConstantTimeCompare(previous, key) == 1
		clear(previous)
		if equal {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_filevault_keys SET observed_at=GREATEST(observed_at,$2),verified_at=CASE WHEN $3 THEN GREATEST(verified_at,$2) ELSE verified_at END WHERE id=$1`, id, at, verified)
			if err == nil && source == "escrow" {
				err = audit(ctx, tx, d.TenantID, "device:"+d.ID, "apple.filevault.key.escrow", id)
			}
			return id, err
		}
	}
	if len(ids) >= 128 {
		return "", errRotationHistoryFull
	}
	id := uuid.NewString()
	sealed, err := s.secrets.seal(key, secretPurpose(d.TenantID, d.ID+"/"+id, "filevault_recovery_key"))
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_filevault_keys(id,tenant_id,device_id,escrow_id,recovery_key,observed_at,verified_at) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $7 THEN $6::timestamptz ELSE NULL END)`, id, d.TenantID, d.ID, escrow, sealed, at, verified)
	if err != nil {
		return "", err
	}
	if err = audit(ctx, tx, d.TenantID, "device:"+d.ID, "apple.filevault.key."+source, id); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) checkFileVaultRotation(ctx context.Context, scope Scope, device, id string) error {
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
	if err = s.reconcileFileVaultRotation(ctx, tx, d, id, r, cert, entity); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReconcileFileVaultRotations(ctx context.Context) error {
	if !rotationSchemaReady(ctx, s.db) {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,tenant_id,site_id FROM mdm_apple_filevault_rotations WHERE status IN ('queued','uncertain') AND next_check_at<=clock_timestamp() ORDER BY next_check_at,id LIMIT 25`)
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
		if err = s.checkFileVaultRotation(ctx, c.scope, c.device, c.id); err != nil {
			return err
		}
	}
	return nil
}
