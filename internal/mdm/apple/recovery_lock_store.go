package apple

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type RecoveryLock struct {
	CurrentKeyID string               `json:"current_key_id"`
	Evidence     string               `json:"evidence"`
	Reason       string               `json:"reason"`
	Attempt      *RecoveryLockAttempt `json:"attempt,omitempty"`
}

type RecoveryLockAttempt struct {
	CanCheckPrevious    bool       `json:"can_check_previous"`
	ID                  string     `json:"id"`
	Operation           string     `json:"operation"`
	Status              string     `json:"status"`
	Error               string     `json:"error"`
	CandidateKeyID      string     `json:"candidate_key_id"`
	PreviousKeyID       string     `json:"previous_key_id"`
	CreatedAt           time.Time  `json:"created_at"`
	CompletedAt         *time.Time `json:"completed_at"`
	command, setCommand string
}

func (a RecoveryLockAttempt) Active() bool {
	switch a.Status {
	case "checking", "queued", "sent", "verifying", "uncertain":
		return true
	}
	return false
}

type RecoveryLockKey struct {
	ID         string     `json:"id"`
	Source     string     `json:"source"`
	Current    bool       `json:"current"`
	CreatedAt  time.Time  `json:"created_at"`
	VerifiedAt *time.Time `json:"verified_at"`
	RejectedAt *time.Time `json:"rejected_at"`
}

const recoveryLockAttemptColumns = `id,operation,status,error,COALESCE(previous_key_id::text,''),COALESCE(candidate_key_id::text,''),COALESCE(command_id::text,''),COALESCE(set_command_id::text,''),created_at,completed_at`

func scanRecoveryLockAttempt(row scanner) (*RecoveryLockAttempt, error) {
	var a RecoveryLockAttempt
	err := row.Scan(&a.ID, &a.Operation, &a.Status, &a.Error, &a.PreviousKeyID, &a.CandidateKeyID, &a.command, &a.setCommand, &a.CreatedAt, &a.CompletedAt)
	return &a, notFound(err)
}

func (s *Store) RecoveryLock(ctx context.Context, scope Scope, id string) (*RecoveryLock, error) {
	d, err := s.Device(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	result := &RecoveryLock{Evidence: "unknown", Reason: d.RecoveryLockReason(time.Now())}
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(current_key_id::text,''),evidence FROM mdm_apple_recovery_lock_state WHERE device_id=$1 AND tenant_id=$2`, id, scope.TenantID).Scan(&result.CurrentKeyID, &result.Evidence)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	result.Attempt, err = scanRecoveryLockAttempt(s.db.QueryRowContext(ctx, `SELECT `+recoveryLockAttemptColumns+` FROM mdm_apple_recovery_lock_attempts WHERE device_id=$1 AND tenant_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, id, scope.TenantID))
	if errors.Is(err, ErrNotFound) {
		result.Attempt = nil
		err = nil
	}
	if err == nil && result.Attempt != nil && result.Attempt.Status == "uncertain" && result.Attempt.PreviousKeyID != "" && result.Attempt.setCommand != "" {
		err = s.db.QueryRowContext(ctx, `SELECT result IN ('acknowledged','error') FROM mdm_apple_recovery_lock_commands WHERE command_id=$1`, result.Attempt.setCommand).Scan(&result.Attempt.CanCheckPrevious)
	}
	return result, err
}

func (s *Store) RecoveryLockKeys(ctx context.Context, scope Scope, id string) ([]RecoveryLockKey, error) {
	if _, err := s.Device(ctx, scope, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT k.id,k.source,COALESCE(s.current_key_id=k.id,false),k.created_at,k.verified_at,k.rejected_at FROM mdm_apple_recovery_lock_keys k LEFT JOIN mdm_apple_recovery_lock_state s ON s.device_id=k.device_id WHERE k.device_id=$1 AND k.tenant_id=$2 ORDER BY k.created_at DESC,k.id DESC LIMIT 128`, id, scope.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []RecoveryLockKey{}
	for rows.Next() {
		var key RecoveryLockKey
		if err = rows.Scan(&key.ID, &key.Source, &key.Current, &key.CreatedAt, &key.VerifiedAt, &key.RejectedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func recoveryLockAuthorize(scope Scope, actor string, permissions *access.Store, capability access.Capability) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		if permissions == nil {
			return access.ErrDenied
		}
		return permissions.AuthorizeTransaction(ctx, tx, actor, capability, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
	}
}

func (s *Store) RequestRecoveryLock(ctx context.Context, scope Scope, device, operation, key string, password []byte, actor string, permissions *access.Store) error {
	return s.requestRecoveryLock(ctx, scope, device, operation, key, password, actor, recoveryLockAuthorize(scope, actor, permissions, access.ManageDeviceSecurity))
}

func (s *Store) requestRecoveryLock(ctx context.Context, scope Scope, device, operation, key string, password []byte, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if actor == "" || len(actor) > 255 {
		return ErrRecoveryLock
	}
	switch operation {
	case "set", "rotate", "remove", "verify", "import", "recheck":
	default:
		return ErrRecoveryLock
	}
	if (operation == "import" && !validRecoveryLockPassword(password)) || (operation != "import" && len(password) > 0) {
		return ErrRecoveryLock
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
	d, err := lockFileVaultDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	if err = s.recoveryLockEligible(ctx, tx, d); err != nil {
		return err
	}
	if err = s.reconcileRecoveryLock(ctx, tx, d, false); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_recovery_lock_state(device_id,tenant_id) VALUES($1,$2) ON CONFLICT(device_id) DO NOTHING`, d.ID, d.TenantID); err != nil {
		return err
	}
	var current string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(current_key_id::text,'') FROM mdm_apple_recovery_lock_state WHERE device_id=$1`, d.ID).Scan(&current); err != nil {
		return err
	}
	active, err := scanRecoveryLockAttempt(tx.QueryRowContext(ctx, `SELECT `+recoveryLockAttemptColumns+` FROM mdm_apple_recovery_lock_attempts WHERE device_id=$1 AND status IN ('checking','queued','sent','verifying','uncertain')`, d.ID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		if operation != "recheck" || active.Status != "uncertain" {
			return ErrConflict
		}
		purpose := "candidate"
		if key == "" {
			return ErrRecoveryLock
		}
		if key != active.CandidateKeyID {
			if key != active.PreviousKeyID || active.setCommand == "" {
				return ErrRecoveryLock
			}
			var stopped bool
			if err = tx.QueryRowContext(ctx, `SELECT result IN ('acknowledged','error') FROM mdm_apple_recovery_lock_commands WHERE command_id=$1`, active.setCommand).Scan(&stopped); err != nil {
				return err
			}
			if !stopped {
				return ErrConflict
			}
			purpose = "previous"
		}
		if err = s.queueRecoveryLockCommand(ctx, tx, d, active, purpose); err != nil {
			return err
		}
		if err = audit(ctx, tx, d.TenantID, actor, "apple.recovery_lock.recheck", active.ID); err != nil {
			return err
		}
		return tx.Commit()
	}
	if operation == "recheck" {
		return ErrConflict
	}
	a := &RecoveryLockAttempt{ID: uuid.NewString(), Operation: operation, Status: "verifying"}
	purpose := "candidate"
	switch operation {
	case "set":
		if current != "" || key != "" {
			return ErrConflict
		}
		fallthrough
	case "rotate":
		if operation == "rotate" && (key == "" || key != current) {
			return ErrConflict
		}
		plain, e := newRecoveryLockPassword()
		if e != nil {
			return e
		}
		defer clear(plain)
		a.CandidateKeyID, err = s.retainRecoveryLockPassword(ctx, tx, d, plain, "generated")
		if err != nil {
			return err
		}
		if operation == "rotate" {
			a.PreviousKeyID = current
			a.Status = "checking"
			purpose = "current"
		} else {
			a.Status = "queued"
			purpose = "set"
		}
	case "remove":
		if key == "" || key != current {
			return ErrConflict
		}
		a.PreviousKeyID = current
		a.Status = "checking"
		purpose = "current"
	case "verify":
		if key == "" || key != current {
			return ErrConflict
		}
		a.CandidateKeyID = current
	case "import":
		if key != "" {
			return ErrRecoveryLock
		}
		a.CandidateKeyID, err = s.retainRecoveryLockPassword(ctx, tx, d, password, "imported")
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_recovery_lock_attempts(id,tenant_id,site_id,device_id,operation,status,previous_key_id,candidate_key_id) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,'')::uuid,NULLIF($8,'')::uuid)`, a.ID, d.TenantID, d.SiteID, d.ID, a.Operation, a.Status, a.PreviousKeyID, a.CandidateKeyID); err != nil {
		return err
	}
	if err = s.queueRecoveryLockCommand(ctx, tx, d, a, purpose); err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.recovery_lock."+operation, a.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) recoveryLockEligible(ctx context.Context, tx *sql.Tx, d *Device) error {
	if d.RecoveryLockReason(time.Now()) != "" {
		return ErrRecoveryLock
	}
	l, err := loadEnrollmentLayout(ctx, tx, d.ID)
	if err != nil || l.accessRights != enrollmentRights(true) {
		return ErrRecoveryLock
	}
	return nil
}

func (s *Store) openRecoveryLockPassword(ctx context.Context, tx *sql.Tx, d *Device, id string) ([]byte, error) {
	var encrypted []byte
	if err := tx.QueryRowContext(ctx, `SELECT password FROM mdm_apple_recovery_lock_keys WHERE id=$1 AND device_id=$2 AND tenant_id=$3`, id, d.ID, d.TenantID).Scan(&encrypted); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(encrypted, secretPurpose(d.TenantID, d.ID+"/"+id, "recovery_lock_password"))
	if err != nil || !validRecoveryLockPassword(plain) {
		clear(plain)
		return nil, ErrRecoveryLock
	}
	return plain, nil
}

func (s *Store) retainRecoveryLockPassword(ctx context.Context, tx *sql.Tx, d *Device, password []byte, source string) (string, error) {
	if !validRecoveryLockPassword(password) {
		return "", ErrRecoveryLock
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,password FROM mdm_apple_recovery_lock_keys WHERE device_id=$1 AND tenant_id=$2 ORDER BY id LIMIT 129`, d.ID, d.TenantID)
	if err != nil {
		return "", err
	}
	count := 0
	found := ""
	for rows.Next() {
		var id string
		var encrypted []byte
		if err = rows.Scan(&id, &encrypted); err != nil {
			rows.Close()
			return "", err
		}
		count++
		plain, e := s.secrets.open(encrypted, secretPurpose(d.TenantID, d.ID+"/"+id, "recovery_lock_password"))
		if e != nil {
			rows.Close()
			return "", ErrRecoveryLock
		}
		if bytes.Equal(plain, password) {
			found = id
		}
		clear(plain)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if found != "" {
		return found, nil
	}
	if count >= 128 {
		return "", ErrRecoveryLock
	}
	id := uuid.NewString()
	encrypted, err := s.secrets.seal(password, secretPurpose(d.TenantID, d.ID+"/"+id, "recovery_lock_password"))
	if err != nil {
		return "", ErrRecoveryLock
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_recovery_lock_keys(id,tenant_id,device_id,password,source) VALUES($1,$2,$3,$4,$5)`, id, d.TenantID, d.ID, encrypted, source)
	return id, err
}

func (s *Store) queueRecoveryLockCommand(ctx context.Context, tx *sql.Tx, d *Device, a *RecoveryLockAttempt, purpose string) error {
	if err := s.recoveryLockEligible(ctx, tx, d); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_recovery_lock_commands WHERE attempt_id=$1`, a.ID).Scan(&count); err != nil {
		return err
	}
	if count >= 32 {
		return ErrRecoveryLock
	}
	var previous, candidate []byte
	var err error
	if purpose == "set" {
		if a.PreviousKeyID != "" {
			previous, err = s.openRecoveryLockPassword(ctx, tx, d, a.PreviousKeyID)
			if err != nil {
				return err
			}
			defer clear(previous)
		}
		if a.CandidateKeyID != "" {
			candidate, err = s.openRecoveryLockPassword(ctx, tx, d, a.CandidateKeyID)
			if err != nil {
				return err
			}
			defer clear(candidate)
		}
	} else {
		key := a.CandidateKeyID
		if purpose == "current" || purpose == "previous" {
			key = a.PreviousKeyID
		}
		candidate, err = s.openRecoveryLockPassword(ctx, tx, d, key)
		if err != nil {
			return err
		}
		defer clear(candidate)
	}
	id := uuid.NewString()
	plain, kind, err := recoveryLockPayload(id, purpose, previous, candidate)
	if err != nil {
		return err
	}
	defer clear(plain)
	encrypted, err := s.secrets.seal(plain, secretPurpose(d.TenantID, id, "command"))
	if err != nil {
		return ErrRecoveryLock
	}
	expires := time.Now().Add(time.Hour)
	if d.CertificateExpiresAt.Before(expires) {
		expires = d.CertificateExpiresAt
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_commands(id,tenant_id,device_id,request_type,payload,recovery_lock,expires_at) VALUES($1,$2,$3,$4,$5,true,$6)`, id, d.TenantID, d.ID, kind, encrypted, expires); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_recovery_lock_commands(command_id,tenant_id,device_id,attempt_id,purpose) VALUES($1,$2,$3,$4,$5)`, id, d.TenantID, d.ID, a.ID, purpose); err != nil {
		return err
	}
	// Replaced read-only commands can still produce late replies, but only the
	// selected command may advance this attempt or refresh password evidence.
	if a.command != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',payload='\x',completed_at=clock_timestamp() WHERE id=$1 AND request_type='VerifyRecoveryLock' AND status IN ('queued','sent','not_now')`, a.command); err != nil {
			return err
		}
	}
	phase := "verifying"
	if purpose == "current" {
		phase = "checking"
	}
	if purpose == "set" {
		phase = "queued"
		a.setCommand = id
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_recovery_lock_attempts SET status=$2,command_id=$3,set_command_id=NULLIF($4,'')::uuid,error='',next_check_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, a.ID, phase, id, a.setCommand); err != nil {
		return err
	}
	a.command = id
	a.Status = phase
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_push_at=clock_timestamp() WHERE id=$1`, d.ID)
	return err
}

func (s *Store) RevealRecoveryLockPassword(ctx context.Context, scope Scope, device, key, actor string, permissions *access.Store) ([]byte, error) {
	return s.revealRecoveryLockPassword(ctx, scope, device, key, actor, recoveryLockAuthorize(scope, actor, permissions, access.RetrieveRecoveryKeys))
}

func (s *Store) revealRecoveryLockPassword(ctx context.Context, scope Scope, device, key, actor string, authorize func(context.Context, *sql.Tx) error) ([]byte, error) {
	if actor == "" || len(actor) > 255 {
		return nil, ErrRecoveryLock
	}
	if id, err := uuid.Parse(key); err != nil || id == uuid.Nil || id.String() != key {
		return nil, ErrRecoveryLock
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
	plain, err := s.openRecoveryLockPassword(ctx, tx, d, key)
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.recovery_lock.password.reveal", key); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(plain)
		return nil, err
	}
	return plain, nil
}
