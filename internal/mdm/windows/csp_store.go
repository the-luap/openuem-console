package windows

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type CSPCommand struct {
	ID       string
	DeviceID string
	access.Scope
	RequestKey         string
	CreatedBy          string
	CreatedByRevision  int64
	UserTarget         bool
	Revision           int64
	Phase              string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	UpdatedAt          time.Time
	DeliveredSessionID string
	DeliveredMessage   int
	DeliveredAt        *time.Time
	CompletedAt        *time.Time
}

func (CSPCommand) String() string     { return "[protected Windows CSP command metadata]" }
func (v CSPCommand) GoString() string { return v.String() }

type cspStoredCommand struct {
	CSPCommand
	digest  []byte
	request []byte
	result  []byte
}

// The salt is encrypted with the request so a database reader cannot recover
// low-entropy settings by hashing a dictionary of known CSP values.
type cspProtectedRequest struct {
	Version int
	Salt    []byte
	Payload []byte
}

func (cspProtectedRequest) String() string     { return "[protected Windows CSP request]" }
func (v cspProtectedRequest) GoString() string { return v.String() }

const cspCommandColumns = `id,device_id,tenant_id,site_id,request_key,request_digest,created_by,created_by_revision,user_target,revision,phase,encrypted_request,encrypted_result,created_at,expires_at,updated_at,COALESCE(delivered_session_id::text,''),COALESCE(delivered_message,0),delivered_at,completed_at`

type cspScanner interface{ Scan(...any) error }

func scanCSPCommand(row cspScanner) (*cspStoredCommand, error) {
	c := &cspStoredCommand{}
	err := row.Scan(&c.ID, &c.DeviceID, &c.TenantID, &c.SiteID, &c.RequestKey, &c.digest, &c.CreatedBy, &c.CreatedByRevision, &c.UserTarget, &c.Revision, &c.Phase, &c.request, &c.result, &c.CreatedAt, &c.ExpiresAt, &c.UpdatedAt, &c.DeliveredSessionID, &c.DeliveredMessage, &c.DeliveredAt, &c.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func cspPurpose(kind string, c *cspStoredCommand) string {
	return fmt.Sprintf("openuem/windows/csp/%s/v1/%s/%s/%d/%d/%s/%x/%x/%d/%t/%s/%s", kind, c.ID, c.DeviceID, c.TenantID, c.SiteID, c.RequestKey, c.digest, sha256.Sum256([]byte(c.CreatedBy)), c.CreatedByRevision, c.UserTarget, c.CreatedAt.UTC().Format(time.RFC3339Nano), c.ExpiresAt.UTC().Format(time.RFC3339Nano))
}

func cspResultPurpose(c *cspStoredCommand) string {
	return cspPurpose("result", c) + fmt.Sprintf("/%d/%s/%s/%d/%s/%s/%s", c.Revision, c.Phase, c.DeliveredSessionID, c.DeliveredMessage, c.UpdatedAt.UTC().Format(time.RFC3339Nano), cspOptionalTime(c.DeliveredAt), cspOptionalTime(c.CompletedAt))
}

func cspOptionalTime(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func cspRequestDigest(salt, payload []byte) []byte {
	h := sha256.New()
	h.Write([]byte("openuem/windows/csp-request/v1\x00"))
	h.Write(salt)
	h.Write(payload)
	return h.Sum(nil)
}

func (s *Store) openCSPRequest(c *cspStoredCommand) ([]byte, SyncMLCommand, error) {
	plain, err := s.secrets.openBounded(c.request, cspPurpose("request", c), maxCSPProtectedBytes)
	if err != nil {
		return nil, SyncMLCommand{}, err
	}
	defer clear(plain)
	var envelope cspProtectedRequest
	if decodeSyncMLProtectedJSON(plain, &envelope) != nil || envelope.Version != 1 || len(envelope.Salt) != 32 || !hmac.Equal(c.digest, cspRequestDigest(envelope.Salt, envelope.Payload)) {
		clear(envelope.Payload)
		clear(envelope.Salt)
		return nil, SyncMLCommand{}, ErrAuthoritySecret
	}
	clear(envelope.Salt)
	command, user, err := decodeCSPRequest(envelope.Payload)
	if err != nil || user != c.UserTarget {
		clear(envelope.Payload)
		return nil, SyncMLCommand{}, ErrAuthoritySecret
	}
	return envelope.Payload, command, nil
}

func (s *Store) authorizeCSPConsole(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, deviceID string, exclusive bool) error {
	if s == nil || s.permissions == nil || !validEnrollmentUsername(actor) || len(actor) > 255 || scope.TenantID <= 0 || scope.SiteID <= 0 || !canonicalInvitationID(deviceID) {
		return ErrCSPCommand
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageWindowsCSP, scope); err != nil {
		return err
	}
	if err := lockEnrollmentScope(ctx, tx, scope); err != nil {
		return err
	}
	lock := "FOR SHARE"
	if exclusive {
		lock = "FOR UPDATE"
	}
	var found string
	err := tx.QueryRowContext(ctx, `SELECT id FROM mdm_windows_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3 `+lock, deviceID, scope.TenantID, scope.SiteID).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// EnqueueCSPCommand requires a current organization/server administrator and a
// stable caller-generated request UUID. It queues intent; no device is contacted.
func (s *Store) EnqueueCSPCommand(ctx context.Context, actor string, scope access.Scope, deviceID, requestKey string, spec CSPCommandSpec, validFor time.Duration) (*CSPCommand, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(requestKey) || validFor < time.Minute || validFor > 7*24*time.Hour || validFor%time.Second != 0 {
		return nil, ErrCSPCommand
	}
	payload, user, err := encodeCSPRequest(spec)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeCSPConsole(ctx, tx, actor, scope, deviceID, true); err != nil {
		return nil, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, actor).Scan(&revision); err != nil {
		return nil, err
	}
	old, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND request_key=$4 FOR SHARE`, deviceID, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		if old.CreatedBy != actor || old.CreatedByRevision != revision || old.ExpiresAt.Sub(old.CreatedAt) != validFor {
			return nil, ErrCSPConflict
		}
		stored, _, err := s.openCSPRequest(old)
		if err != nil {
			return nil, err
		}
		defer clear(stored)
		if !bytes.Equal(stored, payload) {
			return nil, ErrCSPConflict
		}
		if err := auditCSP(ctx, tx, old, actor, "command.replayed"); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &old.CSPCommand, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var revoked bool
	var enrollmentType string
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL,enrollment_type FROM mdm_windows_devices WHERE id=$1`, deviceID).Scan(&revoked, &enrollmentType); err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrManagementIdentity
	}
	if user && enrollmentType != "Full" {
		return nil, ErrCSPCommand
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_windows_csp_commands WHERE device_id=$1 AND phase IN ('queued','blocked','sent','unknown')`, deviceID).Scan(&count); err != nil {
		return nil, err
	}
	if count >= 256 {
		return nil, ErrCSPQueueFull
	}
	c := &cspStoredCommand{CSPCommand: CSPCommand{ID: uuid.NewString(), DeviceID: deviceID, Scope: scope, RequestKey: requestKey, CreatedBy: actor, CreatedByRevision: revision, UserTarget: user, Revision: 1, Phase: "queued"}}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.CreatedAt); err != nil {
		return nil, err
	}
	c.UpdatedAt = c.CreatedAt
	c.ExpiresAt = c.CreatedAt.Add(validFor)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, ErrAuthoritySecret
	}
	defer clear(salt)
	c.digest = cspRequestDigest(salt, payload)
	envelope, err := json.Marshal(cspProtectedRequest{Version: 1, Salt: salt, Payload: payload})
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	defer clear(envelope)
	c.request, err = s.secrets.sealBounded(envelope, cspPurpose("request", c), maxCSPProtectedBytes)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_csp_commands(id,device_id,tenant_id,site_id,request_key,request_digest,created_by,created_by_revision,user_target,revision,phase,encrypted_request,created_at,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,'queued',$10,$11,$12,$11)`, c.ID, c.DeviceID, c.TenantID, c.SiteID, c.RequestKey, c.digest, c.CreatedBy, c.CreatedByRevision, c.UserTarget, c.request, c.CreatedAt, c.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err := auditCSP(ctx, tx, c, actor, "command.queued"); err != nil {
		return nil, err
	}
	if err := checkCSPDeadline(ctx, tx, c); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &c.CSPCommand, nil
}

func (s *Store) CSPCommand(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string) (*CSPCommand, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(commandID) {
		return nil, ErrCSPCommand
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeCSPConsole(ctx, tx, actor, scope, deviceID, false); err != nil {
		return nil, err
	}
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, commandID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if err := s.checkCSPIntegrity(c); err != nil {
		return nil, err
	}
	if err := auditCSP(ctx, tx, c, actor, "command.read"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &c.CSPCommand, nil
}

func (s *Store) CSPCommands(ctx context.Context, actor string, scope access.Scope, deviceID string, offset, limit int) ([]CSPCommand, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, ErrCSPCommand
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeCSPConsole(ctx, tx, actor, scope, deviceID, false); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 ORDER BY created_at DESC,id LIMIT $4 OFFSET $5`, deviceID, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	commands := []CSPCommand{}
	for rows.Next() {
		c, err := scanCSPCommand(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if err := s.checkCSPIntegrity(c); err != nil {
			rows.Close()
			return nil, err
		}
		commands = append(commands, c.CSPCommand)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, c := range commands {
		if err := auditCSP(ctx, tx, &cspStoredCommand{CSPCommand: c}, actor, "command.read"); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return commands, nil
}

// Status metadata is authenticated too: a substituted row revision or phase
// must not appear as successful execution in a list that omits payload data.
func (s *Store) checkCSPIntegrity(c *cspStoredCommand) error {
	plain, _, err := s.openCSPRequest(c)
	clear(plain)
	if err != nil {
		return err
	}
	_, err = s.openCSPResult(c)
	return err
}

func (s *Store) CancelCSPCommand(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string, expectedRevision int64) error {
	if s == nil || s.db == nil {
		return ErrStore
	}
	if s.secrets == nil {
		return ErrMasterKey
	}
	if !canonicalInvitationID(commandID) || expectedRevision < 1 {
		return ErrCSPCommand
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.authorizeCSPConsole(ctx, tx, actor, scope, deviceID, true); err != nil {
		return err
	}
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, commandID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if c.Revision != expectedRevision {
		return ErrCSPConflict
	}
	if c.Phase != "queued" && c.Phase != "blocked" {
		return ErrCSPAlreadySent
	}
	plain, _, err := s.openCSPRequest(c)
	clear(plain)
	if err != nil {
		return err
	}
	result, err := s.openCSPResult(c)
	if err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.UpdatedAt); err != nil {
		return err
	}
	c.Phase = "canceled"
	c.Revision++
	c.CompletedAt = &c.UpdatedAt
	result.Reason = "canceled"
	if err := s.writeCSPResult(ctx, tx, c, *result); err != nil {
		return err
	}
	if err := auditCSP(ctx, tx, c, actor, "command.canceled"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) updateCSPMetadata(ctx context.Context, tx *sql.Tx, c *cspStoredCommand, result []byte) error {
	updated, err := tx.ExecContext(ctx, `UPDATE mdm_windows_csp_commands SET revision=$5,phase=$6,encrypted_result=$7,updated_at=$8,delivered_session_id=NULLIF($9,'')::uuid,delivered_message=NULLIF($10,0),delivered_at=$11,completed_at=$12 WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND revision=$13`, c.ID, c.DeviceID, c.TenantID, c.SiteID, c.Revision, c.Phase, result, c.UpdatedAt, c.DeliveredSessionID, c.DeliveredMessage, c.DeliveredAt, c.CompletedAt, c.Revision-1)
	return syncMLUpdated(updated, err)
}

func auditCSP(ctx context.Context, tx *sql.Tx, c *cspStoredCommand, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_csp_audit(command_id,device_id,tenant_id,site_id,actor,action) VALUES($1,$2,$3,$4,$5,$6)`, c.ID, c.DeviceID, c.TenantID, c.SiteID, actor, action)
	return err
}

func checkCSPDeadline(ctx context.Context, tx *sql.Tx, c *cspStoredCommand) error {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if c.CreatedAt.After(now) || !c.ExpiresAt.After(now) {
		return ErrCSPDeadline
	}
	return nil
}
