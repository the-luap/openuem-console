package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const maxUnenrollmentIntentBytes = 8192

type UnenrollmentRequestDetail struct {
	Command        CSPCommand            `json:"-" xml:"-"`
	Reason         string                `json:"-" xml:"-"`
	ProviderID     string                `json:"-" xml:"-"`
	DeliveryReason string                `json:"-" xml:"-"`
	Outcomes       []CSPOperationOutcome `json:"-" xml:"-"`
	Release        *UnenrollmentRelease  `json:"-" xml:"-"`
}

// Release is an administrative review, never evidence of cleanup or a retry.
type UnenrollmentRelease struct {
	ReleasedBy       string    `json:"-" xml:"-"`
	ReviewedRevision int64     `json:"-" xml:"-"`
	ReleasedAt       time.Time `json:"-" xml:"-"`
	Reason           string    `json:"-" xml:"-"`
}

func (UnenrollmentRequestDetail) String() string     { return "[protected Windows disconnection request]" }
func (v UnenrollmentRequestDetail) GoString() string { return v.String() }
func (UnenrollmentRelease) String() string           { return "[protected Windows disconnection review]" }
func (v UnenrollmentRelease) GoString() string       { return v.String() }

type unenrollmentIntent struct {
	Version int
	Options EnrollmentOptions
	Reason  string
}

func (unenrollmentIntent) String() string     { return "[protected Windows disconnection intent]" }
func (v unenrollmentIntent) GoString() string { return v.String() }

func unenrollmentRequestPurpose(c *cspStoredCommand) string {
	return fmt.Sprintf("openuem/windows/unenrollment-request/v1/%s/%s/%d/%d/%s/%x/%d/%s/%s", c.ID, c.DeviceID, c.TenantID, c.SiteID, c.RequestKey, sha256.Sum256([]byte(c.CreatedBy)), c.CreatedByRevision, c.CreatedAt.UTC().Format(time.RFC3339Nano), c.ExpiresAt.UTC().Format(time.RFC3339Nano))
}
func unenrollmentReleasePurpose(c *cspStoredCommand, r *UnenrollmentRelease) string {
	return unenrollmentRequestPurpose(c) + fmt.Sprintf("/release/%x/%d/%s", sha256.Sum256([]byte(r.ReleasedBy)), r.ReviewedRevision, r.ReleasedAt.UTC().Format(time.RFC3339Nano))
}
func auditUnenrollmentRequest(ctx context.Context, tx *sql.Tx, id, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_unenrollment_request_audit(request_id,actor,action) VALUES($1,$2,$3)`, id, actor, action)
	return err
}

// The enrollment anchor is stable across certificate renewals. Opening its
// bootstrap binds the fixed provider and URL to the actual issued enrollment.
func (s *Store) unenrollmentAnchor(ctx context.Context, tx *sql.Tx, c *cspStoredCommand, options EnrollmentOptions) (ManagementDeviceIdentity, error) {
	identity := ManagementDeviceIdentity{DeviceID: c.DeviceID, Scope: c.Scope}
	err := tx.QueryRowContext(ctx, `SELECT e.certificate_id,a.authority_id,encode(a.fingerprint,'hex'),d.enrollment_type FROM mdm_windows_enrollments e JOIN mdm_windows_device_certificates a ON a.id=e.certificate_id AND a.device_id=e.device_id AND a.tenant_id=e.tenant_id AND a.site_id=e.site_id JOIN mdm_windows_devices d ON d.id=e.device_id AND d.tenant_id=e.tenant_id AND d.site_id=e.site_id WHERE e.device_id=$1 AND e.tenant_id=$2 AND e.site_id=$3 FOR SHARE OF e,a`, c.DeviceID, c.TenantID, c.SiteID).Scan(&identity.CertificateID, &identity.AuthorityID, &identity.FingerprintSHA256, &identity.EnrollmentType)
	if errors.Is(err, sql.ErrNoRows) {
		return identity, ErrAuthoritySecret
	}
	if err != nil {
		return identity, err
	}
	_, err = s.syncMLBootstrap(ctx, tx, identity, options)
	return identity, err
}

func (s *Store) unenrollmentForCommand(ctx context.Context, tx *sql.Tx, c *cspStoredCommand) (*unenrollmentIntent, *UnenrollmentRelease, error) {
	if c.UnenrollmentRequestID != c.ID || c.UpdateRunID != "" || c.UserTarget {
		return nil, nil, ErrAuthoritySecret
	}
	var encrypted []byte
	err := tx.QueryRowContext(ctx, `SELECT encrypted_intent FROM mdm_windows_unenrollment_requests WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND request_key=$5 AND created_by=$6 AND created_by_revision=$7 AND created_at=$8 AND expires_at=$9 FOR SHARE`, c.ID, c.DeviceID, c.TenantID, c.SiteID, c.RequestKey, c.CreatedBy, c.CreatedByRevision, c.CreatedAt, c.ExpiresAt).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrAuthoritySecret
	}
	if err != nil {
		return nil, nil, err
	}
	plain, err := s.secrets.openBounded(encrypted, unenrollmentRequestPurpose(c), maxUnenrollmentIntentBytes)
	if err != nil {
		return nil, nil, err
	}
	defer clear(plain)
	var intent unenrollmentIntent
	if decodeSyncMLProtectedJSON(plain, &intent) != nil || intent.Version != 1 || intent.Options.validate() != nil || !validEnrollmentUsername(intent.Reason) {
		return nil, nil, ErrAuthoritySecret
	}
	payload, _, err := s.openCSPRequest(c)
	defer clear(payload)
	if err != nil {
		return nil, nil, err
	}
	expected, err := encodeUnenrollmentRequest(intent.Options)
	defer clear(expected)
	if err != nil || !bytes.Equal(payload, expected) {
		return nil, nil, ErrAuthoritySecret
	}
	if _, err = s.unenrollmentAnchor(ctx, tx, c, intent.Options); err != nil {
		return nil, nil, err
	}
	release := &UnenrollmentRelease{}
	err = tx.QueryRowContext(ctx, `SELECT released_by,released_revision,released_at,encrypted_reason FROM mdm_windows_unenrollment_releases WHERE request_id=$1 FOR SHARE`, c.ID).Scan(&release.ReleasedBy, &release.ReviewedRevision, &release.ReleasedAt, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return &intent, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if c.DeliveredAt == nil || release.ReviewedRevision < 2 || release.ReviewedRevision > c.Revision || release.ReleasedAt.Before(*c.DeliveredAt) {
		return nil, nil, ErrAuthoritySecret
	}
	reason, err := s.secrets.openBounded(encrypted, unenrollmentReleasePurpose(c, release), maxUnenrollmentIntentBytes)
	if err != nil {
		return nil, nil, err
	}
	defer clear(reason)
	release.Reason = string(reason)
	if !validEnrollmentUsername(release.Reason) {
		return nil, nil, ErrAuthoritySecret
	}
	return &intent, release, nil
}

// EnqueueUnenrollmentRequest queues one fixed lifecycle action for the next
// authenticated device session. Calling it does not contact or revoke the device.
func (s *Store) EnqueueUnenrollmentRequest(ctx context.Context, actor string, scope access.Scope, deviceID, requestKey, reason string, validFor time.Duration, options EnrollmentOptions) (*CSPCommand, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(requestKey) || !validEnrollmentUsername(reason) || validFor < time.Minute || validFor > 7*24*time.Hour || validFor%time.Second != 0 {
		return nil, ErrUnenrollmentRequest
	}
	payload, err := encodeUnenrollmentRequest(options)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorizeWindowsConsole(ctx, tx, actor, access.RevokeDevices, scope, deviceID, true); err != nil {
		return nil, err
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, actor).Scan(&revision); err != nil {
		return nil, err
	}
	old, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND request_key=$4 FOR SHARE`, deviceID, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		if old.UnenrollmentRequestID == "" || old.CreatedBy != actor || old.CreatedByRevision != revision || old.ExpiresAt.Sub(old.CreatedAt) != validFor {
			return nil, ErrCSPConflict
		}
		intent, _, err := s.unenrollmentForCommand(ctx, tx, old)
		if err != nil {
			return nil, err
		}
		if intent.Reason != reason || !bytes.Equal(enrollmentConfigurationDigest(intent.Options), enrollmentConfigurationDigest(options)) {
			return nil, ErrCSPConflict
		}
		if err = s.checkCSPIntegrity(old); err != nil {
			return nil, err
		}
		if err = auditUnenrollmentRequest(ctx, tx, old.ID, actor, "request.replayed"); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return &old.CSPCommand, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var revoked bool
	if err = tx.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM mdm_windows_devices WHERE id=$1`, deviceID).Scan(&revoked); err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrManagementIdentity
	}
	// Existing queued requests and delivered requests awaiting review exclude a
	// second intent. Every release is authenticated before it can reopen delivery.
	requests, err := s.unenrollmentCommands(ctx, tx, scope, deviceID, 0, 0)
	if err != nil {
		return nil, err
	}
	for _, old := range requests {
		_, release, err := s.unenrollmentForCommand(ctx, tx, old)
		if err != nil {
			return nil, err
		}
		if err = s.checkCSPIntegrity(old); err != nil {
			return nil, err
		}
		if old.Phase == "queued" || old.Phase == "blocked" || old.DeliveredAt != nil && release == nil {
			return nil, ErrUnenrollmentRequest
		}
	}
	c := &cspStoredCommand{CSPCommand: CSPCommand{ID: uuid.NewString(), DeviceID: deviceID, Scope: scope, RequestKey: requestKey, CreatedBy: actor, CreatedByRevision: revision, Revision: 1, Phase: "queued"}}
	c.UnenrollmentRequestID = c.ID
	if _, err = s.unenrollmentAnchor(ctx, tx, c, options); err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.CreatedAt); err != nil {
		return nil, err
	}
	c.UpdatedAt = c.CreatedAt
	c.ExpiresAt = c.CreatedAt.Add(validFor)
	plain, err := json.Marshal(unenrollmentIntent{Version: 1, Options: options, Reason: reason})
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	defer clear(plain)
	encrypted, err := s.secrets.sealBounded(plain, unenrollmentRequestPurpose(c), maxUnenrollmentIntentBytes)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_unenrollment_requests(id,device_id,tenant_id,site_id,request_key,created_by,created_by_revision,created_at,expires_at,encrypted_intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, c.ID, c.DeviceID, c.TenantID, c.SiteID, c.RequestKey, c.CreatedBy, c.CreatedByRevision, c.CreatedAt, c.ExpiresAt, encrypted)
	if err != nil {
		return nil, err
	}
	if err = s.insertCSPCommand(ctx, tx, c, payload); err != nil {
		return nil, err
	}
	if err = auditUnenrollmentRequest(ctx, tx, c.ID, actor, "request.created"); err != nil {
		return nil, err
	}
	if err = checkCSPDeadline(ctx, tx, c); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &c.CSPCommand, nil
}

// limit zero is an internal complete history read under the device lock.
func (s *Store) unenrollmentCommands(ctx context.Context, tx *sql.Tx, scope access.Scope, deviceID string, offset, limit int) ([]*cspStoredCommand, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND unenrollment_request_id IS NOT NULL ORDER BY created_at DESC,id LIMIT NULLIF($4,0) OFFSET $5`, deviceID, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	commands := []*cspStoredCommand{}
	for rows.Next() {
		c, err := scanCSPCommand(rows)
		if err != nil {
			return nil, err
		}
		commands = append(commands, c)
	}
	return commands, rows.Err()
}

func (s *Store) UnenrollmentRequests(ctx context.Context, actor string, scope access.Scope, deviceID string, offset, limit int) ([]UnenrollmentRequestDetail, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, ErrUnenrollmentRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorizeWindowsConsole(ctx, tx, actor, access.RevokeDevices, scope, deviceID, false); err != nil {
		return nil, err
	}
	commands, err := s.unenrollmentCommands(ctx, tx, scope, deviceID, offset, limit)
	if err != nil {
		return nil, err
	}
	details := []UnenrollmentRequestDetail{}
	for _, c := range commands {
		detail, err := s.unenrollmentRequestDetail(ctx, tx, c, actor)
		if err != nil {
			return nil, err
		}
		details = append(details, *detail)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return details, nil
}

func (s *Store) unenrollmentRequestDetail(ctx context.Context, tx *sql.Tx, c *cspStoredCommand, actor string) (*UnenrollmentRequestDetail, error) {
	intent, release, err := s.unenrollmentForCommand(ctx, tx, c)
	if err != nil {
		return nil, err
	}
	result, err := s.openCSPResult(c)
	if err != nil {
		return nil, err
	}
	detail := &UnenrollmentRequestDetail{Command: c.CSPCommand, Reason: intent.Reason, ProviderID: intent.Options.ProviderID, DeliveryReason: result.Reason, Outcomes: cspOperationOutcomes(result.Exchange), Release: release}
	if err = auditUnenrollmentRequest(ctx, tx, c.ID, actor, "request.read"); err != nil {
		return nil, err
	}
	return detail, nil
}

func (s *Store) UnenrollmentRequestDetails(ctx context.Context, actor string, scope access.Scope, deviceID, requestID string) (*UnenrollmentRequestDetail, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(requestID) {
		return nil, ErrUnenrollmentRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorizeWindowsConsole(ctx, tx, actor, access.RevokeDevices, scope, deviceID, false); err != nil {
		return nil, err
	}
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND unenrollment_request_id=id FOR SHARE`, requestID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	detail, err := s.unenrollmentRequestDetail(ctx, tx, c, actor)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return detail, nil
}

func (s *Store) CancelUnenrollmentRequest(ctx context.Context, actor string, scope access.Scope, deviceID, requestID string, expectedRevision int64) error {
	return s.resolveUnenrollmentRequest(ctx, actor, scope, deviceID, requestID, expectedRevision, "")
}

// ReleaseUnenrollmentRequest permits later management after an explicit review.
// A delivered Exec may still run. This neither undoes it nor restores revoked
// access; a later authenticated disconnection notification still retires access.
func (s *Store) ReleaseUnenrollmentRequest(ctx context.Context, actor string, scope access.Scope, deviceID, requestID string, expectedRevision int64, reason string) error {
	if !validEnrollmentUsername(reason) {
		return ErrUnenrollmentRequest
	}
	return s.resolveUnenrollmentRequest(ctx, actor, scope, deviceID, requestID, expectedRevision, reason)
}

func (s *Store) resolveUnenrollmentRequest(ctx context.Context, actor string, scope access.Scope, deviceID, requestID string, expectedRevision int64, reason string) error {
	if s == nil || s.db == nil {
		return ErrStore
	}
	if s.secrets == nil {
		return ErrMasterKey
	}
	if !canonicalInvitationID(requestID) || expectedRevision < 1 {
		return ErrUnenrollmentRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.authorizeWindowsConsole(ctx, tx, actor, access.RevokeDevices, scope, deviceID, true); err != nil {
		return err
	}
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND unenrollment_request_id=id FOR UPDATE`, requestID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if c.Revision != expectedRevision {
		return ErrCSPConflict
	}
	intent, release, err := s.unenrollmentForCommand(ctx, tx, c)
	if err != nil {
		return err
	}
	result, err := s.openCSPResult(c)
	if err != nil {
		return err
	}
	action := "request.canceled"
	if reason == "" {
		if c.Phase != "queued" && c.Phase != "blocked" {
			return ErrCSPAlreadySent
		}
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.UpdatedAt); err != nil {
			return err
		}
		c.Revision++
		c.Phase = "canceled"
		c.CompletedAt = &c.UpdatedAt
		result.Reason = "canceled"
		if err = s.writeCSPResult(ctx, tx, c, *result); err != nil {
			return err
		}
		if err = auditCSP(ctx, tx, c, actor, "command.canceled"); err != nil {
			return err
		}
	} else {
		if c.DeliveredAt == nil || release != nil {
			return ErrUnenrollmentRequest
		}
		identity, err := s.unenrollmentAnchor(ctx, tx, c, intent.Options)
		if err != nil {
			return err
		}
		session, err := s.lockSyncMLSession(ctx, tx, identity, intent.Options, c.DeliveredSessionID)
		if err != nil {
			return err
		}
		current, err := s.lockCurrentCSP(ctx, tx, identity, session)
		if err != nil {
			return err
		}
		if current == nil || current.ID != c.ID {
			return ErrAuthoritySecret
		}
		if !syncMLTerminal(session.Phase) {
			session.Phase = "aborted"
			session.Revision++
			if err = s.stopCSPSession(ctx, tx, identity, session); err != nil {
				return err
			}
			if err = s.saveSyncMLSession(ctx, tx, identity, intent.Options, session, false); err != nil {
				return err
			}
			if err = auditSyncML(ctx, tx, identity, session.ID, "session.aborted"); err != nil {
				return err
			}
		}
		release = &UnenrollmentRelease{ReleasedBy: actor, ReviewedRevision: expectedRevision, Reason: reason}
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&release.ReleasedAt); err != nil {
			return err
		}
		encrypted, err := s.secrets.sealBounded([]byte(reason), unenrollmentReleasePurpose(c, release), maxUnenrollmentIntentBytes)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_unenrollment_releases(request_id,released_by,released_revision,released_at,encrypted_reason) VALUES($1,$2,$3,$4,$5)`, c.ID, release.ReleasedBy, release.ReviewedRevision, release.ReleasedAt, encrypted)
		if err != nil {
			return err
		}
		action = "request.released"
	}
	if err = auditUnenrollmentRequest(ctx, tx, c.ID, actor, action); err != nil {
		return err
	}
	return tx.Commit()
}
