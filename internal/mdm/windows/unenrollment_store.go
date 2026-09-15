package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const maxUnenrollmentRecordBytes = 2 << 20

// UnenrollmentReport records an authenticated notification and retirement of
// server access. It never asserts that Windows completed its local cleanup.
type UnenrollmentReport struct {
	ID                   string       `json:"-" xml:"-" yaml:"-"`
	DeviceID             string       `json:"-" xml:"-" yaml:"-"`
	Scope                access.Scope `json:"-" xml:"-" yaml:"-"`
	CertificateID        string       `json:"-" xml:"-" yaml:"-"`
	FingerprintSHA256    string       `json:"-" xml:"-" yaml:"-"`
	InterruptedSessionID string       `json:"-" xml:"-" yaml:"-"`
	WireSessionID        string       `json:"-" xml:"-" yaml:"-"`
	AlertCommandID       string       `json:"-" xml:"-" yaml:"-"`
	ReceivedAt           time.Time    `json:"-" xml:"-" yaml:"-"`
}

func (UnenrollmentReport) String() string     { return "[protected Windows unenrollment report]" }
func (v UnenrollmentReport) GoString() string { return v.String() }

type storedUnenrollmentReport struct {
	UnenrollmentReport
	anchorCertificateID                                   string
	fingerprint, requestDigest, responseDigest, encrypted []byte
}

func (storedUnenrollmentReport) String() string     { return "[protected Windows unenrollment record]" }
func (v storedUnenrollmentReport) GoString() string { return v.String() }

type unenrollmentRecord struct {
	Version           int
	Request, Response []byte
	Options           EnrollmentOptions
	Nonces            syncMLDeviceNonces
}

func (unenrollmentRecord) String() string     { return "[protected Windows unenrollment proof]" }
func (v unenrollmentRecord) GoString() string { return v.String() }

func unenrollmentPurpose(r *storedUnenrollmentReport) string {
	return fmt.Sprintf("openuem/windows/unenrollment/v1/%s/%s/%d/%d/%s/%s/%x/%x/%x/%s/%s", r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.CertificateID, r.anchorCertificateID, r.fingerprint, r.requestDigest, r.responseDigest, r.InterruptedSessionID, r.ReceivedAt.UTC().Format(time.RFC3339Nano))
}

func auditUnenrollment(ctx context.Context, tx *sql.Tx, r *storedUnenrollmentReport, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_unenrollment_audit(report_id,device_id,tenant_id,site_id,actor,action) VALUES($1,$2,$3,$4,$5,$6)`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, actor, action)
	return err
}

// A valid first-package notification is independent of any interrupted session.
// Only the current next-session digest can authorize this one-way transition.
// Normal replay and management authentication never admit a retired identity.
func (s *Store) acceptUnenrollment(ctx context.Context, tx *sql.Tx, device *managementDevice, record *syncMLDeviceRecord, session *syncMLSession, request *SyncMLMessage, alert *SyncMLCommand, data []byte, options EnrollmentOptions, secrets *syncMLBootstrapSecrets) ([]byte, error) {
	response, err := unenrollmentResponse(device.stateIdentity, options, request, alert, secrets, record.Nonces)
	if err != nil {
		return nil, err
	}
	r := &storedUnenrollmentReport{UnenrollmentReport: UnenrollmentReport{ID: uuid.NewString(), DeviceID: device.identity.DeviceID, Scope: device.identity.Scope, CertificateID: device.identity.CertificateID}, anchorCertificateID: device.stateIdentity.CertificateID}
	r.fingerprint, err = hex.DecodeString(device.identity.FingerprintSHA256)
	if err != nil || len(r.fingerprint) != sha256.Size {
		return nil, ErrAuthoritySecret
	}
	requestDigest, responseDigest := sha256.Sum256(data), sha256.Sum256(response)
	r.requestDigest, r.responseDigest = requestDigest[:], responseDigest[:]
	if session != nil && !syncMLTerminal(session.Phase) {
		r.InterruptedSessionID = session.ID
		session.Phase = "aborted"
		session.Revision++
		if err := s.stopCSPSession(ctx, tx, device.stateIdentity, session); err != nil {
			return nil, err
		}
		if err := s.saveSyncMLSession(ctx, tx, device.stateIdentity, options, session, false); err != nil {
			return nil, err
		}
		if err := auditSyncML(ctx, tx, device.stateIdentity, session.ID, "session.aborted"); err != nil {
			return nil, err
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.ReceivedAt); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(unenrollmentRecord{Version: 1, Request: data, Response: response, Options: options, Nonces: record.Nonces})
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	defer clear(plain)
	r.encrypted, err = s.secrets.sealBounded(plain, unenrollmentPurpose(r), maxUnenrollmentRecordBytes)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_unenrollment_reports(id,device_id,tenant_id,site_id,certificate_id,anchor_certificate_id,fingerprint,request_digest,response_digest,interrupted_session_id,encrypted_record,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,'')::uuid,$11,$12)`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.CertificateID, r.anchorCertificateID, r.fingerprint, r.requestDigest, r.responseDigest, r.InterruptedSessionID, r.encrypted, r.ReceivedAt)
	if err != nil {
		return nil, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE mdm_windows_devices SET revoked_at=$4 WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND revoked_at IS NULL`, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.ReceivedAt)
	if err = syncMLUpdated(updated, err); err != nil {
		return nil, err
	}
	if err = auditUnenrollment(ctx, tx, r, "windows-device", "unenrollment.reported"); err != nil {
		return nil, err
	}
	// Scope/device/certificate locks remain held. Recheck the actual TLS leaf's
	// lifetime after every audit/command wait before making revocation durable.
	if err = checkManagementDeviceTime(ctx, tx, device); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Store) readUnenrollmentReport(ctx context.Context, tx *sql.Tx, scope access.Scope, deviceID string) (*storedUnenrollmentReport, error) {
	r := &storedUnenrollmentReport{}
	var revoked *time.Time
	err := tx.QueryRowContext(ctx, `SELECT r.id,r.device_id,r.tenant_id,r.site_id,r.certificate_id,r.anchor_certificate_id,r.fingerprint,r.request_digest,r.response_digest,COALESCE(r.interrupted_session_id::text,''),r.encrypted_record,r.received_at,d.revoked_at FROM mdm_windows_unenrollment_reports r JOIN mdm_windows_devices d ON d.id=r.device_id AND d.tenant_id=r.tenant_id AND d.site_id=r.site_id WHERE r.device_id=$1 AND r.tenant_id=$2 AND r.site_id=$3 FOR SHARE OF r,d`, deviceID, scope.TenantID, scope.SiteID).Scan(&r.ID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.CertificateID, &r.anchorCertificateID, &r.fingerprint, &r.requestDigest, &r.responseDigest, &r.InterruptedSessionID, &r.encrypted, &r.ReceivedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if revoked == nil || !revoked.Equal(r.ReceivedAt) || len(r.fingerprint) != sha256.Size || len(r.requestDigest) != sha256.Size || len(r.responseDigest) != sha256.Size {
		return nil, ErrAuthoritySecret
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	plain, err := s.secrets.openBounded(r.encrypted, unenrollmentPurpose(r), maxUnenrollmentRecordBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var record unenrollmentRecord
	if decodeSyncMLProtectedJSON(plain, &record) != nil || record.Version != 1 || record.Options.validate() != nil || record.Nonces.validate() != nil || len(record.Request) > MaxSyncMLBytes || len(record.Response) > MaxSyncMLBytes {
		return nil, ErrAuthoritySecret
	}
	requestDigest, responseDigest := sha256.Sum256(record.Request), sha256.Sum256(record.Response)
	if !bytes.Equal(requestDigest[:], r.requestDigest) || !bytes.Equal(responseDigest[:], r.responseDigest) {
		return nil, ErrAuthoritySecret
	}
	request, err := ParseSyncML(record.Request)
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	alert, err := syncMLUnenrollmentAlert(request)
	if err != nil || alert == nil {
		return nil, ErrAuthoritySecret
	}
	identity := ManagementDeviceIdentity{DeviceID: deviceID, CertificateID: r.anchorCertificateID, Scope: scope}
	var der []byte
	err = tx.QueryRowContext(ctx, `SELECT a.authority_id,encode(a.fingerprint,'hex'),c.certificate FROM mdm_windows_enrollments e JOIN mdm_windows_device_certificates a ON a.id=e.certificate_id AND a.device_id=e.device_id AND a.tenant_id=e.tenant_id AND a.site_id=e.site_id JOIN mdm_windows_device_certificates c ON c.id=$4 AND c.device_id=e.device_id AND c.tenant_id=e.tenant_id AND c.site_id=e.site_id WHERE e.device_id=$1 AND e.tenant_id=$2 AND e.site_id=$3 AND e.certificate_id=$5 FOR SHARE OF e,a,c`, deviceID, scope.TenantID, scope.SiteID, r.CertificateID, r.anchorCertificateID).Scan(&identity.AuthorityID, &identity.FingerprintSHA256, &der)
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	fingerprint := sha256.Sum256(der)
	if !bytes.Equal(fingerprint[:], r.fingerprint) {
		return nil, ErrAuthoritySecret
	}
	secrets, err := s.syncMLBootstrap(ctx, tx, identity, record.Options)
	if err != nil {
		return nil, err
	}
	response, err := unenrollmentResponse(identity, record.Options, request, alert, secrets, record.Nonces)
	defer clear(response)
	if err != nil || !bytes.Equal(response, record.Response) {
		return nil, ErrAuthoritySecret
	}
	if r.InterruptedSessionID != "" {
		old, err := s.lockSyncMLSession(ctx, tx, identity, record.Options, r.InterruptedSessionID)
		if err != nil || old.Phase != "aborted" {
			return nil, ErrAuthoritySecret
		}
	}
	r.FingerprintSHA256 = hex.EncodeToString(r.fingerprint)
	r.WireSessionID, r.AlertCommandID = request.Header.SessionID, alert.ID
	return r, nil
}

func (s *Store) UnenrollmentReport(ctx context.Context, actor string, scope access.Scope, deviceID string) (*UnenrollmentReport, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(deviceID) || scope.SiteID <= 0 {
		return nil, ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorizeConsole(ctx, tx, actor, scope, access.ReadDevices); err != nil {
		return nil, err
	}
	r, err := s.readUnenrollmentReport(ctx, tx, scope, deviceID)
	if err != nil {
		return nil, err
	}
	if err = auditUnenrollment(ctx, tx, r, actor, "unenrollment.read"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &r.UnenrollmentReport, nil
}
