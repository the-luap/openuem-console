package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const maxRenewalRecordBytes = 128 << 10

var ErrCertificateRenewal = errors.New("invalid native Windows certificate renewal")
var ErrRenewalWindow = errors.New("the native Windows certificate is outside its renewal window")
var ErrRenewalConflict = errors.New("native Windows certificate renewal conflicts with existing work")

type CertificateRenewalRequest struct {
	MessageID string
	CMSDER    []byte     `json:"-" xml:"-" yaml:"-"`
	CreatedAt *time.Time `json:"-" xml:"-" yaml:"-"`
	ExpiresAt *time.Time `json:"-" xml:"-" yaml:"-"`
}

func (CertificateRenewalRequest) String() string     { return "[protected Windows renewal request]" }
func (v CertificateRenewalRequest) GoString() string { return v.String() }

type CertificateRenewal struct {
	ID                   string       `json:"-" xml:"-" yaml:"-"`
	DeviceID             string       `json:"-" xml:"-" yaml:"-"`
	Scope                access.Scope `json:"-" xml:"-" yaml:"-"`
	SourceCertificateID  string       `json:"-" xml:"-" yaml:"-"`
	RenewedCertificateID string       `json:"-" xml:"-" yaml:"-"`
	Revision             int64        `json:"-" xml:"-" yaml:"-"`
	Phase                string       `json:"-" xml:"-" yaml:"-"`
	CreatedAt            time.Time    `json:"-" xml:"-" yaml:"-"`
	CompletedAt          *time.Time   `json:"-" xml:"-" yaml:"-"`
	ConfirmedSessionID   string       `json:"-" xml:"-" yaml:"-"`
	ConfirmedMessageID   int          `json:"-" xml:"-" yaml:"-"`
}

func (CertificateRenewal) String() string     { return "[protected Windows certificate renewal]" }
func (v CertificateRenewal) GoString() string { return v.String() }

type storedCertificateRenewal struct {
	CertificateRenewal
	requestID                                                      int64
	requestDigest, configurationDigest, confirmedDigest, encrypted []byte
}

type renewalRecord struct {
	Version      int
	CMS          []byte
	Provisioning []byte
	Options      EnrollmentOptions
	Resolution   string
}

func (renewalRecord) String() string     { return "[protected Windows renewal record]" }
func (v renewalRecord) GoString() string { return v.String() }

const renewalColumns = `id,device_id,tenant_id,site_id,source_certificate_id,renewed_certificate_id,request_id,request_digest,configuration_digest,revision,phase,encrypted_record,created_at,completed_at,COALESCE(confirmed_session_id::text,''),COALESCE(confirmed_message_id,0),confirmed_request_digest`

func scanCertificateRenewal(row cspScanner) (*storedCertificateRenewal, error) {
	r := &storedCertificateRenewal{}
	err := row.Scan(&r.ID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.SourceCertificateID, &r.RenewedCertificateID, &r.requestID, &r.requestDigest, &r.configurationDigest, &r.Revision, &r.Phase, &r.encrypted, &r.CreatedAt, &r.CompletedAt, &r.ConfirmedSessionID, &r.ConfirmedMessageID, &r.confirmedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !canonicalInvitationID(r.ID) || !canonicalInvitationID(r.DeviceID) || !canonicalInvitationID(r.SourceCertificateID) || !canonicalInvitationID(r.RenewedCertificateID) || r.SourceCertificateID == r.RenewedCertificateID || r.Scope.TenantID <= 0 || r.Scope.SiteID <= 0 || r.requestID < 1 || r.Revision < 1 || !slices.Contains([]string{"pending", "confirmed", "canceled"}, r.Phase) || len(r.requestDigest) != 32 || len(r.configurationDigest) != 32 || (r.Phase == "pending") != (r.CompletedAt == nil) {
		return nil, ErrAuthoritySecret
	}
	if r.CompletedAt != nil && r.CompletedAt.Before(r.CreatedAt) {
		return nil, ErrAuthoritySecret
	}
	if r.Phase == "confirmed" {
		if !canonicalInvitationID(r.ConfirmedSessionID) || r.ConfirmedMessageID < 1 || r.ConfirmedMessageID > maxSyncMLSessionMessages || len(r.confirmedDigest) != 32 {
			return nil, ErrAuthoritySecret
		}
	} else if r.ConfirmedSessionID != "" || r.ConfirmedMessageID != 0 || len(r.confirmedDigest) != 0 {
		return nil, ErrAuthoritySecret
	}
	return r, nil
}

func certificateRenewalPurpose(r *storedCertificateRenewal) string {
	completed := ""
	if r.CompletedAt != nil {
		completed = r.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("openuem/windows/certificate-renewal/v1/%s/%s/%d/%d/%s/%s/%d/%x/%x/%d/%s/%s/%s/%s/%d/%x", r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.SourceCertificateID, r.RenewedCertificateID, r.requestID, r.requestDigest, r.configurationDigest, r.Revision, r.Phase, r.CreatedAt.UTC().Format(time.RFC3339Nano), completed, r.ConfirmedSessionID, r.ConfirmedMessageID, r.confirmedDigest)
}

func renewalRequestDigest(csr []byte) []byte {
	h := sha256.New()
	h.Write([]byte("openuem/windows/certificate-renewal-request/v1\x00"))
	h.Write(csr)
	return h.Sum(nil)
}

func buildRenewalProvisioning(options EnrollmentOptions, deviceID, enrollmentType string, root, certificate *x509.Certificate) ([]byte, error) {
	if options.validate() != nil || !canonicalInvitationID(deviceID) || (enrollmentType != "Full" && enrollmentType != "Device") || root == nil || certificate == nil || certificate.Subject.CommonName != "OpenUEM Windows "+deviceID || certificate.IsCA || certificate.CheckSignatureFrom(root) != nil {
		return nil, ErrProvisioning
	}
	location := "User"
	if enrollmentType == "Device" {
		location = "System"
	}
	leaf := provisioningCertificate(certificate)
	leaf.Children = []provisioningCharacteristic{{Type: "PrivateKeyContainer"}}
	document := provisioningDocument{Version: "1.1", Characteristics: []provisioningCharacteristic{
		{Type: "CertificateStore", Children: []provisioningCharacteristic{{Type: "My", Children: []provisioningCharacteristic{{Type: location, Children: []provisioningCharacteristic{leaf}}}}}},
		{Type: "APPLICATION", Parameters: []provisioningParameter{provisioningParam("APPID", "w7", ""), provisioningParam("PROVIDER-ID", options.ProviderID, "")}},
	}}
	data, err := xml.Marshal(document)
	if err != nil || len(data) > maxProvisioningBytes {
		return nil, ErrProvisioning
	}
	return data, nil
}

func (s *Store) renewalCertificate(ctx context.Context, tx *sql.Tx, r *storedCertificateRenewal, id string) (*managementDevice, *EnrollmentAuthority, error) {
	d := &managementDevice{identity: ManagementDeviceIdentity{DeviceID: r.DeviceID, CertificateID: id, Scope: r.Scope}}
	var der, fingerprint, public, serial []byte
	err := tx.QueryRowContext(ctx, `SELECT c.authority_id,c.certificate,c.fingerprint,c.public_key_fingerprint,c.serial,c.issued_at,c.expires_at,d.enrollment_type,d.created_at FROM mdm_windows_device_certificates c JOIN mdm_windows_devices d ON d.id=c.device_id AND d.tenant_id=c.tenant_id AND d.site_id=c.site_id WHERE c.id=$1 AND c.device_id=$2 AND c.tenant_id=$3 AND c.site_id=$4 FOR SHARE OF c,d`, id, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID).Scan(&d.identity.AuthorityID, &der, &fingerprint, &public, &serial, &d.issued, &d.identity.CertificateExpiry, &d.identity.EnrollmentType, &d.deviceCreated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrAuthoritySecret
	}
	if err != nil {
		return nil, nil, err
	}
	d.certificate, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, ErrAuthoritySecret
	}
	hash := sha256.Sum256(der)
	if !bytes.Equal(hash[:], fingerprint) {
		return nil, nil, ErrAuthoritySecret
	}
	d.identity.FingerprintSHA256 = hex.EncodeToString(fingerprint)
	a, err := scanAuthority(tx.QueryRowContext(ctx, `SELECT `+authorityColumns+` FROM mdm_windows_authorities WHERE id=$1 AND tenant_id=$2 FOR SHARE`, d.identity.AuthorityID, r.Scope.TenantID))
	if err != nil {
		return nil, nil, err
	}
	d.root, err = parseAuthorityCertificate(*a)
	if err != nil {
		return nil, nil, err
	}
	d.caCreated = a.CreatedAt
	if err := validateManagementCertificate(d, *a, public, serial); err != nil {
		return nil, nil, err
	}
	return d, a, nil
}

func (s *Store) openCertificateRenewal(ctx context.Context, tx *sql.Tx, r *storedCertificateRenewal) (*renewalRecord, error) {
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	plain, err := s.secrets.openBounded(r.encrypted, certificateRenewalPurpose(r), maxRenewalRecordBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var record renewalRecord
	if decodeSyncMLProtectedJSON(plain, &record) != nil || record.Version != 1 || record.Options.validate() != nil || !bytes.Equal(enrollmentConfigurationDigest(record.Options), r.configurationDigest) || len(record.Provisioning) > maxProvisioningBytes || len(record.CMS) > MaxWindowsRenewalProofBytes {
		return nil, ErrAuthoritySecret
	}
	if (r.Phase == "canceled" && !validEnrollmentUsername(record.Resolution)) || (r.Phase != "canceled" && record.Resolution != "") {
		return nil, ErrAuthoritySecret
	}
	source, a, err := s.renewalCertificate(ctx, tx, r, r.SourceCertificateID)
	if err != nil {
		return nil, err
	}
	renewed, _, err := s.renewalCertificate(ctx, tx, r, r.RenewedCertificateID)
	if err != nil {
		return nil, err
	}
	proof, err := VerifyWindowsRenewalProof(record.CMS, source.certificate.Raw, a.MinimumKeyBits)
	if err != nil || !bytes.Equal(renewalRequestDigest(proof.CSR.Raw), r.requestDigest) || !bytes.Equal(proof.CSR.RawSubjectPublicKeyInfo, renewed.certificate.RawSubjectPublicKeyInfo) || renewed.identity.AuthorityID != source.identity.AuthorityID || !renewed.issued.Equal(r.CreatedAt) {
		return nil, ErrAuthoritySecret
	}
	provisioning, err := buildRenewalProvisioning(record.Options, r.DeviceID, source.identity.EnrollmentType, renewed.root, renewed.certificate)
	defer clear(provisioning)
	if err != nil || !bytes.Equal(provisioning, record.Provisioning) {
		return nil, ErrAuthoritySecret
	}
	if r.Phase == "confirmed" {
		var digest []byte
		if err := tx.QueryRowContext(ctx, `SELECT request_digest FROM mdm_windows_syncml_packets WHERE session_id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND message_id=$5`, r.ConfirmedSessionID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.ConfirmedMessageID).Scan(&digest); err != nil || !bytes.Equal(digest, r.confirmedDigest) {
			return nil, ErrAuthoritySecret
		}
	}
	return &record, nil
}

func (s *Store) sealCertificateRenewal(r *storedCertificateRenewal, record *renewalRecord) error {
	plain, err := json.Marshal(record)
	if err != nil {
		return ErrAuthoritySecret
	}
	defer clear(plain)
	r.encrypted, err = s.secrets.sealBounded(plain, certificateRenewalPurpose(r), maxRenewalRecordBytes)
	return err
}

func auditCertificateRenewal(ctx context.Context, tx *sql.Tx, r *storedCertificateRenewal, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_renewal_audit(renewal_id,device_id,tenant_id,site_id,actor,action) VALUES($1,$2,$3,$4,$5,$6)`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, actor, action)
	return err
}

// Complete the handoff only after the new transport key participates in a
// mutually authenticated exchange. The caller holds the device exclusively and
// commits the packet, nonce state, certificate transition and audit together.
func (s *Store) confirmCertificateRenewal(ctx context.Context, tx *sql.Tx, device *managementDevice, session *syncMLSession, messageID int, digest []byte) error {
	r := device.pendingRenewal
	if r == nil || !session.State.ClientAuthenticated || !session.State.ServerVerified {
		return nil
	}
	record, err := s.openCertificateRenewal(ctx, tx, r)
	if err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	r.Phase, r.CompletedAt = "confirmed", &now
	r.Revision++
	r.ConfirmedSessionID, r.ConfirmedMessageID, r.confirmedDigest = session.ID, messageID, digest
	if err := s.saveCertificateRenewal(ctx, tx, r, record); err != nil {
		return err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE mdm_windows_device_certificates SET revoked_at=$5 WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND revoked_at IS NULL`, r.SourceCertificateID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, now)
	if err := syncMLUpdated(updated, err); err != nil {
		return err
	}
	return auditCertificateRenewal(ctx, tx, r, "windows-renewal", "renewal.confirmed")
}

func (s *Store) saveCertificateRenewal(ctx context.Context, tx *sql.Tx, r *storedCertificateRenewal, record *renewalRecord) error {
	if err := s.sealCertificateRenewal(r, record); err != nil {
		return err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE mdm_windows_certificate_renewals SET revision=$5,phase=$6,encrypted_record=$7,completed_at=$8,confirmed_session_id=NULLIF($9,'')::uuid,confirmed_message_id=NULLIF($10,0),confirmed_request_digest=$11 WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND phase='pending' AND revision=$12`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.Revision, r.Phase, r.encrypted, r.CompletedAt, r.ConfirmedSessionID, r.ConfirmedMessageID, r.confirmedDigest, r.Revision-1)
	return syncMLUpdated(updated, err)
}

func (s *Store) authorizeRenewalConsole(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, deviceID string, exclusive bool) error {
	if !canonicalInvitationID(deviceID) {
		return ErrConsoleInput
	}
	if err := s.authorizeConsole(ctx, tx, actor, scope, access.ManageCertificates); err != nil {
		return err
	}
	lock := "FOR SHARE"
	if exclusive {
		lock = "FOR UPDATE"
	}
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM mdm_windows_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3 `+lock, deviceID, scope.TenantID, scope.SiteID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// CertificateRenewals returns authenticated lifecycle metadata without exposing
// the proof, provisioning or resolution note. Revoked devices retain history.
func (s *Store) CertificateRenewals(ctx context.Context, actor string, scope access.Scope, deviceID string, offset, limit int) ([]CertificateRenewal, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !validConsolePage(offset, limit) {
		return nil, ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeRenewalConsole(ctx, tx, actor, scope, deviceID, false); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+renewalColumns+` FROM mdm_windows_certificate_renewals WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 ORDER BY created_at DESC,id DESC LIMIT $4 OFFSET $5 FOR SHARE`, deviceID, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	var stored []*storedCertificateRenewal
	for rows.Next() {
		r, err := scanCertificateRenewal(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		stored = append(stored, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []CertificateRenewal{}
	for _, r := range stored {
		if _, err := s.openCertificateRenewal(ctx, tx, r); err != nil {
			return nil, err
		}
		if err := auditCertificateRenewal(ctx, tx, r, actor, "renewal.read"); err != nil {
			return nil, err
		}
		result = append(result, r.CertificateRenewal)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// CancelCertificateRenewal revokes only an unconfirmed replacement. It cannot
// reactivate a retired key or roll back a confirmed handoff.
func (s *Store) CancelCertificateRenewal(ctx context.Context, actor string, scope access.Scope, deviceID, renewalID string, expectedRevision int64, reason string) error {
	if s == nil || s.db == nil {
		return ErrStore
	}
	if s.secrets == nil {
		return ErrMasterKey
	}
	if !canonicalInvitationID(renewalID) || expectedRevision < 1 || !validEnrollmentUsername(reason) {
		return ErrConsoleInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.authorizeRenewalConsole(ctx, tx, actor, scope, deviceID, true); err != nil {
		return err
	}
	r, err := scanCertificateRenewal(tx.QueryRowContext(ctx, `SELECT `+renewalColumns+` FROM mdm_windows_certificate_renewals WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, renewalID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if r.Revision != expectedRevision || r.Phase != "pending" {
		return ErrRenewalConflict
	}
	record, err := s.openCertificateRenewal(ctx, tx, r)
	if err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	r.Phase, r.CompletedAt, record.Resolution = "canceled", &now, reason
	r.Revision++
	if err := s.saveCertificateRenewal(ctx, tx, r, record); err != nil {
		return err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE mdm_windows_device_certificates SET revoked_at=$5 WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND revoked_at IS NULL`, r.RenewedCertificateID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, now)
	if err := syncMLUpdated(updated, err); err != nil {
		return err
	}
	if err := auditCertificateRenewal(ctx, tx, r, actor, "renewal.canceled"); err != nil {
		return err
	}
	return tx.Commit()
}

func checkCertificateRenewalWindow(ctx context.Context, tx *sql.Tx, device *managementDevice, authority EnrollmentAuthority) error {
	if err := checkManagementDeviceTime(ctx, tx, device); err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if now.Before(device.certificate.NotAfter.Add(-time.Duration(authority.RenewalSeconds)*time.Second)) || !device.certificate.NotAfter.After(now) {
		return ErrRenewalWindow
	}
	return nil
}

// A WS-Security timestamp is an optional freshness constraint, never identity
// or a replacement for CMS proof. Recheck it after database/audit waits.
func checkRenewalRequestTime(ctx context.Context, tx *sql.Tx, request CertificateRenewalRequest) error {
	if request.CreatedAt == nil && request.ExpiresAt == nil {
		return nil
	}
	if request.CreatedAt == nil || request.ExpiresAt == nil || !request.ExpiresAt.After(*request.CreatedAt) || request.ExpiresAt.Sub(*request.CreatedAt) > 10*time.Minute {
		return ErrCertificateRenewal
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if request.CreatedAt.After(now.Add(5*time.Minute)) || !request.ExpiresAt.After(now) {
		return ErrCertificateRenewal
	}
	return nil
}

// RenewWindowsCertificate issues one pending replacement from an authenticated
// current device certificate. The transport must supply the actual peer leaf;
// scope and identity are derived again under database locks. Issuance does not
// activate the candidate or change existing enrollment/SyncML credentials.
func (s *Store) RenewWindowsCertificate(ctx context.Context, certificate *x509.Certificate, request CertificateRenewalRequest, options EnrollmentOptions) ([]byte, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !validMessageID(request.MessageID) || len(request.CMSDER) == 0 || len(request.CMSDER) > MaxWindowsRenewalProofBytes || options.validate() != nil {
		return nil, ErrCertificateRenewal
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627902)`); err != nil {
		return nil, err
	}
	if err := checkRenewalRequestTime(ctx, tx, request); err != nil {
		return nil, err
	}
	device, err := s.authorizeManagementDeviceExclusive(ctx, tx, certificate, options)
	if err != nil {
		return nil, err
	}
	if device.pendingRenewal != nil {
		return nil, ErrRenewalConflict
	}
	a, err := s.enrollmentAuthority(ctx, tx, device.identity.TenantID)
	if err != nil {
		return nil, err
	}
	if a.metadata.ID != device.identity.AuthorityID {
		return nil, ErrAuthoritySecret
	}
	if err := checkCertificateRenewalWindow(ctx, tx, device, a.metadata); err != nil {
		return nil, err
	}
	proof, err := VerifyWindowsRenewalProof(request.CMSDER, device.certificate.Raw, a.metadata.MinimumKeyBits)
	if err != nil {
		return nil, err
	}
	digest := renewalRequestDigest(proof.CSR.Raw)
	old, err := scanCertificateRenewal(tx.QueryRowContext(ctx, `SELECT `+renewalColumns+` FROM mdm_windows_certificate_renewals WHERE source_certificate_id=$1 AND request_digest=$2 FOR UPDATE`, device.identity.CertificateID, digest))
	if err == nil {
		if old.Phase == "canceled" || !bytes.Equal(old.configurationDigest, enrollmentConfigurationDigest(options)) {
			return nil, ErrRenewalConflict
		}
		record, err := s.openCertificateRenewal(ctx, tx, old)
		if err != nil {
			return nil, err
		}
		response, err := buildWSTEPResponse(request.MessageID, old.requestID, record.Provisioning)
		if err != nil {
			return nil, err
		}
		if err := auditCertificateRenewal(ctx, tx, old, "windows-renewal", "renewal.replayed"); err != nil {
			return nil, err
		}
		if err := checkCertificateRenewalWindow(ctx, tx, device, a.metadata); err != nil {
			return nil, err
		}
		if err := checkRenewalRequestTime(ctx, tx, request); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return response, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var pending bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_windows_certificate_renewals WHERE device_id=$1 AND phase='pending')`, device.identity.DeviceID).Scan(&pending); err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrRenewalConflict
	}
	r := &storedCertificateRenewal{CertificateRenewal: CertificateRenewal{ID: uuid.NewString(), DeviceID: device.identity.DeviceID, Scope: device.identity.Scope, SourceCertificateID: device.identity.CertificateID, RenewedCertificateID: uuid.NewString(), Revision: 1, Phase: "pending"}, requestDigest: digest, configurationDigest: enrollmentConfigurationDigest(options)}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp(),nextval(pg_get_serial_sequence('mdm_windows_enrollments','request_id'))`).Scan(&r.CreatedAt, &r.requestID); err != nil {
		return nil, err
	}
	renewed, err := issueEnrollmentCertificate(a, r.DeviceID, r.Scope, proof.CSR, r.CreatedAt)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(renewed.Raw)
	public := sha256.Sum256(renewed.RawSubjectPublicKeyInfo)
	if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_device_certificates(id,device_id,tenant_id,site_id,authority_id,certificate,fingerprint,public_key_fingerprint,serial,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, r.RenewedCertificateID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, a.metadata.ID, renewed.Raw, fingerprint[:], public[:], renewed.SerialNumber.Bytes(), r.CreatedAt, renewed.NotAfter); err != nil {
		return nil, err
	}
	provisioning, err := buildRenewalProvisioning(options, r.DeviceID, device.identity.EnrollmentType, a.certificate, renewed)
	if err != nil {
		return nil, err
	}
	defer clear(provisioning)
	record := &renewalRecord{Version: 1, CMS: request.CMSDER, Provisioning: provisioning, Options: options}
	if err := s.sealCertificateRenewal(r, record); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_certificate_renewals(id,device_id,tenant_id,site_id,source_certificate_id,renewed_certificate_id,request_id,request_digest,configuration_digest,revision,phase,encrypted_record,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,'pending',$10,$11)`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.SourceCertificateID, r.RenewedCertificateID, r.requestID, r.requestDigest, r.configurationDigest, r.encrypted, r.CreatedAt); err != nil {
		return nil, err
	}
	response, err := buildWSTEPResponse(request.MessageID, r.requestID, provisioning)
	if err != nil {
		return nil, err
	}
	if err := auditCertificateRenewal(ctx, tx, r, "windows-renewal", "renewal.issued"); err != nil {
		return nil, err
	}
	if err := checkCertificateRenewalWindow(ctx, tx, device, a.metadata); err != nil {
		return nil, err
	}
	if err := checkRenewalRequestTime(ctx, tx, request); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}
