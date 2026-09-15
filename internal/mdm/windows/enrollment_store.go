package windows

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrEnrollmentReplay = errors.New("Windows enrollment request differs from its completed issuance")
var ErrWindowsDeviceType = errors.New("native Windows enrollment requires a desktop MDM client")

func enrollmentRequestDigest(request *WSTEPRequest) []byte {
	items := slices.Clone(request.Context)
	slices.SortFunc(items, func(a, b EnrollmentContextItem) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Value, b.Value)
	})
	// MessageID is response correlation, not the identity of the certified key.
	// A retry may use a new MessageID but must carry the exact same CSR/context.
	data, _ := json.Marshal(struct {
		Version string
		CSR     []byte
		Context []EnrollmentContextItem
	}{"openuem/windows/enrollment-request/v1", request.CSRDER, items})
	digest := sha256.Sum256(data)
	return digest[:]
}

func enrollmentConfigurationDigest(options EnrollmentOptions) []byte {
	data, _ := json.Marshal(options)
	digest := sha256.Sum256(append([]byte("openuem/windows/provisioning-config/v1\x00"), data...))
	return digest[:]
}

// EnrollWindows authorizes a one-use invitation and verified CSR, then commits
// device identity, its certificate, encrypted bootstrap state and audit together.
// Only an exact CSR/context/configuration retry can retrieve the same result for
// ten minutes, and never after invitation expiry/revocation or permission loss.
// It does not report a successful management session or register a public route.
func (s *Store) EnrollWindows(ctx context.Context, request *WSTEPRequest, options EnrollmentOptions) ([]byte, error) {
	if request == nil || !validMessageID(request.MessageID) || validateEnrollmentContext(request.Context) != nil || len(request.CSRDER) == 0 || len(request.CSRDER) > MaxEnrollmentCSRBytes {
		return nil, ErrWSTEP
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	i, err := s.authorizeEnrollmentCredentialUse(ctx, tx, request.Credential, credentialIssueOrReplay)
	if err != nil {
		return nil, err
	}
	if enrollmentContextValue(request.Context, "DeviceType") != "CIMClient_Windows" {
		return nil, ErrWindowsDeviceType
	}
	requestDigest, configDigest := enrollmentRequestDigest(request), enrollmentConfigurationDigest(options)
	if i.ConsumedAt != nil {
		data, err := s.replayWindowsEnrollment(ctx, tx, *i, request, requestDigest, configDigest)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return data, nil
	}
	a, err := s.enrollmentAuthority(ctx, tx, i.TenantID)
	if err != nil {
		return nil, err
	}
	csr, err := verifyEnrollmentCSR(request.CSRDER, a.metadata.MinimumKeyBits)
	if err != nil {
		return nil, err
	}
	deviceID, certificateID := uuid.NewString(), uuid.NewString()
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	certificate, err := issueEnrollmentCertificate(a, deviceID, i.Scope, csr, now)
	if err != nil {
		return nil, err
	}
	secrets, err := newSyncMLBootstrapSecrets()
	if err != nil {
		return nil, err
	}
	enrollmentType := enrollmentContextValue(request.Context, "EnrollmentType")
	provisioning, err := buildProvisioningDocument(options, deviceID, enrollmentType, a.certificate, certificate, secrets)
	if err != nil {
		return nil, err
	}
	defer clear(provisioning)
	fingerprint := sha256.Sum256(certificate.Raw)
	keyFingerprint := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	purpose := func(kind string) string {
		return enrollmentSecretPurpose(kind, i.TenantID, i.SiteID, deviceID, a.metadata.ID, fingerprint[:], requestDigest, configDigest)
	}
	encryptedProvisioning, err := s.secrets.sealBounded(provisioning, purpose("provisioning"), maxProvisioningBytes)
	if err != nil {
		return nil, err
	}
	auth, err := json.Marshal(secrets)
	if err != nil {
		return nil, ErrProvisioning
	}
	defer clear(auth)
	encryptedAuth, err := s.secrets.seal(auth, purpose("syncml-bootstrap"))
	if err != nil {
		return nil, err
	}
	edition, _ := strconv.ParseUint(enrollmentContextValue(request.Context, "OSEdition"), 10, 32)
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_devices(id,tenant_id,site_id,invitation_id,reported_device_id,device_name,enrollment_type,os_edition,os_version,application_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, deviceID, i.TenantID, i.SiteID, i.ID, enrollmentContextValue(request.Context, "DeviceID"), enrollmentContextValue(request.Context, "DeviceName"), enrollmentType, int64(edition), enrollmentContextValue(request.Context, "OSVersion"), enrollmentContextValue(request.Context, "ApplicationVersion"))
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_device_certificates(id,device_id,tenant_id,site_id,authority_id,certificate,fingerprint,public_key_fingerprint,serial,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, certificateID, deviceID, i.TenantID, i.SiteID, a.metadata.ID, certificate.Raw, fingerprint[:], keyFingerprint[:], certificate.SerialNumber.Bytes(), now, certificate.NotAfter)
	if err != nil {
		return nil, err
	}
	var requestID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO mdm_windows_enrollments(invitation_id,tenant_id,site_id,device_id,certificate_id,request_digest,configuration_digest,encrypted_provisioning,encrypted_auth) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING request_id`, i.ID, i.TenantID, i.SiteID, deviceID, certificateID, requestDigest, configDigest, encryptedProvisioning, encryptedAuth).Scan(&requestID)
	if err != nil {
		return nil, err
	}
	response, err := buildWSTEPResponse(request.MessageID, requestID, provisioning)
	if err != nil {
		return nil, err
	}
	if err := consumeEnrollmentInvitation(ctx, tx, *i); err != nil {
		return nil, err
	}
	if err := auditInvitation(ctx, tx, *i, "windows-enrollment", "enrollment.issued"); err != nil {
		return nil, err
	}
	if err := activeEnrollmentInvitationUse(ctx, tx, i.ID, true); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Store) replayWindowsEnrollment(ctx context.Context, tx *sql.Tx, i EnrollmentInvitation, request *WSTEPRequest, requestDigest, configDigest []byte) ([]byte, error) {
	var deviceID, authorityID string
	var requestID int64
	var storedRequest, storedConfig, encrypted, encryptedAuth, fingerprint, certificateDER []byte
	err := tx.QueryRowContext(ctx, `SELECT e.device_id,c.authority_id,e.request_id,e.request_digest,e.configuration_digest,e.encrypted_provisioning,e.encrypted_auth,c.fingerprint,c.certificate FROM mdm_windows_enrollments e JOIN mdm_windows_devices d ON d.id=e.device_id AND d.invitation_id=e.invitation_id AND d.tenant_id=e.tenant_id AND d.site_id=e.site_id JOIN mdm_windows_device_certificates c ON c.id=e.certificate_id AND c.device_id=d.id AND c.tenant_id=e.tenant_id AND c.site_id=e.site_id WHERE e.invitation_id=$1 AND e.tenant_id=$2 AND e.site_id=$3 AND d.revoked_at IS NULL AND c.revoked_at IS NULL AND c.issued_at<=clock_timestamp() AND c.expires_at>clock_timestamp() FOR SHARE OF e,d,c`, i.ID, i.TenantID, i.SiteID).Scan(&deviceID, &authorityID, &requestID, &storedRequest, &storedConfig, &encrypted, &encryptedAuth, &fingerprint, &certificateDER)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCredential
	}
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(requestDigest, storedRequest) || !hmac.Equal(configDigest, storedConfig) {
		return nil, ErrEnrollmentReplay
	}
	a, err := scanAuthority(tx.QueryRowContext(ctx, `SELECT `+authorityColumns+` FROM mdm_windows_authorities WHERE id=$1 AND tenant_id=$2 FOR SHARE`, authorityID, i.TenantID))
	if err != nil {
		return nil, err
	}
	csr, err := verifyEnrollmentCSR(request.CSRDER, a.MinimumKeyBits)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, ErrAuthority
	}
	root, err := parseAuthorityCertificate(*a)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(certificateDER)
	public, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !hmac.Equal(public, cert.RawSubjectPublicKeyInfo) || !hmac.Equal(hash[:], fingerprint) || cert.CheckSignatureFrom(root) != nil || cert.Subject.CommonName != "OpenUEM Windows "+deviceID || cert.IsCA {
		return nil, ErrAuthority
	}
	purpose := enrollmentSecretPurpose("provisioning", i.TenantID, i.SiteID, deviceID, authorityID, fingerprint, requestDigest, configDigest)
	authPurpose := enrollmentSecretPurpose("syncml-bootstrap", i.TenantID, i.SiteID, deviceID, authorityID, fingerprint, requestDigest, configDigest)
	auth, err := s.secrets.open(encryptedAuth, authPurpose)
	if err != nil {
		return nil, err
	}
	defer clear(auth)
	var credentials syncMLBootstrapSecrets
	if json.Unmarshal(auth, &credentials) != nil || credentials.validate() != nil {
		return nil, ErrAuthoritySecret
	}
	provisioning, err := s.secrets.openBounded(encrypted, purpose, maxProvisioningBytes)
	if err != nil {
		return nil, err
	}
	defer clear(provisioning)
	response, err := buildWSTEPResponse(request.MessageID, requestID, provisioning)
	if err != nil {
		return nil, err
	}
	if err := auditInvitation(ctx, tx, i, "windows-enrollment", "enrollment.replayed"); err != nil {
		return nil, err
	}
	if err := activeEnrollmentInvitationUse(ctx, tx, i.ID, true); err != nil {
		return nil, err
	}
	return response, nil
}
