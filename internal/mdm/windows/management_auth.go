package windows

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrManagementIdentity = errors.New("native Windows management device authentication failed")

// ManagementDeviceIdentity is a point-in-time transport identity, not a SyncML
// session or an authorization token. Never accept it back from an HTTP client or
// use a previous result to authorize a later command or database transaction.
type ManagementDeviceIdentity struct {
	DeviceID      string
	CertificateID string
	AuthorityID   string
	access.Scope
	EnrollmentType    string
	FingerprintSHA256 string
	CertificateExpiry time.Time
}

type managementDevice struct {
	identity                         ManagementDeviceIdentity
	certificate, root                *x509.Certificate
	deviceCreated, issued, caCreated time.Time
}

// AuthenticateManagementDevice verifies the direct TLS peer at the configured
// management endpoint and returns public identity only. It does not read a body,
// verify SyncML credentials, create a session, or record a successful check-in.
// The HTTP server must request client certificates and supply the unmodified
// net/http TLS state. Forwarded certificates and proxy identity headers are not
// authentication. A session operation must use authorizeManagementDevice and
// checkManagementDeviceTime inside its own transaction instead of this snapshot.
func (s *Store) AuthenticateManagementDevice(r *http.Request, options EnrollmentOptions) (*ManagementDeviceIdentity, error) {
	certificate, err := managementPeerCertificate(r, options)
	if err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	device, err := s.authorizeManagementDevice(r.Context(), tx, certificate, options)
	if err != nil {
		return nil, err
	}
	if err := checkManagementDeviceTime(r.Context(), tx, device); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &device.identity, nil
}

func managementPeerCertificate(r *http.Request, options EnrollmentOptions) (*x509.Certificate, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	u, _ := enrollmentEndpoint(options.ManagementURL)
	if r == nil || r.Method != http.MethodPost || r.URL == nil || r.URL.RawPath != "" || r.URL.Path != u.Path || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.User != nil || r.URL.Opaque != "" || (r.URL.Scheme != "" && r.URL.Scheme != "https") || (r.URL.Host != "" && r.URL.Host != r.Host) || !sameEnrollmentEndpoint("https://"+r.Host+u.Path, options.ManagementURL) {
		return nil, ErrManagementIdentity
	}
	state := r.TLS
	if state == nil || !state.HandshakeComplete || (state.Version != tls.VersionTLS12 && state.Version != tls.VersionTLS13) || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 8 || state.PeerCertificates[0] == nil {
		return nil, ErrManagementIdentity
	}
	// Reparse the actual leaf bytes. Subject fields, later chain elements and
	// VerifiedChains supplied by middleware cannot substitute another identity.
	der := state.PeerCertificates[0].Raw
	if len(der) == 0 || len(der) > MaxEnrollmentCSRBytes {
		return nil, ErrManagementIdentity
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil || certificate.IsCA {
		return nil, ErrManagementIdentity
	}
	return certificate, nil
}

// Acquire the live scope before device/certificate locks, then hold all of them
// through the caller's transaction. Never derive scope from a subject or hint.
func (s *Store) authorizeManagementDevice(ctx context.Context, tx *sql.Tx, certificate *x509.Certificate, options EnrollmentOptions) (*managementDevice, error) {
	if certificate == nil || len(certificate.Raw) == 0 || len(certificate.Raw) > MaxEnrollmentCSRBytes || options.validate() != nil {
		return nil, ErrManagementIdentity
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	var scope access.Scope
	err := tx.QueryRowContext(ctx, `SELECT tenant_id,site_id FROM mdm_windows_device_certificates WHERE fingerprint=$1`, fingerprint[:]).Scan(&scope.TenantID, &scope.SiteID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagementIdentity
	}
	if err != nil {
		return nil, err
	}
	if err := lockEnrollmentScope(ctx, tx, scope); err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvitation) {
			return nil, ErrManagementIdentity
		}
		return nil, err
	}
	device := &managementDevice{identity: ManagementDeviceIdentity{Scope: scope}}
	i := &device.identity
	var der, publicFingerprint, serial, configDigest []byte
	err = tx.QueryRowContext(ctx, `SELECT d.id,c.id,c.authority_id,d.enrollment_type,c.certificate,c.public_key_fingerprint,c.serial,c.expires_at,d.created_at,c.issued_at,e.configuration_digest
		FROM mdm_windows_device_certificates c
		JOIN mdm_windows_devices d ON d.id=c.device_id AND d.tenant_id=c.tenant_id AND d.site_id=c.site_id
		JOIN mdm_windows_enrollments e ON e.device_id=d.id AND e.invitation_id=d.invitation_id AND e.certificate_id=c.id AND e.tenant_id=d.tenant_id AND e.site_id=d.site_id
		WHERE c.fingerprint=$1 AND c.tenant_id=$2 AND c.site_id=$3 AND c.revoked_at IS NULL AND d.revoked_at IS NULL
		FOR SHARE OF c,d,e`, fingerprint[:], scope.TenantID, scope.SiteID).Scan(&i.DeviceID, &i.CertificateID, &i.AuthorityID, &i.EnrollmentType, &der, &publicFingerprint, &serial, &i.CertificateExpiry, &device.deviceCreated, &device.issued, &configDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagementIdentity
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(der, certificate.Raw) || !hmac.Equal(configDigest, enrollmentConfigurationDigest(options)) {
		return nil, ErrManagementIdentity
	}
	// Reparse here too: this transaction helper must not trust caller-mutated
	// x509 fields when it is reused by the SyncML session service.
	device.certificate, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrManagementIdentity
	}
	a, err := scanAuthority(tx.QueryRowContext(ctx, `SELECT `+authorityColumns+` FROM mdm_windows_authorities WHERE id=$1 AND tenant_id=$2 FOR SHARE`, i.AuthorityID, i.TenantID))
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrAuthority) {
		return nil, ErrManagementIdentity
	}
	if err != nil {
		return nil, err
	}
	device.root, err = parseAuthorityCertificate(*a)
	if err != nil {
		return nil, ErrManagementIdentity
	}
	device.caCreated = a.CreatedAt
	i.FingerprintSHA256 = hex.EncodeToString(fingerprint[:])
	if err := validateManagementCertificate(device, *a, publicFingerprint, serial); err != nil {
		return nil, err
	}
	if err := checkManagementDeviceTime(ctx, tx, device); err != nil {
		return nil, err
	}
	return device, nil
}

func validateManagementCertificate(device *managementDevice, a EnrollmentAuthority, publicFingerprint, serial []byte) error {
	i, c, root := device.identity, device.certificate, device.root
	if !canonicalInvitationID(i.DeviceID) || !canonicalInvitationID(i.CertificateID) || i.AuthorityID != a.ID || i.TenantID != a.TenantID || i.SiteID <= 0 || (i.EnrollmentType != "Full" && i.EnrollmentType != "Device") {
		return ErrManagementIdentity
	}
	public, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok || public.E != 65537 || public.N.BitLen() < a.MinimumKeyBits || public.N.BitLen() > 4096 || c.SignatureAlgorithm != x509.SHA256WithRSA || c.CheckSignatureFrom(root) != nil || !bytes.Equal(c.RawIssuer, root.RawSubject) {
		return ErrManagementIdentity
	}
	hash := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	if !hmac.Equal(hash[:], publicFingerprint) || !bytes.Equal(c.SubjectKeyId, hash[:20]) || !bytes.Equal(c.AuthorityKeyId, root.SubjectKeyId) || c.SerialNumber.Sign() <= 0 || !bytes.Equal(c.SerialNumber.Bytes(), serial) || !c.NotAfter.Equal(i.CertificateExpiry) {
		return ErrManagementIdentity
	}
	units := slices.Clone(c.Subject.OrganizationalUnit)
	slices.Sort(units)
	wantUnits := []string{fmt.Sprintf("Organization %d", i.TenantID), fmt.Sprintf("Site %d", i.SiteID)}
	if c.Subject.CommonName != "OpenUEM Windows "+i.DeviceID || !slices.Equal(c.Subject.Organization, []string{a.Organization}) || !slices.Equal(units, wantUnits) || len(c.URIs) != 1 || c.URIs[0].String() != "urn:openuem:windows:device:"+i.DeviceID || len(c.DNSNames) != 0 || len(c.EmailAddresses) != 0 || len(c.IPAddresses) != 0 {
		return ErrManagementIdentity
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(c.UnknownExtKeyUsage) != 0 || len(c.UnhandledCriticalExtensions) != 0 {
		return ErrManagementIdentity
	}
	return nil
}

// Recheck after any command/audit/session lock waits, immediately before commit.
// Revocation and scope rows remain locked; time itself cannot be locked.
func checkManagementDeviceTime(ctx context.Context, tx *sql.Tx, device *managementDevice) error {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if device.deviceCreated.After(now) || device.issued.After(now) || device.caCreated.After(now) || device.certificate.NotBefore.After(now) || !device.certificate.NotAfter.After(now) || device.root.NotBefore.After(now) || !device.root.NotAfter.After(now) {
		return ErrManagementIdentity
	}
	// This is a private organization root pool. Host trust stores, caller-provided
	// intermediates and proxy VerifiedChains cannot broaden the accepted issuer.
	roots := x509.NewCertPool()
	roots.AddCert(device.root)
	_, err := device.certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return ErrManagementIdentity
	}
	return nil
}
