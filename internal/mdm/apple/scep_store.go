package apple

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/smallstep/scep"
	"howett.net/plist"
)

var errSCEPAuthority = errors.New("SCEP authority is unavailable")

type scepAuthority struct {
	id, deviceID, renewalID string
	tenant                  int
	ca, ra                  *x509.Certificate
	key                     crypto.PrivateKey
}

func enrollmentCA(c *Settings, now time.Time) (*x509.Certificate, crypto.PrivateKey, error) {
	pair, err := tls.X509KeyPair(c.CACertificate, c.CAKey)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, nil, errSCEPAuthority
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(ca.NotBefore) || !now.Add(24*time.Hour).Before(ca.NotAfter) {
		return nil, nil, errSCEPAuthority
	}
	return ca, pair.PrivateKey, nil
}

func validateSCEPAuthority(caDER, raDER []byte, now time.Time) (*x509.Certificate, *x509.Certificate, error) {
	ca, err := x509.ParseCertificate(caDER)
	if err != nil || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return nil, nil, errSCEPAuthority
	}
	ra, err := x509.ParseCertificate(raDER)
	if err != nil || ra.IsCA || !scepRSA(ra.PublicKey) || now.Before(ra.NotBefore) || !now.Before(ra.NotAfter) || ra.NotAfter.After(ca.NotAfter) || ra.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment || ra.CheckSignatureFrom(ca) != nil {
		return nil, nil, errSCEPAuthority
	}
	return ca, ra, nil
}

// The caller holds both the device row and organization setup lock. No public
// GetCACert request can create a key or replace an authority under an enrollment.
func (s *Store) ensureSCEPAuthority(ctx context.Context, tx *sql.Tx, c *Settings) (*scepAuthority, error) {
	now := time.Now()
	ca, caKey, err := enrollmentCA(c, now)
	if err != nil {
		return nil, err
	}
	var authorityID string
	var authorityDER []byte
	err = tx.QueryRowContext(ctx, `SELECT id,certificate FROM mdm_apple_scep_authorities WHERE tenant_id=$1 AND expires_at>clock_timestamp()+interval '30 days' ORDER BY expires_at DESC,id LIMIT 1`, c.TenantID).Scan(&authorityID, &authorityDER)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		serial, err := certificateSerial()
		if err != nil {
			return nil, err
		}
		expires := now.AddDate(5, 0, 0)
		if ca.NotAfter.Before(expires) {
			expires = ca.NotAfter
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM Apple SCEP RA", Organization: []string{c.Organization}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
		authorityDER, err = x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		authorityID = uuid.NewString()
		encrypted, err := s.secrets.seal(keyDER, secretPurpose(c.TenantID, authorityID, "scep_ra_key"))
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_scep_authorities(id,tenant_id,certificate,encrypted_key,expires_at) VALUES($1,$2,$3,$4,$5)`, authorityID, c.TenantID, authorityDER, encrypted, expires); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, c.TenantID, "enrollment-service", "apple.scep.authority.create", authorityID); err != nil {
			return nil, err
		}
	}
	_, ra, err := validateSCEPAuthority(ca.Raw, authorityDER, now)
	if err != nil {
		return nil, err
	}
	return &scepAuthority{id: authorityID, tenant: c.TenantID, ca: ca, ra: ra}, nil
}

func (s *Store) prepareSCEPEnrollment(ctx context.Context, tx *sql.Tx, c *Settings, deviceID string) ([]byte, error) {
	authority, err := s.ensureSCEPAuthority(ctx, tx, c)
	if err != nil {
		return nil, err
	}
	challenge, err := randomToken()
	if err != nil {
		return nil, err
	}
	// This window starts at browser claim, independently of the invitation's
	// remaining lifetime. It never renews on download or a SCEP retry.
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_scep_enrollments(device_id,tenant_id,authority_id,challenge_hash,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '1 hour')`, deviceID, c.TenantID, authority.id, digest([]byte(challenge))); err != nil {
		return nil, err
	}
	layout := newEnrollmentLayout(c)
	data, err := scepEnrollmentProfile(c, deviceID, challenge, "/mdm/apple/"+deviceID+"/scep", layout)
	if err != nil {
		return nil, err
	}
	if err = saveEnrollmentLayout(ctx, tx, c.TenantID, deviceID, layout); err != nil {
		return nil, err
	}
	return data, nil
}

func scepEnrollmentProfile(c *Settings, deviceID, challenge, endpoint string, layout enrollmentLayout) ([]byte, error) {
	if err := layout.validate(); err != nil {
		return nil, err
	}
	if layout.publicURL != c.PublicURL || layout.topic != c.Topic {
		return nil, ErrConflict
	}
	if err := validatePushOrganization(c); err != nil {
		return nil, err
	}
	caBlock, _ := pem.Decode(c.CACertificate)
	if caBlock == nil {
		return nil, errSCEPAuthority
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return nil, errSCEPAuthority
	}
	prefix := "eu.openuem.enrollment." + deviceID
	identityID := layout.identityUUID
	// The device also needs the issuing CA in its trust anchors for SCEP. This
	// public certificate is installed with the enrollment; it contains no key.
	trust := map[string]any{"PayloadType": "com.apple.security.root", "PayloadVersion": 1, "PayloadIdentifier": prefix + ".ca", "PayloadUUID": layout.caUUID, "PayloadDisplayName": "OpenUEM enrollment authority", "PayloadContent": ca.Raw}
	// HTTPS authenticates GetCACert and capabilities. Apple's documented legacy
	// fingerprint field supports SHA-1/MD5; do not invent a SHA-256 interpretation
	// or weaken CMS signatures to support those hashes.
	content := map[string]any{"URL": c.PublicURL + endpoint, "Challenge": challenge, "Key Type": "RSA", "Keysize": 2048, "Key Usage": 5, "KeyIsExtractable": false, "AllowAllAppsAccess": false, "Subject": []any{[]any{[]any{"CN", deviceID}}}}
	identity := map[string]any{"PayloadType": "com.apple.security.scep", "PayloadVersion": 1, "PayloadIdentifier": prefix + ".identity", "PayloadUUID": identityID, "PayloadDisplayName": "OpenUEM device identity", "PayloadContent": content}
	mdm := map[string]any{"PayloadType": "com.apple.mdm", "PayloadVersion": 1, "PayloadIdentifier": prefix + ".mdm", "PayloadUUID": layout.mdmUUID, "PayloadDisplayName": "OpenUEM management", "IdentityCertificateUUID": identityID, "Topic": c.Topic, "ServerURL": c.PublicURL + "/mdm/apple/" + deviceID + "/connect", "CheckInURL": c.PublicURL + "/mdm/apple/" + deviceID + "/checkin", "CheckOutWhenRemoved": true, "SignMessage": false, "AccessRights": layout.accessRights}
	profile := map[string]any{"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": prefix, "PayloadUUID": layout.profileUUID, "PayloadDisplayName": c.Organization + " – OpenUEM", "PayloadOrganization": c.Organization, "PayloadDescription": "Manage this device's configuration, software updates, and inventory with OpenUEM.", "PayloadScope": "System", "PayloadContent": []any{trust, identity, mdm}}
	return plist.Marshal(profile, plist.XMLFormat)
}

// Read eligibility before private-key operations. Public discovery never reads
// or decrypts either the APNs key, the issuing CA key, or the RA key.
func (s *Store) scepEnrollmentAuthority(ctx context.Context, deviceID string, private bool) (*scepAuthority, error) {
	var a scepAuthority
	var caPEM, raDER []byte
	err := s.db.QueryRowContext(ctx, `SELECT e.authority_id,e.tenant_id,c.ca_certificate,a.certificate FROM mdm_apple_scep_enrollments e JOIN mdm_apple_devices d ON d.id=e.device_id AND d.tenant_id=e.tenant_id JOIN mdm_apple_settings c ON c.tenant_id=e.tenant_id JOIN mdm_apple_scep_authorities a ON a.id=e.authority_id AND a.tenant_id=e.tenant_id WHERE e.device_id=$1 AND d.status='authenticating' AND d.udid IS NULL AND e.expires_at>clock_timestamp()`, deviceID).Scan(&a.id, &a.tenant, &caPEM, &raDER)
	if err != nil {
		return nil, notFound(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, errSCEPAuthority
	}
	a.deviceID = deviceID
	a.ca, a.ra, err = validateSCEPAuthority(caBlock.Bytes, raDER, time.Now())
	if err != nil {
		return nil, err
	}
	if private {
		if err = s.loadSCEPAuthorityKey(ctx, &a); err != nil {
			return nil, err
		}
	}
	return &a, nil
}

func (s *Store) loadSCEPAuthorityKey(ctx context.Context, a *scepAuthority) error {
	var err error
	var encrypted []byte
	if err = s.db.QueryRowContext(ctx, `SELECT encrypted_key FROM mdm_apple_scep_authorities WHERE id=$1 AND tenant_id=$2`, a.id, a.tenant).Scan(&encrypted); err != nil {
		return err
	}
	keyDER, err := s.secrets.open(encrypted, secretPurpose(a.tenant, a.id, "scep_ra_key"))
	if err != nil {
		return errSCEPAuthority
	}
	a.key, err = x509.ParsePKCS8PrivateKey(keyDER)
	signer, ok := a.key.(crypto.Signer)
	if err != nil || !ok {
		return errSCEPAuthority
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(publicDER, a.ra.RawSubjectPublicKeyInfo) {
		return errSCEPAuthority
	}
	return nil
}

func (s *Store) scepEnroll(ctx context.Context, a *scepAuthority, request *scepRequest) ([]byte, error) {
	// Current enrollment authorizes only an initial, one-time PKCSReq. Parsing a
	// RenewalReq does not grant it authority to renew an existing device.
	if request.message.MessageType != scep.PKCSReq || request.csr.Subject.CommonName != a.deviceID {
		return request.response(a.ra, a.key, a.ca, nil, scep.BadRequest)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var deviceExpiry time.Time
	var fingerprint string
	err = tx.QueryRowContext(ctx, `SELECT certificate_expires_at,COALESCE(certificate_fingerprint,'') FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND status='authenticating' AND udid IS NULL FOR UPDATE`, a.deviceID, a.tenant).Scan(&deviceExpiry, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return request.response(a.ra, a.key, a.ca, nil, scep.BadRequest)
	}
	if err != nil {
		return nil, err
	}
	var challenge, csrHash, signerFingerprint, transaction string
	var certificate []byte
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(challenge_hash,''),COALESCE(csr_hash,''),COALESCE(signer_fingerprint,''),COALESCE(transaction_id,''),certificate,expires_at FROM mdm_apple_scep_enrollments WHERE device_id=$1 AND tenant_id=$2 AND authority_id=$3 FOR UPDATE`, a.deviceID, a.tenant, a.id).Scan(&challenge, &csrHash, &signerFingerprint, &transaction, &certificate, &expires)
	if err != nil {
		return nil, notFound(err)
	}
	now := time.Now()
	if !now.Before(expires) || now.Before(a.ra.NotBefore) || !now.Before(a.ra.NotAfter) || !now.Before(a.ca.NotAfter) {
		return request.response(a.ra, a.key, a.ca, nil, scep.BadRequest)
	}
	var issued *x509.Certificate
	if len(certificate) > 0 {
		// Exact CSR and signer association lets a lost response be retried, without
		// storing the device's private key or issuing a second certificate.
		if csrHash != digest(request.csr.Raw) || signerFingerprint != digest(request.signer.Raw) || transaction != string(request.message.TransactionID) || fingerprint != digest(certificate) {
			return request.response(a.ra, a.key, a.ca, nil, scep.BadRequest)
		}
		issued, err = x509.ParseCertificate(certificate)
		if err != nil || !now.Before(issued.NotAfter) {
			return nil, errSCEPAuthority
		}
	} else {
		if fingerprint != "" || !validEnrollmentToken(request.challenge) || !hmac.Equal([]byte(challenge), []byte(digest([]byte(request.challenge)))) {
			return request.response(a.ra, a.key, a.ca, nil, scep.BadRequest)
		}
		var c Settings
		c.TenantID = a.tenant
		if err = tx.QueryRowContext(ctx, `SELECT organization,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1`, a.tenant).Scan(&c.Organization, &c.CACertificate, &c.CAKey); err != nil {
			return nil, err
		}
		c.CAKey, err = s.secrets.open(c.CAKey, secretPurpose(a.tenant, "settings", "ca_key"))
		if err != nil {
			return nil, errSCEPAuthority
		}
		ca, key, err := enrollmentCA(&c, now)
		if err != nil || !bytes.Equal(ca.Raw, a.ca.Raw) {
			return nil, errSCEPAuthority
		}
		if ca.NotAfter.Before(deviceExpiry) {
			deviceExpiry = ca.NotAfter
		}
		if !now.Add(time.Hour).Before(deviceExpiry) {
			return nil, errSCEPAuthority
		}
		serial, err := certificateSerial()
		if err != nil {
			return nil, err
		}
		// Never copy arbitrary CSR SANs, usages, subjects, or CA privileges. The
		// invitation fixes this individual identity and its organization.
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: a.deviceID, Organization: []string{c.Organization}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: deviceExpiry, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		certificate, err = x509.CreateCertificate(rand.Reader, template, ca, request.csr.PublicKey, key)
		if err != nil {
			return nil, err
		}
		issued, err = x509.ParseCertificate(certificate)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_scep_enrollments SET challenge_hash=NULL,csr_hash=$2,signer_fingerprint=$3,transaction_id=$4,certificate=$5,issued_at=clock_timestamp() WHERE device_id=$1`, a.deviceID, digest(request.csr.Raw), digest(request.signer.Raw), string(request.message.TransactionID), certificate); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET certificate_fingerprint=$2,certificate_expires_at=$3 WHERE id=$1`, a.deviceID, digest(certificate), issued.NotAfter); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, a.tenant, "device:"+a.deviceID, "apple.scep.enrollment.issue", a.deviceID); err != nil {
			return nil, err
		}
	}
	response, err := request.response(a.ra, a.key, a.ca, issued, "")
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}

// CleanupSCEPEnrollments removes unused challenge hashes in bounded batches.
// Status and expiry are checked synchronously too; cleanup is never an access gate.
func (s *Store) CleanupSCEPEnrollments(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `WITH expired AS (SELECT e.device_id FROM mdm_apple_scep_enrollments e JOIN mdm_apple_devices d ON d.id=e.device_id WHERE e.challenge_hash IS NOT NULL AND (e.expires_at<=clock_timestamp() OR d.status<>'authenticating' OR d.udid IS NOT NULL) ORDER BY e.device_id LIMIT 100 FOR UPDATE OF e SKIP LOCKED) UPDATE mdm_apple_scep_enrollments e SET challenge_hash=NULL FROM expired WHERE e.device_id=expired.device_id`)
	return err
}
