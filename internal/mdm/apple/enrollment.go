package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

func certificateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func generateCA(organization string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	serial, err := certificateSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM Apple Device CA", Organization: []string{organization}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func PushTopic(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	uid := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	var topic string
	count := 0
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(uid) {
			count++
			topic, _ = name.Value.(string)
		}
	}
	if count != 1 || !strings.HasPrefix(topic, "com.apple.mgmt.") || len(topic) <= len("com.apple.mgmt.") || len(topic) > 255 {
		return ""
	}
	for _, c := range topic {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return ""
		}
	}
	return topic
}

func validatePushOrganization(c *Settings) error {
	if c.TenantID <= 0 {
		return errors.New("organization is required")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("public MDM URL must be an HTTPS origin without a path, query or credentials")
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.Organization == "" || len(c.Organization) > 255 {
		return errors.New("organization name is required")
	}
	return nil
}

func (s *Store) validatePushSettings(c *Settings) error {
	if err := validatePushOrganization(c); err != nil {
		return err
	}
	verified, err := s.pushTrust.verify(c.PushCertificate, time.Now())
	if err != nil {
		return err
	}
	c.PushCertificate = verified
	pair, err := tls.X509KeyPair(c.PushCertificate, c.PushKey)
	if err != nil {
		return errors.New("invalid APNs certificate/key pair")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	c.Topic = PushTopic(cert)
	if c.Topic == "" {
		return errors.New("certificate does not contain an Apple MDM push topic")
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return errors.New("APNs certificate is not currently valid")
	}
	c.PushExpiresAt = cert.NotAfter
	return nil
}

// Configure creates or renews APNs credentials without changing an existing
// topic or enrollment CA. A successful replacement supersedes pending requests.
func (s *Store) Configure(ctx context.Context, c Settings, actor string) error {
	if err := s.validatePushSettings(&c); err != nil {
		return err
	}
	// Serializing setup also prevents concurrent initializations from creating
	// different CAs. Private CA material is never returned through the web API.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902,$1::integer)`, c.TenantID); err != nil {
		return err
	}
	if err = s.configurePushTx(ctx, tx, c, actor, false); err != nil {
		return err
	}
	return tx.Commit()
}

// The caller holds the organization setup lock. Request import and the legacy
// pair import share one atomic replacement and invalidate all other pending keys.
func (s *Store) configurePushTx(ctx context.Context, tx *sql.Tx, c Settings, actor string, accountConfirmed bool) error {
	var oldTopic, oldURL string
	var oldCA, oldKey []byte
	err := tx.QueryRowContext(ctx, `SELECT topic,public_url,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1 FOR UPDATE`, c.TenantID).Scan(&oldTopic, &oldURL, &oldCA, &oldKey)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if oldTopic != c.Topic {
			return errors.New("APNs renewal must preserve the existing push topic")
		}
		if oldURL != c.PublicURL {
			var active bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_devices WHERE tenant_id=$1 AND status IN ('authenticating','enrolled'))`, c.TenantID).Scan(&active); err != nil {
				return err
			}
			if active {
				return errors.New("the public MDM URL cannot change while enrolled devices use it")
			}
		}
		c.CACertificate = oldCA
		c.CAKey, err = s.secrets.open(oldKey, secretPurpose(c.TenantID, "settings", "ca_key"))
		if err != nil {
			return err
		}
	} else {
		c.CACertificate, c.CAKey, err = generateCA(c.Organization)
		if err != nil {
			return err
		}
	}
	// CA generation and lock waits can outlast a credential's remaining validity.
	if _, err = s.pushTrust.verify(c.PushCertificate, time.Now()); err != nil {
		return err
	}
	if s.checkPushConnection == nil || s.checkPushConnection(ctx, &c) != nil {
		return ErrPushConnection
	}
	// Check validity again after the network operation, before activation.
	if _, err = s.pushTrust.verify(c.PushCertificate, time.Now()); err != nil {
		return err
	}
	leaf, _ := pem.Decode(c.PushCertificate)
	fingerprint := digest(leaf.Bytes)
	pushKey, err := s.secrets.seal(c.PushKey, secretPurpose(c.TenantID, "settings", "push_key"))
	if err != nil {
		return err
	}
	caKey, err := s.secrets.seal(c.CAKey, secretPurpose(c.TenantID, "settings", "ca_key"))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_settings(tenant_id,public_url,organization,topic,push_expires_at,push_certificate,push_key,ca_certificate,ca_key,apple_account) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id) DO UPDATE SET public_url=excluded.public_url,organization=excluded.organization,push_expires_at=excluded.push_expires_at,push_certificate=excluded.push_certificate,push_key=excluded.push_key,push_revision=mdm_apple_settings.push_revision+1,apple_account=CASE WHEN $11 THEN excluded.apple_account ELSE mdm_apple_settings.apple_account END,updated_at=now()`, c.TenantID, c.PublicURL, c.Organization, c.Topic, c.PushExpiresAt, c.PushCertificate, pushKey, c.CACertificate, caKey, c.AppleAccount, accountConfirmed)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_settings SET push_checked_at=clock_timestamp(),push_fingerprint=$2 WHERE tenant_id=$1`, c.TenantID, fingerprint); err != nil {
		return err
	}
	if err = audit(ctx, tx, c.TenantID, actor, "apple.push_connection.verify", fingerprint); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `WITH superseded AS (UPDATE mdm_apple_push_requests SET status='superseded',encrypted_key=NULL,completed_at=clock_timestamp() WHERE tenant_id=$1 AND status='pending' RETURNING id) INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id) SELECT $1,$2,'apple.push_request.supersede',id::text FROM superseded`, c.TenantID, actor); err != nil {
		return err
	}
	if err = audit(ctx, tx, c.TenantID, actor, "apple.settings.save", fmt.Sprint(c.TenantID)); err != nil {
		return err
	}
	return nil
}

type Invitation struct {
	DeviceID  string    `json:"device_id"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Store) Invite(ctx context.Context, scope Scope, name, actor string) (*Invitation, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if scope.SiteID == 0 {
		return nil, errors.New("select a site before enrolling a device")
	}
	if len(name) > 255 {
		return nil, errors.New("device name is too long")
	}
	c, err := s.Settings(ctx, scope.TenantID)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(c.PushExpiresAt) {
		return nil, errors.New("renew the expired APNs certificate before enrollment")
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	expires := time.Now().Add(time.Hour)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var siteID int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR KEY SHARE`, scope.SiteID, scope.TenantID).Scan(&siteID); err != nil {
		return nil, notFound(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_devices(id,tenant_id,site_id,name,invite_hash,invite_expires_at,certificate_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, scope.TenantID, siteID, name, digest([]byte(token)), expires, time.Now().AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.enrollment.invite", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &Invitation{DeviceID: id, URL: c.PublicURL + "/mdm/apple/enroll/" + token, ExpiresAt: expires}, nil
}

// EnrollmentProfile atomically consumes an invitation and returns a unique
// SCEP enrollment profile once. Its private device key is generated by the device.
func (s *Store) EnrollmentProfile(ctx context.Context, token string) ([]byte, error) {
	return s.issueEnrollmentProfile(ctx, token, "")
}

func (s *Store) issueEnrollmentProfile(ctx context.Context, token, browser string) ([]byte, error) {
	if !validEnrollmentToken(token) || (browser != "" && !validEnrollmentToken(browser)) {
		return nil, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id string
	var tenant int
	var invitationExpiry time.Time
	err = tx.QueryRowContext(ctx, `SELECT id,tenant_id,invite_expires_at FROM mdm_apple_devices WHERE invite_hash=$1 AND invite_expires_at>clock_timestamp() AND status='pending' FOR UPDATE`, digest([]byte(token))).Scan(&id, &tenant, &invitationExpiry)
	if err != nil {
		return nil, notFound(err)
	}
	// Serialize identity issuance with settings renewal/origin changes. Once a
	// profile has been issued, Configure must observe an active enrollment.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902,$1::integer)`, tenant); err != nil {
		return nil, err
	}
	if !time.Now().Before(invitationExpiry) {
		return nil, ErrNotFound
	}
	c := &Settings{TenantID: tenant}
	if err = tx.QueryRowContext(ctx, `SELECT public_url,organization,topic,push_expires_at,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&c.PublicURL, &c.Organization, &c.Topic, &c.PushExpiresAt, &c.CACertificate, &c.CAKey); err != nil {
		return nil, err
	}
	c.CAKey, err = s.secrets.open(c.CAKey, secretPurpose(tenant, "settings", "ca_key"))
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(c.PushExpiresAt) {
		return nil, ErrConflict
	}
	data, err := s.prepareSCEPEnrollment(ctx, tx, c, id)
	if err != nil {
		return nil, err
	}
	// Lock waits or initial RA key generation must not turn an expired browser
	// invitation or APNs credential into a fresh SCEP authorization.
	if !time.Now().Before(invitationExpiry) || !time.Now().Before(c.PushExpiresAt) {
		return nil, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET invite_hash=NULL,status='authenticating' WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	if browser != "" {
		box, err := enrollmentRetryBox(browser)
		if err != nil {
			return nil, err
		}
		encrypted, err := box.seal(data, secretPurpose(tenant, id, "enrollment_retry"))
		if err != nil {
			return nil, err
		}
		encrypted, err = s.secrets.seal(encrypted, secretPurpose(tenant, id, "enrollment_retry"))
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_enrollment_claims(device_id,invite_hash,browser_hash,profile) VALUES($1,$2,$3,$4)`, id, digest([]byte(token)), digest([]byte(browser)), encrypted); err != nil {
			return nil, err
		}
	}
	if err = audit(ctx, tx, tenant, "enrollment-browser", "apple.enrollment.claim", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *Store) AuthenticateCertificate(ctx context.Context, id string, cert *x509.Certificate) (*Device, error) {
	if cert == nil || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return nil, ErrUnauthorized
	}
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND status IN ('authenticating','enrolled') AND ((certificate_fingerprint=$2 AND certificate_expires_at>clock_timestamp()) OR (status='enrolled' AND EXISTS(SELECT 1 FROM mdm_apple_identity_renewals r WHERE r.device_id=mdm_apple_devices.id AND r.status='issued' AND r.base_fingerprint=mdm_apple_devices.certificate_fingerprint AND r.certificate_fingerprint=$2 AND r.certificate_expires_at>clock_timestamp())) OR (status='enrolled' AND EXISTS(SELECT 1 FROM mdm_apple_identity_renewals r WHERE r.device_id=mdm_apple_devices.id AND r.status='confirmed' AND r.certificate_fingerprint=mdm_apple_devices.certificate_fingerprint AND r.base_fingerprint=$2 AND r.grace_until>clock_timestamp() AND r.base_expires_at>clock_timestamp())))`, id, digest(cert.Raw)))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	d.peerFingerprint, d.peerExpiresAt = digest(cert.Raw), cert.NotAfter
	// Pinning the exact individually issued certificate is stronger than merely
	// trusting any certificate from the organization's CA.
	return d, nil
}
