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
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
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
	uid := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(uid) {
			if topic, ok := name.Value.(string); ok && strings.HasPrefix(topic, "com.apple.mgmt.") {
				return topic
			}
		}
	}
	return ""
}

// Configure creates or renews APNs credentials. A renewal cannot silently change
// the push topic or enrollment CA and strand existing devices.
func (s *Store) Configure(ctx context.Context, c Settings, actor string) error {
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
	pair, err := tls.X509KeyPair(c.PushCertificate, c.PushKey)
	if err != nil {
		return fmt.Errorf("invalid APNs certificate/key pair: %w", err)
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
	var oldTopic, oldURL string
	var oldCA, oldKey []byte
	err = tx.QueryRowContext(ctx, `SELECT topic,public_url,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1 FOR UPDATE`, c.TenantID).Scan(&oldTopic, &oldURL, &oldCA, &oldKey)
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
	pushKey, err := s.secrets.seal(c.PushKey, secretPurpose(c.TenantID, "settings", "push_key"))
	if err != nil {
		return err
	}
	caKey, err := s.secrets.seal(c.CAKey, secretPurpose(c.TenantID, "settings", "ca_key"))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_settings(tenant_id,public_url,organization,topic,push_expires_at,push_certificate,push_key,ca_certificate,ca_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id) DO UPDATE SET public_url=excluded.public_url,organization=excluded.organization,push_expires_at=excluded.push_expires_at,push_certificate=excluded.push_certificate,push_key=excluded.push_key,updated_at=now()`, c.TenantID, c.PublicURL, c.Organization, c.Topic, c.PushExpiresAt, c.PushCertificate, pushKey, c.CACertificate, caKey)
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, c.TenantID, actor, "apple.settings.save", fmt.Sprint(c.TenantID)); err != nil {
		return err
	}
	return tx.Commit()
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

func identityProfile(c *Settings, id string, expires time.Time) ([]byte, string, error) {
	caBlock, _ := pem.Decode(c.CACertificate)
	if caBlock == nil {
		return nil, "", errors.New("invalid enrollment CA")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, "", err
	}
	keyBlock, _ := pem.Decode(c.CAKey)
	if keyBlock == nil {
		return nil, "", errors.New("invalid enrollment CA key")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	serial, err := certificateSerial()
	if err != nil {
		return nil, "", err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: id, Organization: []string{c.Organization}}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", err
	}
	password, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	p12, err := pkcs12.Modern.Encode(key, cert, []*x509.Certificate{ca}, password)
	if err != nil {
		return nil, "", err
	}
	identityID := uuid.NewString()
	prefix := "eu.openuem.enrollment." + id
	identity := map[string]any{"PayloadType": "com.apple.security.pkcs12", "PayloadVersion": 1, "PayloadIdentifier": prefix + ".identity", "PayloadUUID": identityID, "PayloadDisplayName": "OpenUEM device identity", "PayloadContent": p12, "Password": password}
	mdm := map[string]any{"PayloadType": "com.apple.mdm", "PayloadVersion": 1, "PayloadIdentifier": prefix + ".mdm", "PayloadUUID": uuid.NewString(), "PayloadDisplayName": "OpenUEM management", "IdentityCertificateUUID": identityID, "Topic": c.Topic, "ServerURL": c.PublicURL + "/mdm/apple/" + id + "/connect", "CheckInURL": c.PublicURL + "/mdm/apple/" + id + "/checkin", "CheckOutWhenRemoved": true, "SignMessage": false, "AccessRights": 1 | 2 | 16 | 256 | 512 | 1024 | 2048 | 4096}
	profile := map[string]any{"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": prefix, "PayloadUUID": uuid.NewString(), "PayloadDisplayName": c.Organization + " – OpenUEM", "PayloadOrganization": c.Organization, "PayloadDescription": "Manage this device's configuration, software updates, and inventory with OpenUEM.", "PayloadScope": "System", "PayloadContent": []any{identity, mdm}}
	data, err := plist.Marshal(profile, plist.XMLFormat)
	return data, digest(der), err
}

// EnrollmentProfile atomically consumes an invitation and returns a unique
// identity profile once. The private device key is never persisted on the server.
func (s *Store) EnrollmentProfile(ctx context.Context, token string) ([]byte, error) {
	if len(token) != 43 {
		return nil, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id string
	var tenant int
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT id,tenant_id,certificate_expires_at FROM mdm_apple_devices WHERE invite_hash=$1 AND invite_expires_at>now() AND status='pending' FOR UPDATE`, digest([]byte(token))).Scan(&id, &tenant, &expires)
	if err != nil {
		return nil, notFound(err)
	}
	// Serialize identity issuance with settings renewal/origin changes. Once a
	// profile has been issued, Configure must observe an active enrollment.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902,$1::integer)`, tenant); err != nil {
		return nil, err
	}
	c, err := s.Settings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	data, fingerprint, err := identityProfile(c, id, expires)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET certificate_fingerprint=$1,invite_hash=NULL,status='authenticating' WHERE id=$2`, fingerprint, id)
	if err != nil {
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
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND certificate_fingerprint=$2 AND certificate_expires_at>now() AND status IN ('authenticating','enrolled')`, id, digest(cert.Raw)))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	// Pinning the exact individually issued certificate is stronger than merely
	// trusting any certificate from the organization's CA.
	return d, nil
}
