package apple

// Legacy PKCS#12 fixture for compatibility and gateway identity tests. New
// enrollment profiles never generate a private device key on the server.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
	"testing"
	"time"
)

func TestLegacyPKCS12EnrollmentSurvivesSCEPMigration(t *testing.T) {
	s := testStore(t)
	c := testSettings(t, s, 1)
	ctx := context.Background()
	invite, err := s.Invite(ctx, Scope{TenantID: 1, SiteID: 1}, "Legacy device", "admin")
	if err != nil {
		t.Fatal(err)
	}
	profile, fingerprint, err := identityProfile(c, invite.DeviceID, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	browser, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	box, err := enrollmentRetryBox(browser)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := box.seal(profile, secretPurpose(1, invite.DeviceID, "enrollment_retry"))
	if err != nil {
		t.Fatal(err)
	}
	copy, err = s.secrets.seal(copy, secretPurpose(1, invite.DeviceID, "enrollment_retry"))
	if err != nil {
		t.Fatal(err)
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	if _, err = s.db.Exec(`UPDATE mdm_apple_devices SET status='authenticating',certificate_fingerprint=$2,invite_hash=NULL WHERE id=$1`, invite.DeviceID, fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO mdm_apple_enrollment_claims(device_id,invite_hash,browser_hash,profile) VALUES($1,$2,$3,$4)`, invite.DeviceID, digest([]byte(token)), digest([]byte(browser)), copy); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	download, err := s.DownloadEnrollment(ctx, token, browser)
	if err != nil || !bytes.Equal(download, profile) {
		t.Fatal("legacy retry profile changed", err)
	}
	var root map[string]any
	if _, err = plist.Unmarshal(profile, &root); err != nil {
		t.Fatal(err)
	}
	identity := root["PayloadContent"].([]any)[0].(map[string]any)
	_, cert, _, err := pkcs12.DecodeChain(identity["PayloadContent"].([]byte), identity["Password"].(string))
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.AuthenticateCertificate(ctx, invite.DeviceID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckIn(ctx, d, map[string]any{"MessageType": "Authenticate", "UDID": "legacy-device", "Topic": c.Topic, "ProductName": "iPhone16,1"}); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckIn(ctx, d, map[string]any{"MessageType": "TokenUpdate", "UDID": "legacy-device", "Topic": c.Topic, "Token": []byte("token"), "PushMagic": "magic"}); err != nil {
		t.Fatal(err)
	}
	d, err = s.AuthenticateCertificate(ctx, d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	testIdentityDue(t, s, d)
	if err = s.ScheduleIdentityRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	var renewalError string
	if err = s.db.QueryRow(`SELECT identity_renewal_error FROM mdm_apple_devices WHERE id=$1`, d.ID).Scan(&renewalError); err != nil || renewalError != "profile_inventory_required" {
		t.Fatal("legacy enrollment guessed unknown profile UUIDs", renewalError, err)
	}
	reported := InstalledProfile{Identifier: root["PayloadIdentifier"].(string), UUID: root["PayloadUUID"].(string)}
	for _, value := range root["PayloadContent"].([]any) {
		payload := value.(map[string]any)
		reported.Payloads = append(reported.Payloads, InstalledPayload{Identifier: payload["PayloadIdentifier"].(string), UUID: payload["PayloadUUID"].(string), Type: payload["PayloadType"].(string)})
	}
	drainCommands(t, s, d, []InstalledProfile{reported})
	if err = s.ScheduleIdentityRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	renewal := testIdentityGeneration(t, s, d)
	replacement := testIdentityDelivery(t, s, d, renewal)
	var next map[string]any
	if _, err = plist.Unmarshal(replacement, &next); err != nil {
		t.Fatal(err)
	}
	oldMDM := root["PayloadContent"].([]any)[1].(map[string]any)
	newMDM := next["PayloadContent"].([]any)[2].(map[string]any)
	if next["PayloadUUID"] != root["PayloadUUID"] || newMDM["PayloadUUID"] != oldMDM["PayloadUUID"] {
		t.Fatal("legacy migration replaced immutable profile metadata")
	}
	a, err := s.scepRenewalAuthority(ctx, d.ID, renewal.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	f, csr := testSCEPDeviceRequest(t, d.ID, testSCEPProfile(t, replacement)["Challenge"].(string), a.ca, a.ra)
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	candidate, newCert := testIdentityIssue(t, s, a, f, request)
	testIdentityPin(t, s, d, cert, "token")
	testIdentityToken(t, s, candidate)
	if _, err = s.Connect(ctx, candidate, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
		t.Fatal(err)
	}
	testIdentityPin(t, s, d, newCert, "renewed-push-token")
	if err = s.RevokeEnrollment(ctx, Scope{TenantID: 1, SiteID: 1}, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthenticateCertificate(ctx, d.ID, cert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("legacy revocation bypassed", err)
	}
	if _, err = s.AuthenticateCertificate(ctx, d.ID, newCert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("migrated identity bypassed revocation", err)
	}
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
