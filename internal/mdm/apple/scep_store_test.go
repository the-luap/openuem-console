package apple

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/smallstep/scep"
	scepx509 "github.com/smallstep/scep/x509util"
	"howett.net/plist"
)

func testSCEPProfile(t *testing.T, profile []byte) map[string]any {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(profile, &root); err != nil {
		t.Fatal(err)
	}
	payloads := root["PayloadContent"].([]any)
	if len(payloads) != 3 {
		t.Fatal("enrollment requires CA trust, SCEP identity and MDM payloads")
	}
	trust := payloads[0].(map[string]any)
	if trust["PayloadType"] != "com.apple.security.root" {
		t.Fatal("enrollment CA trust missing before SCEP")
	}
	ca, err := x509.ParseCertificate(trust["PayloadContent"].([]byte))
	if err != nil || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil {
		t.Fatal("enrollment contains an invalid trust anchor", err)
	}
	identity := payloads[1].(map[string]any)
	if identity["PayloadType"] != "com.apple.security.scep" {
		t.Fatal("enrollment must generate its key on the device")
	}
	if _, exists := identity["Password"]; exists {
		t.Fatal("PKCS#12 password in SCEP identity")
	}
	mdm := payloads[2].(map[string]any)
	if mdm["IdentityCertificateUUID"] != identity["PayloadUUID"] {
		t.Fatal("MDM identity is not linked to SCEP")
	}
	content := identity["PayloadContent"].(map[string]any)
	if content["KeyIsExtractable"] != false || content["AllowAllAppsAccess"] != false || numberValue(content["Keysize"]) != 2048 || content["Key Type"] != "RSA" || numberValue(content["Key Usage"]) != 5 {
		t.Fatal("unsafe key generation settings")
	}
	return content
}

func testSCEPDeviceRequest(t *testing.T, deviceID, challenge string, ca, ra *x509.Certificate) (*scepFixture, *x509.CertificateRequest) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := certificateSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: deviceID}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := scepx509.CreateCertificateRequest(rand.Reader, &scepx509.CertificateRequest{CertificateRequest: x509.CertificateRequest{Subject: template.Subject, SignatureAlgorithm: x509.SHA256WithRSA}, ChallengePassword: challenge}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	return &scepFixture{ca: ca, ra: ra, client: client, clientKey: key}, csr
}

func testSCEPResult(t *testing.T, f *scepFixture, wire []byte, success bool) *x509.Certificate {
	t.Helper()
	response, err := scep.ParsePKIMessage(wire, scep.WithCACerts([]*x509.Certificate{f.ca, f.ra}))
	if err != nil {
		t.Fatal(err)
	}
	if !success {
		if response.PKIStatus != scep.FAILURE {
			t.Fatal("unauthorized certificate request succeeded")
		}
		return nil
	}
	if response.PKIStatus != scep.SUCCESS {
		t.Fatal("SCEP certificate was not issued")
	}
	if err = response.DecryptPKIEnvelope(f.client, f.clientKey); err != nil {
		t.Fatal(err)
	}
	cert := response.Certificate
	if cert == nil || cert.CheckSignatureFrom(f.ca) != nil || cert.IsCA || cert.Subject.CommonName != f.client.Subject.CommonName || !bytes.Equal(cert.RawSubjectPublicKeyInfo, f.client.RawSubjectPublicKeyInfo) || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Fatal("issued identity does not match its device and allowed usages")
	}
	return cert
}

func testSCEPEnrollProfile(t *testing.T, s *Store, deviceID string, profile []byte) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	content := testSCEPProfile(t, profile)
	a, err := s.scepEnrollmentAuthority(context.Background(), deviceID, true)
	if err != nil {
		t.Fatal(err)
	}
	f, csr := testSCEPDeviceRequest(t, deviceID, content["Challenge"].(string), a.ca, a.ra)
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.scepEnroll(context.Background(), a, request)
	if err != nil {
		t.Fatal(err)
	}
	return f.clientKey, testSCEPResult(t, f, response, true)
}

func testSCEPEnrollHTTP(t *testing.T, client *http.Client, deviceID string, profile []byte) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	content := testSCEPProfile(t, profile)
	address := content["URL"].(string)
	get := func(operation string) []byte {
		response, err := client.Get(address + "?operation=" + operation)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 {
			t.Fatal("SCEP discovery", response.StatusCode, err)
		}
		return data
	}
	if string(get("GetCACaps")) != scepCapabilities {
		t.Fatal("incorrect SCEP capabilities")
	}
	certs, err := scep.CACerts(get("GetCACert"))
	if err != nil || len(certs) != 2 {
		t.Fatal("SCEP CA/RA chain", err)
	}
	var ca, ra *x509.Certificate
	for _, c := range certs {
		if c.IsCA {
			ca = c
		} else {
			ra = c
		}
	}
	if ca == nil || ra == nil || ra.CheckSignatureFrom(ca) != nil {
		t.Fatal("invalid CA/RA chain")
	}
	var root map[string]any
	if _, err = plist.Unmarshal(profile, &root); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root["PayloadContent"].([]any)[0].(map[string]any)["PayloadContent"].([]byte), ca.Raw) {
		t.Fatal("SCEP discovery does not match the profile's trust anchor")
	}
	f, csr := testSCEPDeviceRequest(t, deviceID, content["Challenge"].(string), ca, ra)
	response, err := client.Post(address+"?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(testSCEPWire(t, f, csr, scepWireOptions{})))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("SCEP enrollment", response.StatusCode, err)
	}
	return f.clientKey, testSCEPResult(t, f, data, true)
}

func testSCEPPending(t *testing.T, s *Store, scope Scope) (string, []byte, *scepAuthority, *scepFixture, *x509.CertificateRequest) {
	t.Helper()
	invite, err := s.Invite(context.Background(), scope, "SCEP test", "admin")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s.EnrollmentProfile(context.Background(), invite.URL[strings.LastIndex(invite.URL, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	content := testSCEPProfile(t, profile)
	a, err := s.scepEnrollmentAuthority(context.Background(), invite.DeviceID, true)
	if err != nil {
		t.Fatal(err)
	}
	f, csr := testSCEPDeviceRequest(t, invite.DeviceID, content["Challenge"].(string), a.ca, a.ra)
	return invite.DeviceID, profile, a, f, csr
}

func TestSCEPEnrollmentSingleUseAndConcurrentRetries(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	id, profile, a, f, csr := testSCEPPending(t, s, Scope{TenantID: 1, SiteID: 1})
	ctx := context.Background()
	if _, err := s.AuthenticateCertificate(ctx, id, f.client); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("self-signed request authenticated as device", err)
	}
	var fingerprint sql.NullString
	var encryptedKey, storedCertificate []byte
	var challenge string
	if err := s.db.QueryRow(`SELECT d.certificate_fingerprint,e.challenge_hash,a.encrypted_key,a.certificate FROM mdm_apple_devices d JOIN mdm_apple_scep_enrollments e ON e.device_id=d.id JOIN mdm_apple_scep_authorities a ON a.id=e.authority_id WHERE d.id=$1`, id).Scan(&fingerprint, &challenge, &encryptedKey, &storedCertificate); err != nil {
		t.Fatal(err)
	}
	if fingerprint.Valid || challenge != digest([]byte(testSCEPProfile(t, profile)["Challenge"].(string))) {
		t.Fatal("identity authorized before SCEP, or challenge stored incorrectly")
	}
	if _, err := x509.ParsePKCS8PrivateKey(encryptedKey); err == nil {
		t.Fatal("RA key stored unencrypted")
	}
	if _, err := s.secrets.open(encryptedKey, secretPurpose(2, a.id, "scep_ra_key")); err == nil {
		t.Fatal("RA key crosses organization")
	}
	if f.ra.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment || f.ra.IsCA || bytes.Equal(f.ca.RawSubjectPublicKeyInfo, f.ra.RawSubjectPublicKeyInfo) {
		t.Fatal("SCEP reused issuing CA as RA")
	}
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	responses := make([][]byte, 8)
	failures := make([]error, 8)
	for i := range responses {
		wg.Add(1)
		go func() { defer wg.Done(); responses[i], failures[i] = s.scepEnroll(ctx, a, request) }()
	}
	wg.Wait()
	var certificate *x509.Certificate
	for i, response := range responses {
		if failures[i] != nil {
			t.Fatal(failures[i])
		}
		cert := testSCEPResult(t, f, response, true)
		if certificate != nil && !bytes.Equal(certificate.Raw, cert.Raw) {
			t.Fatal("retry issued another certificate")
		}
		certificate = cert
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE resource_id=$1 AND action='apple.scep.enrollment.issue'`, id).Scan(&count); err != nil || count != 1 {
		t.Fatal("issuance/audit not atomic", count, err)
	}
	var consumed sql.NullString
	if err = s.db.QueryRow(`SELECT challenge_hash FROM mdm_apple_scep_enrollments WHERE device_id=$1`, id).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatal("challenge remains reusable", err)
	}
	other, otherCSR := testSCEPDeviceRequest(t, id, request.challenge, a.ca, a.ra)
	otherRequest, err := parseSCEPRequest(testSCEPWire(t, other, otherCSR, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.scepEnroll(ctx, a, otherRequest)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, other, response, false)
	changed, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{transaction: "another-transaction"}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err = s.scepEnroll(ctx, a, changed)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, f, response, false)
	d, err := s.AuthenticateCertificate(ctx, id, certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckIn(ctx, d, map[string]any{"MessageType": "Authenticate", "UDID": uuid.NewString(), "Topic": "com.apple.mgmt.test", "ProductName": "iPhone16,1"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.scepEnrollmentAuthority(ctx, id, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("discovery remains after device possession", err)
	}
	response, err = s.scepEnroll(ctx, a, request)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, f, response, false)
}

func TestSCEPEnrollmentAuthorizationAndRollback(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	testSettings(t, s, 2)
	id, _, a, f, csr := testSCEPPending(t, s, Scope{TenantID: 1, SiteID: 1})
	_, _, foreign, _, _ := testSCEPPending(t, s, Scope{TenantID: 2, SiteID: 2})
	ctx := context.Background()
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*scepRequest)
	}{
		{"wrong challenge", func(r *scepRequest) { r.challenge = strings.Repeat("a", 43) }},
		{"wrong subject", func(r *scepRequest) { c := *r.csr; c.Subject.CommonName = foreign.deviceID; r.csr = &c }},
		{"renewal without authorization", func(r *scepRequest) { m := *r.message; m.MessageType = scep.RenewalReq; r.message = &m }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := *request
			tc.change(&r)
			response, err := s.scepEnroll(ctx, a, &r)
			if err != nil {
				t.Fatal(err)
			}
			testSCEPResult(t, f, response, false)
		})
	}
	response, err := s.scepEnroll(ctx, foreign, request)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, &scepFixture{ca: foreign.ca, ra: foreign.ra}, response, false)
	// Inject a real SQL failure after signing/pinning and check transaction rollback.
	if _, err = s.db.Exec(`CREATE FUNCTION reject_scep_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.scep.enrollment.issue' THEN RAISE EXCEPTION 'test failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_scep_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_scep_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.scepEnroll(ctx, a, request); err == nil {
		t.Fatal("audit failure ignored")
	}
	var clean bool
	if err = s.db.QueryRow(`SELECT e.challenge_hash IS NOT NULL AND e.certificate IS NULL AND d.certificate_fingerprint IS NULL FROM mdm_apple_scep_enrollments e JOIN mdm_apple_devices d ON d.id=e.device_id WHERE e.device_id=$1`, id).Scan(&clean); err != nil || !clean {
		t.Fatal("failed issuance consumed or authorized identity", err)
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_scep_audit ON mdm_apple_audit`); err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeEnrollment(ctx, Scope{TenantID: 1, SiteID: 1}, id, "admin"); err != nil {
		t.Fatal(err)
	}
	response, err = s.scepEnroll(ctx, a, request)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, f, response, false)
	if err = s.CleanupSCEPEnrollments(ctx); err != nil {
		t.Fatal(err)
	}
	var hash sql.NullString
	if err = s.db.QueryRow(`SELECT challenge_hash FROM mdm_apple_scep_enrollments WHERE device_id=$1`, id).Scan(&hash); err != nil || hash.Valid {
		t.Fatal("revoked challenge retained", err)
	}
}

func TestSCEPEnrollmentExpiryAndPublicDiscovery(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	id, _, a, f, csr := testSCEPPending(t, s, Scope{TenantID: 1, SiteID: 1})
	ctx := context.Background()
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Public discovery works without access to any private key, including APNs.
	if _, err = s.db.Exec(`UPDATE mdm_apple_settings SET push_key='bad',ca_key='bad'; UPDATE mdm_apple_scep_authorities SET encrypted_key='bad'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.scepEnrollmentAuthority(ctx, id, false); err != nil {
		t.Fatal("public discovery decrypted a key", err)
	}
	if _, err = s.scepEnrollmentAuthority(ctx, id, true); !errors.Is(err, errSCEPAuthority) {
		t.Fatal("corrupt RA key ignored", err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_scep_enrollments SET expires_at=now()-interval '1 second' WHERE device_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	response, err := s.scepEnroll(ctx, a, request)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, f, response, false)
	if _, err = s.scepEnrollmentAuthority(ctx, id, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired enrollment discovered", err)
	}
	if err = s.CleanupSCEPEnrollments(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSCEPEnrollmentCapsValidityAndIgnoresRequestedPrivileges(t *testing.T) {
	s := testStore(t)
	c := testSettings(t, s, 1)
	ctx := context.Background()
	ca, key, err := enrollmentCA(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	short := *ca
	short.NotAfter = time.Now().Add(48 * time.Hour).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &short, &short, ca.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_settings SET ca_certificate=$1 WHERE tenant_id=1`, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	id, profile, a, f, _ := testSCEPPending(t, s, Scope{TenantID: 1, SiteID: 1})
	csrDER, err := scepx509.CreateCertificateRequest(rand.Reader, &scepx509.CertificateRequest{CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: id, Organization: []string{"Unauthorized organization"}}, DNSNames: []string{"admin.example.test"}, SignatureAlgorithm: x509.SHA256WithRSA, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}}}, ChallengePassword: testSCEPProfile(t, profile)["Challenge"].(string)}, f.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	request, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.scepEnroll(ctx, a, request)
	if err != nil {
		t.Fatal(err)
	}
	cert := testSCEPResult(t, f, response, true)
	if !cert.NotAfter.Equal(short.NotAfter) || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != c.Organization || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("requested privileges or lifetime escaped issuer policy")
	}
	var expiry time.Time
	if err = s.db.QueryRow(`SELECT certificate_expires_at FROM mdm_apple_devices WHERE id=$1`, id).Scan(&expiry); err != nil || !expiry.Equal(cert.NotAfter) {
		t.Fatal("stored expiry disagrees with issued certificate", err)
	}
}

func TestSCEPClaimRechecksInvitationAfterOrganizationLock(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	ctx := context.Background()
	invite, err := s.Invite(ctx, Scope{TenantID: 1, SiteID: 1}, "Expiring invitation", "admin")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(300 * time.Millisecond)
	if _, err = s.db.Exec(`UPDATE mdm_apple_devices SET invite_expires_at=$2 WHERE id=$1`, invite.DeviceID, expires); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(684627902,1)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.EnrollmentProfile(ctx, invite.URL[strings.LastIndex(invite.URL, "/")+1:])
		done <- err
	}()
	// Observe the actual lock wait before allowing the wall-clock expiry to pass.
	for {
		var waiting bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=684627902 AND objid=1 AND objsubid=2 AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatal("claim did not wait for setup lock", err)
		default:
		}
		if time.Now().After(expires.Add(time.Second)) {
			t.Fatal("claim never reached setup lock")
		}
		time.Sleep(time.Millisecond)
	}
	if delay := time.Until(expires) + 10*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrNotFound) {
		t.Fatal("expired invitation passed lock wait", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_scep_enrollments WHERE device_id=$1`, invite.DeviceID).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired claim created a challenge", err)
	}
}
