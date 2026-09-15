package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

const managementTestDeviceID = "12345678-1234-4567-89ab-123456789012"

func managementTestCertificates(t *testing.T) (*x509.Certificate, *x509.Certificate, *authoritySigner) {
	t.Helper()
	now := time.Now().UTC()
	a := EnrollmentAuthority{ID: "00112233-4455-4677-8899-aabbccddeeff", TenantID: 1, AuthorityOptions: authorityTestOptions(), CreatedAt: now}
	der, private, err := generateAuthorityCertificate(a, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	a.Certificate, a.ExpiresAt = der, root.NotAfter
	signer := &authoritySigner{metadata: a, certificate: root, key: key.(*rsa.PrivateKey)}
	_, request := enrollmentTestCSR(t)
	csr, err := verifyEnrollmentCSR(request, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := issueEnrollmentCertificate(signer, managementTestDeviceID, credentialTestScope, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf, signer
}

func managementTestRequest(t *testing.T, der []byte, options EnrollmentOptions) *http.Request {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, options.ManagementURL, nil)
	r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{c}}
	return r
}

func managementTestEnrollment(t *testing.T, s *Store, options EnrollmentOptions) (*EnrollmentInvitation, enrollmentTestResult, *rsa.PrivateKey) {
	t.Helper()
	i, request, key := enrollmentTestRequest(t, s)
	if _, err := s.EnrollWindows(context.Background(), request, options); err != nil {
		t.Fatal(err)
	}
	return i, readEnrollmentTestResult(t, s, i.ID), key
}

func TestManagementPeerRequiresDirectTLSAndExactEndpoint(t *testing.T) {
	root, certificate, _ := managementTestCertificates(t)
	options := enrollmentTestOptions()
	for name, mutate := range map[string]func(*http.Request){
		"no TLS":               func(r *http.Request) { r.TLS = nil },
		"unfinished handshake": func(r *http.Request) { r.TLS.HandshakeComplete = false },
		"old TLS":              func(r *http.Request) { r.TLS.Version = tls.VersionTLS11 },
		"unknown TLS":          func(r *http.Request) { r.TLS.Version = 0xffff },
		"no peer":              func(r *http.Request) { r.TLS.PeerCertificates = nil },
		"nil leaf":             func(r *http.Request) { r.TLS.PeerCertificates[0] = nil },
		"empty DER":            func(r *http.Request) { r.TLS.PeerCertificates[0] = &x509.Certificate{} },
		"malformed DER":        func(r *http.Request) { r.TLS.PeerCertificates[0] = &x509.Certificate{Raw: []byte("invalid")} },
		"large DER": func(r *http.Request) {
			r.TLS.PeerCertificates[0] = &x509.Certificate{Raw: bytes.Repeat([]byte{0}, MaxEnrollmentCSRBytes+1)}
		},
		"CA as leaf":             func(r *http.Request) { r.TLS.PeerCertificates[0] = root },
		"large chain":            func(r *http.Request) { r.TLS.PeerCertificates = make([]*x509.Certificate, 9) },
		"wrong host":             func(r *http.Request) { r.Host = "other.example.test" },
		"wrong path":             func(r *http.Request) { r.URL.Path += "/" },
		"raw path":               func(r *http.Request) { r.URL.RawPath = r.URL.Path },
		"query":                  func(r *http.Request) { r.URL.RawQuery = "tenant=1" },
		"empty query":            func(r *http.Request) { r.URL.ForceQuery = true },
		"fragment":               func(r *http.Request) { r.URL.Fragment = "device" },
		"userinfo":               func(r *http.Request) { r.URL.User = url.User("device") },
		"opaque URL":             func(r *http.Request) { r.URL.Opaque = "device" },
		"plain URL":              func(r *http.Request) { r.URL.Scheme = "http" },
		"absolute host mismatch": func(r *http.Request) { r.URL.Host = "other.example.test" },
		"no URL":                 func(r *http.Request) { r.URL = nil },
		"GET":                    func(r *http.Request) { r.Method = http.MethodGet },
		"HEAD":                   func(r *http.Request) { r.Method = http.MethodHead },
	} {
		t.Run(name, func(t *testing.T) {
			r := managementTestRequest(t, certificate.Raw, options)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Client-Cert", base64.StdEncoding.EncodeToString(certificate.Raw))
			r.Header.Set("client-request-id", managementTestDeviceID)
			mutate(r)
			if got, err := managementPeerCertificate(r, options); !errors.Is(err, ErrManagementIdentity) || got != nil {
				t.Fatal("transport boundary admitted invalid identity", err)
			}
		})
	}
	if got, err := managementPeerCertificate(nil, options); !errors.Is(err, ErrManagementIdentity) || got != nil {
		t.Fatal("nil request accepted")
	}
	bad := options
	bad.ProviderID = ""
	if got, err := managementPeerCertificate(nil, bad); !errors.Is(err, ErrProvisioning) || got != nil {
		t.Fatal("invalid operator configuration accepted")
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		r := managementTestRequest(t, certificate.Raw, options)
		r.URL.Scheme, r.URL.Host = "", "" // Normal net/http server request form.
		r.TLS.Version = version
		r.TLS.PeerCertificates[0].Subject.CommonName = "untrusted middleware subject"
		r.TLS.VerifiedChains = [][]*x509.Certificate{{root}}
		r.TLS.PeerCertificates = append(r.TLS.PeerCertificates, root)
		got, err := managementPeerCertificate(r, options)
		if err != nil || got.Subject.CommonName != certificate.Subject.CommonName {
			t.Fatal("raw leaf identity was replaced by parsed fields or a chain", err)
		}
	}
}

func TestManagementIdentityIsStoredScopedAndIndependentOfInvitation(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	options := enrollmentTestOptions()
	i, state, _ := managementTestEnrollment(t, s, options)
	r := managementTestRequest(t, state.Certificate, options)
	r.Header.Set("TenantID", "2")
	r.Header.Set("SiteID", "21")
	r.Header.Set("client-request-id", "untrusted reported identifier")
	r.Header.Set("Authorization", "Bearer untrusted-token")
	// Certificate validation needs public issuer state, never its private key or
	// the master key. Session credentials will remain a separate protected read.
	readOnly, err := NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := readOnly.AuthenticateManagementDevice(r, options)
	if err != nil || identity.DeviceID != state.DeviceID || identity.Scope != credentialTestScope || identity.AuthorityID != state.AuthorityID || identity.EnrollmentType != "Full" || identity.FingerprintSHA256 != hex.EncodeToString(state.Fingerprint) || !canonicalInvitationID(identity.CertificateID) {
		t.Fatal("transport authentication did not recover persisted identity", err)
	}
	encoded, err := json.Marshal(identity)
	if err != nil || bytes.Contains(encoded, state.Auth) || bytes.Contains(encoded, []byte("synthetic@example.test")) || bytes.Contains(encoded, []byte("SYNTHETIC-WINDOWS")) {
		t.Fatal("transport identity exposed private enrollment data")
	}
	if err := s.RevokeEnrollmentInvitation(context.Background(), "operator", credentialTestScope, i.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.permissions.ReplaceGrants(context.Background(), "admin", "operator", 1, []access.Grant{{Role: access.Viewer, Scope: credentialTestScope}}); err != nil {
		t.Fatal(err)
	}
	// Change only the owned test invitation to simulate its later expiry.
	if _, err := s.db.Exec(`ALTER TABLE mdm_windows_invitations DISABLE TRIGGER mdm_windows_invitation_identity`); err != nil {
		t.Fatal(err)
	}
	_, updateErr := s.db.Exec(`UPDATE mdm_windows_invitations SET created_at=clock_timestamp()-INTERVAL '1 hour',consumed_at=clock_timestamp()-INTERVAL '2 minutes',expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE id=$1`, i.ID)
	_, enableErr := s.db.Exec(`ALTER TABLE mdm_windows_invitations ENABLE TRIGGER mdm_windows_invitation_identity`)
	if updateErr != nil || enableErr != nil {
		t.Fatal("could not simulate invitation expiry", updateErr, enableErr)
	}
	if got, err := readOnly.AuthenticateManagementDevice(r, options); err != nil || *got != *identity {
		t.Fatal("invitation lifetime or creator permissions invalidated an enrolled device", err)
	}
	for _, changed := range []EnrollmentOptions{
		{ManagementURL: options.ManagementURL, ProviderID: "other", DisplayName: options.DisplayName},
		{ManagementURL: options.ManagementURL, ProviderID: options.ProviderID, DisplayName: "Other service"},
		{ManagementURL: "https://other.example.test/manage", ProviderID: options.ProviderID, DisplayName: options.DisplayName},
	} {
		if got, err := s.AuthenticateManagementDevice(managementTestRequest(t, state.Certificate, changed), changed); !errors.Is(err, ErrManagementIdentity) || got != nil {
			t.Fatal("different service configuration accepted an enrolled identity", err)
		}
	}
	if _, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.AuthenticateManagementDevice(r, options); !errors.Is(err, ErrManagementIdentity) || got != nil {
		t.Fatal("site reparenting silently reassigned an enrolled device")
	}
	assertEnrollmentCounts(t, s, 1)
	if invitationEventCount(t, s, i.ID, "enrollment.issued") != 1 || invitationEventCount(t, s, i.ID, "enrollment.replayed") != 0 {
		t.Fatal("transport authentication rewrote enrollment state")
	}
}

func TestManagementIdentityRequiresExactCertificateAndRevocation(t *testing.T) {
	for _, resource := range []string{"mdm_windows_devices", "mdm_windows_device_certificates"} {
		t.Run(resource, func(t *testing.T) {
			s := authorityTestStore(t)
			initializeTestAuthority(t, s, 1)
			options := enrollmentTestOptions()
			_, state, _ := managementTestEnrollment(t, s, options)
			r := managementTestRequest(t, state.Certificate, options)
			identity, err := s.AuthenticateManagementDevice(r, options)
			if err != nil {
				t.Fatal(err)
			}
			_, unregistered, _ := managementTestCertificates(t)
			untrusted := managementTestRequest(t, unregistered.Raw, options)
			untrusted.TLS.PeerCertificates = append(untrusted.TLS.PeerCertificates, r.TLS.PeerCertificates[0])
			untrusted.TLS.VerifiedChains = [][]*x509.Certificate{{r.TLS.PeerCertificates[0]}}
			if got, err := s.AuthenticateManagementDevice(untrusted, options); !errors.Is(err, ErrManagementIdentity) || got != nil {
				t.Fatal("unregistered leaf borrowed a registered chain identity")
			}
			id := identity.DeviceID
			if resource == "mdm_windows_device_certificates" {
				id = identity.CertificateID
			}
			if _, err := s.db.Exec(`UPDATE `+resource+` SET revoked_at=clock_timestamp() WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
			if got, err := s.AuthenticateManagementDevice(r, options); !errors.Is(err, ErrManagementIdentity) || got != nil {
				t.Fatal("revoked identity authenticated")
			}
		})
	}
}

func TestManagementIdentityKeepsOrganizationsAndEnrollmentContextsSeparate(t *testing.T) {
	s := authorityTestStore(t)
	firstCA := initializeTestAuthority(t, s, 1)
	secondCA := initializeTestAuthority(t, s, 2)
	options := enrollmentTestOptions()
	_, first, _ := managementTestEnrollment(t, s, options)
	otherScope := access.Scope{TenantID: 2, SiteID: 21}
	invitation, credential, err := s.CreateEnrollmentInvitation(context.Background(), "foreign", otherScope, "synthetic@example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, csr := enrollmentTestCSR(t)
	items := wstepTestContext()
	for n := range items {
		if items[n].Name == "EnrollmentType" {
			items[n].Value = "Device"
		}
	}
	request := &WSTEPRequest{MessageID: discoveryTestID, Credential: *credential, CSRDER: csr, Context: items}
	if _, err := s.EnrollWindows(context.Background(), request, options); err != nil {
		t.Fatal(err)
	}
	second := readEnrollmentTestResult(t, s, invitation.ID)
	for n, state := range []enrollmentTestResult{first, second} {
		r := managementTestRequest(t, state.Certificate, options)
		r.Header.Set("client-request-id", first.DeviceID)
		r.Header.Set("X-Organization-ID", "1")
		identity, err := s.AuthenticateManagementDevice(r, options)
		if err != nil || identity.DeviceID != state.DeviceID {
			t.Fatal("enrolled device could not authenticate", err)
		}
		if n == 0 && (identity.AuthorityID != firstCA.ID || identity.Scope != credentialTestScope || identity.EnrollmentType != "Full") {
			t.Fatal("first organization or context changed")
		}
		if n == 1 && (identity.AuthorityID != secondCA.ID || identity.Scope != otherScope || identity.EnrollmentType != "Device") {
			t.Fatal("reported identifiers merged organizations or enrollment contexts")
		}
	}
	if first.DeviceID == second.DeviceID {
		t.Fatal("identical device hints merged independent enrollments")
	}
}

func TestManagementIdentityHoldsRevocationLockThroughTransaction(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	options := enrollmentTestOptions()
	_, state, _ := managementTestEnrollment(t, s, options)
	r := managementTestRequest(t, state.Certificate, options)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	device, err := s.authorizeManagementDevice(ctx, tx, r.TLS.PeerCertificates[0], options)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := s.db.ExecContext(ctx, `UPDATE mdm_windows_device_certificates SET revoked_at=clock_timestamp() WHERE device_id=$1`, state.DeviceID)
		finished <- err
	}()
	waitForCredentialLock(t, s.db, pid, 1)
	if err := checkManagementDeviceTime(ctx, tx, device); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if got, err := s.AuthenticateManagementDevice(r, options); !errors.Is(err, ErrManagementIdentity) || got != nil {
		t.Fatal("subsequent request reused identity from before revocation")
	}
}

func TestManagementIdentityWaitsForRevocationAndScopeTransactions(t *testing.T) {
	for name, statement := range map[string]string{
		"certificate revoked": `UPDATE mdm_windows_device_certificates SET revoked_at=clock_timestamp() WHERE device_id=$1`,
		"device revoked":      `UPDATE mdm_windows_devices SET revoked_at=clock_timestamp() WHERE id=$1`,
		"site reparented":     `UPDATE sites SET tenant_sites=2 WHERE id=(SELECT site_id FROM mdm_windows_devices WHERE id=$1)`,
	} {
		t.Run(name, func(t *testing.T) {
			s := authorityTestStore(t)
			initializeTestAuthority(t, s, 1)
			options := enrollmentTestOptions()
			_, state, _ := managementTestEnrollment(t, s, options)
			hold, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback()
			var pid int
			if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(statement, state.DeviceID); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r := managementTestRequest(t, state.Certificate, options).WithContext(ctx)
			finished := make(chan error, 1)
			go func() {
				got, err := s.AuthenticateManagementDevice(r, options)
				if got != nil {
					err = errors.New("identity escaped a conflicting transaction")
				}
				finished <- err
			}()
			waitForCredentialLock(t, s.db, pid, 1)
			if err := hold.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-finished; !errors.Is(err, ErrManagementIdentity) {
				t.Fatal("concurrent state change did not deny authentication", err)
			}
		})
	}
}

func TestManagementCertificateRejectsSignedPrivilegeAndIdentityChanges(t *testing.T) {
	root, leaf, signer := managementTestCertificates(t)
	a := signer.metadata
	for name, mutate := range map[string]func(*x509.Certificate){
		"CA privilege":          func(c *x509.Certificate) { c.IsCA = true },
		"missing constraints":   func(c *x509.Certificate) { c.BasicConstraintsValid = false },
		"server authentication": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"any authentication":    func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
		"extra usage":           func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment },
		"unknown EKU":           func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} },
		"critical extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 5}, Critical: true, Value: []byte{5, 0}}}
		},
		"subject":             func(c *x509.Certificate) { c.Subject.CommonName = "other" },
		"organization":        func(c *x509.Certificate) { c.Subject.Organization = []string{"other"} },
		"site":                func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"Organization 1", "Site 12"} },
		"URI":                 func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "urn", Opaque: "other"}} },
		"DNS identity":        func(c *x509.Certificate) { c.DNSNames = []string{"other.example.test"} },
		"email identity":      func(c *x509.Certificate) { c.EmailAddresses = []string{"other@example.test"} },
		"key identifier":      func(c *x509.Certificate) { c.SubjectKeyId = []byte("other") },
		"signature algorithm": func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA384WithRSA },
	} {
		t.Run(name, func(t *testing.T) {
			template := *leaf
			template.RawSubject = nil
			mutate(&template)
			der, err := x509.CreateCertificate(rand.Reader, &template, root, leaf.PublicKey, signer.key)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			device := &managementDevice{identity: ManagementDeviceIdentity{DeviceID: managementTestDeviceID, CertificateID: "22222222-2222-4222-8222-222222222222", AuthorityID: a.ID, Scope: credentialTestScope, EnrollmentType: "Device", CertificateExpiry: changed.NotAfter}, certificate: changed, root: root}
			hash := sha256.Sum256(changed.RawSubjectPublicKeyInfo)
			if err := validateManagementCertificate(device, a, hash[:], changed.SerialNumber.Bytes()); !errors.Is(err, ErrManagementIdentity) {
				t.Fatal("signed but incompatible certificate admitted", err)
			}
		})
	}
}

func TestManagementIdentityRealTLSAndSessionResumption(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	options := enrollmentTestOptions()
	type result struct {
		identity *ManagementDeviceIdentity
		err      error
		resumed  bool
	}
	observed := make(chan result, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.AuthenticateManagementDevice(r, options)
		observed <- result{identity, err, r.TLS.DidResume}
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	options.ManagementURL = "https://" + server.Listener.Addr().String() + "/management"
	_, state, key := managementTestEnrollment(t, s, options)
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	withoutCertificate := &http.Client{Transport: client.Transport.(*http.Transport).Clone(), Timeout: 5 * time.Second}
	defer withoutCertificate.CloseIdleConnections()
	transport := client.Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.DisableKeepAlives = true
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{state.Certificate}, PrivateKey: key}}
	client.Transport = transport
	for n := 0; n < 3; n++ {
		if n == 2 {
			if _, err := s.db.Exec(`UPDATE mdm_windows_devices SET revoked_at=clock_timestamp() WHERE id=$1`, state.DeviceID); err != nil {
				t.Fatal(err)
			}
		}
		response, err := client.Post(options.ManagementURL, "application/vnd.syncml.dm+xml", strings.NewReader("unused synthetic payload"))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		got := <-observed
		if n < 2 && (response.StatusCode != http.StatusNoContent || got.err != nil || got.identity.DeviceID != state.DeviceID) {
			t.Fatal("real mutual TLS did not authenticate enrolled certificate", got.err)
		}
		if n > 0 && !got.resumed {
			t.Fatal("test did not exercise a resumed TLS session")
		}
		if n == 2 && (response.StatusCode != http.StatusUnauthorized || !errors.Is(got.err, ErrManagementIdentity) || got.identity != nil) {
			t.Fatal("TLS resumption bypassed current device revocation")
		}
	}
	// A fresh client cannot replace TLS proof with forwarded certificate headers.
	request, _ := http.NewRequest(http.MethodPost, options.ManagementURL, nil)
	request.Header.Set("X-Forwarded-Client-Cert", base64.StdEncoding.EncodeToString(state.Certificate))
	if response, err := withoutCertificate.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("missing client private-key proof completed mutual TLS")
	}
}

func TestManagementIdentityExpiryAndCancellationDuringDatabaseWait(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "certificate expires"
		if canceled {
			name = "request canceled"
		}
		t.Run(name, func(t *testing.T) {
			s := authorityTestStore(t)
			initializeTestAuthority(t, s, 1)
			options := enrollmentTestOptions()
			_, state, _ := managementTestEnrollment(t, s, options)
			tx, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			signer, err := s.enrollmentAuthority(context.Background(), tx, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(state.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := s.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			leaf.NotAfter = now.Add(3 * time.Second).Truncate(time.Second)
			leaf.SerialNumber = big.NewInt(12345)
			der, err := x509.CreateCertificate(rand.Reader, leaf, signer.certificate, leaf.PublicKey, signer.key)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(der)
			// Only this disposable schema gets an artificially short-lived leaf.
			// Runtime certificate records retain their immutability trigger.
			if _, err := s.db.Exec(`ALTER TABLE mdm_windows_device_certificates DISABLE TRIGGER mdm_windows_device_certificate`); err != nil {
				t.Fatal(err)
			}
			_, updateErr := s.db.Exec(`UPDATE mdm_windows_device_certificates SET certificate=$1,fingerprint=$2,serial=$3,expires_at=$4 WHERE device_id=$5`, der, hash[:], leaf.SerialNumber.Bytes(), leaf.NotAfter, state.DeviceID)
			_, enableErr := s.db.Exec(`ALTER TABLE mdm_windows_device_certificates ENABLE TRIGGER mdm_windows_device_certificate`)
			if updateErr != nil || enableErr != nil {
				t.Fatal(updateErr, enableErr)
			}
			r := managementTestRequest(t, der, options)
			if got, err := s.AuthenticateManagementDevice(r, options); err != nil || got == nil {
				t.Fatal("short-lived test certificate was not initially valid", err)
			}
			hold, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback()
			var pid int
			if err := hold.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(`LOCK TABLE mdm_windows_authorities IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
			finished := make(chan error, 1)
			go func() {
				got, err := s.AuthenticateManagementDevice(r, options)
				if got != nil {
					err = errors.New("identity escaped expiry or cancellation")
				}
				finished <- err
			}()
			waitForCredentialLock(t, s.db, pid, 1)
			if canceled {
				cancel()
			} else if err := waitUntilDatabaseExpiry(ctx, hold, leaf.NotAfter); err != nil {
				t.Fatal(err)
			}
			if err := hold.Commit(); err != nil {
				t.Fatal(err)
			}
			err = <-finished
			if err == nil || (!canceled && !errors.Is(err, ErrManagementIdentity)) {
				t.Fatal("expired or canceled identity authenticated", err)
			}
			assertEnrollmentCounts(t, s, 1)
		})
	}
}
