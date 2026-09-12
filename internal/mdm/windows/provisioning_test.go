package windows

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func enrollmentTestOptions() EnrollmentOptions {
	return EnrollmentOptions{ManagementURL: "https://manage.example.test/windows/syncml", ProviderID: "OpenUEM", DisplayName: "OpenUEM & Synthetic"}
}

func enrollmentTestCSR(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "administrator", Organization: []string{"Foreign organization"}},
		DNSNames: []string{"admin.attacker.example.test"}, EmailAddresses: []string{"administrator@attacker.example.test"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions:    []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func wireAttribute(t *testing.T, node *policyWireNode, name string) string {
	t.Helper()
	for _, attr := range node.Attrs {
		if attr.Name == (xml.Name{Local: name}) {
			return attr.Value
		}
	}
	t.Fatal("missing provisioning attribute", name)
	return ""
}

func wireCharacteristic(t *testing.T, node *policyWireNode, kind string) *policyWireNode {
	t.Helper()
	for i := range node.Children {
		child := &node.Children[i]
		if child.Name == (xml.Name{Local: "characteristic"}) && wireAttribute(t, child, "type") == kind {
			return child
		}
	}
	t.Fatal("missing provisioning characteristic", kind)
	return nil
}

func wireParameter(t *testing.T, node *policyWireNode, name string) *policyWireNode {
	t.Helper()
	for i := range node.Children {
		child := &node.Children[i]
		if child.Name == (xml.Name{Local: "parm"}) && wireAttribute(t, child, "name") == name {
			return child
		}
	}
	t.Fatal("missing provisioning parameter", name)
	return nil
}

func provisioningFromResponse(t *testing.T, data []byte, messageID string) ([]byte, int64) {
	t.Helper()
	var root policyWireNode
	if err := xml.Unmarshal(data, &root); err != nil {
		t.Fatal("invalid SOAP response XML")
	}
	header := wireChild(t, &root, soapNS, "Header")
	if wireChild(t, header, addressingNS, "Action").Text != WSTEPResponseAction || wireChild(t, header, addressingNS, "RelatesTo").Text != messageID {
		t.Fatal("WSTEP response action or correlation changed")
	}
	body := wireChild(t, &root, soapNS, "Body")
	collection := wireChild(t, body, trustNS, "RequestSecurityTokenResponseCollection")
	if len(collection.Children) != 1 {
		t.Fatal("multiple WSTEP results returned")
	}
	response := wireChild(t, collection, trustNS, "RequestSecurityTokenResponse")
	if wireChild(t, response, trustNS, "TokenType").Text != deviceTokenType {
		t.Fatal("incorrect enrollment response token type")
	}
	if wireChild(t, response, wstepNS, "DispositionMessage").Text != "" {
		t.Fatal("unexpected disposition details")
	}
	requestID, err := strconv.ParseInt(wireChild(t, response, wstepNS, "RequestID").Text, 10, 64)
	if err != nil || requestID <= 0 {
		t.Fatal("missing durable issuance request number")
	}
	token := wireChild(t, wireChild(t, response, trustNS, "RequestedSecurityToken"), securityNS, "BinarySecurityToken")
	if wireAttribute(t, token, "ValueType") != provisionTokenType || wireAttribute(t, token, "EncodingType") != binaryEncodingType {
		t.Fatal("incorrect provisioning token encoding")
	}
	provisioning, err := base64.StdEncoding.Strict().DecodeString(token.Text)
	if err != nil || len(provisioning) == 0 || len(provisioning) > maxProvisioningBytes {
		t.Fatal("invalid provisioning document encoding")
	}
	return provisioning, requestID
}

func TestEnrollmentCertificateAndProvisioning(t *testing.T) {
	now := time.Now().UTC()
	a := EnrollmentAuthority{ID: "00112233-4455-4677-8899-aabbccddeeff", TenantID: 1, AuthorityOptions: authorityTestOptions(), CreatedAt: now}
	rootDER, private, err := generateAuthorityCertificate(a, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	a.Certificate, a.ExpiresAt = rootDER, root.NotAfter
	box, _ := newAuthoritySecretBox(authorityTestMasterKey)
	encrypted, err := box.seal(private, authoritySecretPurpose(a))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := (&Store{secrets: box}).decryptAuthority(a, encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	key, der := enrollmentTestCSR(t)
	csr, err := verifyEnrollmentCSR(der, 2048)
	if err != nil {
		t.Fatal(err)
	}
	id := "12345678-1234-4567-89ab-123456789012"
	certificate, err := issueEnrollmentCertificate(signer, id, credentialTestScope, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.PublicKey.(*rsa.PublicKey).Equal(&key.PublicKey) || certificate.IsCA || certificate.Subject.CommonName != "OpenUEM Windows "+id || !slices.Equal(certificate.Subject.Organization, []string{a.Organization}) || (len(certificate.Subject.OrganizationalUnit) != 2 || !slices.Contains(certificate.Subject.OrganizationalUnit, "Organization 1") || !slices.Contains(certificate.Subject.OrganizationalUnit, "Site 11")) || len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 1 || certificate.URIs[0].String() != "urn:openuem:windows:device:"+id {
		t.Fatal("CSR controlled the certified identity or privileges")
	}
	if certificate.KeyUsage != x509.KeyUsageDigitalSignature || !slices.Equal(certificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || !certificate.NotAfter.Equal(now.Add(time.Duration(a.ValiditySeconds)*time.Second).Truncate(time.Second)) {
		t.Fatal("certificate usage or validity differs from policy")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("device certificate admitted for server authentication")
	}
	secrets, err := newSyncMLBootstrapSecrets()
	if err != nil {
		t.Fatal(err)
	}
	unique := map[string]bool{}
	for _, value := range []string{secrets.ClientSecret, secrets.ServerSecret, secrets.ClientNonce, secrets.ServerNonce} {
		if unique[value] {
			t.Fatal("bootstrap credentials share a secret or nonce")
		}
		unique[value] = true
	}
	options := enrollmentTestOptions()
	for _, enrollmentType := range []string{"Full", "Device"} {
		doc, err := buildProvisioningDocument(options, id, enrollmentType, root, certificate, secrets)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := buildWSTEPResponse(discoveryTestID, 42, doc)
		if err != nil {
			t.Fatal(err)
		}
		decoded, requestID := provisioningFromResponse(t, wire, discoveryTestID)
		if !bytes.Equal(decoded, doc) || requestID != 42 {
			t.Fatal("SOAP changed provisioning content")
		}
		var document policyWireNode
		if err := xml.Unmarshal(doc, &document); err != nil {
			t.Fatal("invalid provisioning XML")
		}
		if document.Name != (xml.Name{Local: "wap-provisioningdoc"}) || wireAttribute(t, &document, "version") != "1.1" || len(document.Children) != 4 {
			t.Fatal("incorrect provisioning root")
		}
		location := "User"
		if enrollmentType == "Device" {
			location = "System"
		}
		for n, target := range []*x509.Certificate{root, certificate} {
			store := &document.Children[n]
			if wireAttribute(t, store, "type") != "CertificateStore" {
				t.Fatal("missing certificate store")
			}
			kind, where := "Root", "System"
			if n == 1 {
				kind, where = "My", location
			}
			container := wireCharacteristic(t, wireCharacteristic(t, store, kind), where)
			thumbprint := sha1.Sum(target.Raw)
			entry := wireCharacteristic(t, container, strings.ToUpper(hex.EncodeToString(thumbprint[:])))
			encoded := wireAttribute(t, wireParameter(t, entry, "EncodedCertificate"), "value")
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || !bytes.Equal(decoded, target.Raw) {
				t.Fatal("provisioned certificate does not match issued certificate")
			}
			if n == 1 {
				if len(wireCharacteristic(t, container, "PrivateKeyContainer").Children) != 0 {
					t.Fatal("private key container must be empty")
				}
			}
		}
		app := wireCharacteristic(t, &document, "APPLICATION")
		for name, value := range map[string]string{"APPID": "w7", "PROVIDER-ID": options.ProviderID, "NAME": options.DisplayName, "ADDR": options.ManagementURL, "PROTOVER": "1.2", "DEFAULTENCODING": "application/vnd.syncml.dm+xml", "ROLE": "32"} {
			if wireAttribute(t, wireParameter(t, app, name), "value") != value {
				t.Fatal("incorrect management bootstrap parameter", name)
			}
		}
		criteria, err := url.ParseQuery(wireAttribute(t, wireParameter(t, app, "SSLCLIENTCERTSEARCHCRITERIA"), "value"))
		if err != nil || criteria.Get("Subject") != "CN="+certificate.Subject.CommonName || criteria.Get("Stores") != "My\\User" {
			t.Fatal("client certificate search does not select the issued identity")
		}
		levels := map[string]bool{}
		for i := range app.Children {
			child := &app.Children[i]
			if child.Name.Local != "characteristic" {
				continue
			}
			if wireAttribute(t, child, "type") != "APPAUTH" {
				t.Fatal("unexpected APPLICATION characteristic")
			}
			level := wireAttribute(t, wireParameter(t, child, "AAUTHLEVEL"), "value")
			levels[level] = true
			wantSecret, wantNonce, wantName := secrets.ClientSecret, secrets.ClientNonce, id
			if level == "CLIENT" {
				wantSecret, wantNonce, wantName = secrets.ServerSecret, secrets.ServerNonce, options.ProviderID
			}
			for name, want := range map[string]string{"AAUTHTYPE": "DIGEST", "AAUTHSECRET": wantSecret, "AAUTHDATA": wantNonce, "AAUTHNAME": wantName} {
				if wireAttribute(t, wireParameter(t, child, name), "value") != want {
					t.Fatal("SyncML authentication direction or material changed")
				}
			}
		}
		if !levels["CLIENT"] || !levels["APPSRV"] || len(levels) != 2 {
			t.Fatal("missing mutual SyncML credentials")
		}
		client := wireCharacteristic(t, wireCharacteristic(t, wireCharacteristic(t, &document, "DMClient"), "Provider"), options.ProviderID)
		if wireAttribute(t, wireParameter(t, client, "EntDMID"), "value") != id {
			t.Fatal("server device identity not provisioned")
		}
		poll := wireCharacteristic(t, client, "Poll")
		if wireAttribute(t, wireParameter(t, poll, "NumberOfFirstRetries"), "value") == "0" || wireAttribute(t, wireParameter(t, poll, "IntervalForRemainingScheduledRetries"), "value") != "1560" {
			t.Fatal("invalid polling schedule")
		}
		for _, unsupported := range []string{"ROBOSupport", "AAUTHTYPE\" value=\"BASIC", "untrusted.example.test", "administrator", "Foreign organization", "Registry", "Attestation"} {
			if bytes.Contains(doc, []byte(unsupported)) {
				t.Fatal("provisioning copied untrusted input or advertised unfinished capability")
			}
		}
	}
	if _, err := buildWSTEPResponse("invalid", 1, []byte("x")); !errors.Is(err, ErrWSTEP) {
		t.Fatal("invalid SOAP correlation admitted")
	}
}

func TestProvisioningConfigurationAndSecretBounds(t *testing.T) {
	for _, change := range []func(*EnrollmentOptions){
		func(o *EnrollmentOptions) { o.ManagementURL = "http://manage.example.test/syncml" },
		func(o *EnrollmentOptions) { o.ManagementURL += "?device=1" },
		func(o *EnrollmentOptions) { o.ProviderID = "" },
		func(o *EnrollmentOptions) { o.ProviderID = strings.Repeat("a", 65) },
		func(o *EnrollmentOptions) { o.ProviderID = "a/b" },
		func(o *EnrollmentOptions) { o.DisplayName = "" },
		func(o *EnrollmentOptions) { o.DisplayName = strings.Repeat("a", 129) },
		func(o *EnrollmentOptions) { o.DisplayName = " padded " },
		func(o *EnrollmentOptions) { o.DisplayName = "a\nb" },
		func(o *EnrollmentOptions) { o.DisplayName = "a\uffffb" },
		func(o *EnrollmentOptions) { o.DisplayName = string([]byte{255}) },
	} {
		o := enrollmentTestOptions()
		change(&o)
		if !errors.Is(o.validate(), ErrProvisioning) {
			t.Fatal("invalid provisioning configuration admitted")
		}
	}
	o := enrollmentTestOptions()
	o.ProviderID = strings.Repeat("a", 64)
	o.DisplayName = strings.Repeat("a", 128)
	if err := o.validate(); err != nil {
		t.Fatal("valid provisioning size boundary rejected")
	}
	secrets, err := newSyncMLBootstrapSecrets()
	if err != nil {
		t.Fatal(err)
	}
	secrets.ClientNonce = "malformed"
	if !errors.Is(secrets.validate(), ErrProvisioning) {
		t.Fatal("invalid nonce admitted")
	}
	box, err := newAuthoritySecretBox(authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{7}, maxProvisioningBytes)
	encrypted, err := box.sealBounded(plain, "provisioning-test", maxProvisioningBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted, err := box.openBounded(encrypted, "provisioning-test", maxProvisioningBytes); err != nil || !bytes.Equal(decrypted, plain) {
		t.Fatal("valid protected provisioning boundary failed")
	}
	if _, err := box.open(encrypted, "provisioning-test"); !errors.Is(err, ErrAuthoritySecret) {
		t.Fatal("provisioning size widened the CA-key envelope limit")
	}
	if _, err := box.sealBounded(append(plain, 0), "provisioning-test", maxProvisioningBytes); !errors.Is(err, ErrAuthoritySecret) {
		t.Fatal("oversized protected provisioning admitted")
	}
	for _, input := range []struct {
		id   int64
		data []byte
	}{{0, []byte("x")}, {1, nil}, {1, make([]byte, maxProvisioningBytes+1)}} {
		if _, err := buildWSTEPResponse(discoveryTestID, input.id, input.data); !errors.Is(err, ErrWSTEP) {
			t.Fatal("invalid response bounds admitted")
		}
	}
	if _, err := buildProvisioningDocument(enrollmentTestOptions(), "invalid", "Full", nil, nil, nil); !errors.Is(err, ErrProvisioning) {
		t.Fatal("invalid provisioning identity admitted")
	}
}
