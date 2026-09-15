package apple

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	scepx509 "github.com/smallstep/scep/x509util"
)

type scepFixture struct {
	ca, ra, client                  *x509.Certificate
	caKey, raKey, clientKey, newKey *rsa.PrivateKey
}

var sharedSCEPFixture = sync.OnceValues(func() (*scepFixture, error) {
	f := new(scepFixture)
	for _, dest := range []**rsa.PrivateKey{&f.caKey, &f.raKey, &f.clientKey, &f.newKey} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		*dest = key
	}
	now := time.Now()
	issue := func(template, parent *x509.Certificate, key, signer *rsa.PrivateKey) (*x509.Certificate, error) {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SCEP test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true}
	var err error
	if f.ca, err = issue(ca, ca, f.caKey, f.caKey); err != nil {
		return nil, err
	}
	ra := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "SCEP test RA"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, BasicConstraintsValid: true}
	if f.ra, err = issue(ra, f.ca, f.raKey, f.caKey); err != nil {
		return nil, err
	}
	client := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "10000000-0000-0000-0000-000000000001"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, BasicConstraintsValid: true}
	if f.client, err = issue(client, client, f.clientKey, f.clientKey); err != nil {
		return nil, err
	}
	return f, nil
})

func testSCEPFixture(t testing.TB) *scepFixture {
	t.Helper()
	f, err := sharedSCEPFixture()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func testSCEPCSR(t testing.TB, key *rsa.PrivateKey, challenge string) *x509.CertificateRequest {
	t.Helper()
	der, err := scepx509.CreateCertificateRequest(rand.Reader, &scepx509.CertificateRequest{CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: "10000000-0000-0000-0000-000000000001"}, SignatureAlgorithm: x509.SHA256WithRSA}, ChallengePassword: challenge}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

type scepWireOptions struct {
	digest         asn1.ObjectIdentifier
	kind           scep.MessageType
	nonce          []byte
	transaction    string
	extra          []pkcs7.Attribute
	changeEnvelope func([]byte) []byte
	changeSigned   func(*pkcs7.SignedData)
}

func testSCEPWire(t testing.TB, f *scepFixture, csr *x509.CertificateRequest, options scepWireOptions) []byte {
	t.Helper()
	encrypted, err := pkcs7.Encrypt(csr.Raw, []*x509.Certificate{f.ra})
	if err != nil {
		t.Fatal(err)
	}
	if options.changeEnvelope != nil {
		encrypted = options.changeEnvelope(encrypted)
	}
	signed, err := pkcs7.NewSignedData(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if options.digest == nil {
		options.digest = pkcs7.OIDDigestAlgorithmSHA256
	}
	if options.kind == "" {
		options.kind = scep.PKCSReq
	}
	if options.nonce == nil {
		options.nonce = bytes.Repeat([]byte{1}, 16)
	}
	if options.transaction == "" {
		options.transaction = "test-transaction-1"
	}
	signed.SetDigestAlgorithm(options.digest)
	attributes := []pkcs7.Attribute{{Type: scepMessageTypeOID, Value: options.kind}, {Type: scepTransactionOID, Value: options.transaction}, {Type: scepSenderNonceOID, Value: options.nonce}}
	attributes = append(attributes, options.extra...)
	if err = signed.AddSigner(f.client, f.clientKey, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attributes}); err != nil {
		t.Fatal(err)
	}
	if options.changeSigned != nil {
		options.changeSigned(signed)
	}
	data, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSCEPVerifiesBothProofsAndStrongAlgorithms(t *testing.T) {
	f := testSCEPFixture(t)
	for _, kind := range []scep.MessageType{scep.PKCSReq, scep.RenewalReq} {
		key := f.clientKey
		if kind == scep.RenewalReq {
			key = f.newKey
		}
		csr := testSCEPCSR(t, key, "single-use-challenge")
		for _, algorithm := range []asn1.ObjectIdentifier{pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA384, pkcs7.OIDDigestAlgorithmSHA512} {
			data := testSCEPWire(t, f, csr, scepWireOptions{kind: kind, digest: algorithm})
			got, err := parseSCEPRequest(data, f.ra, f.raKey, time.Now())
			if err != nil {
				t.Fatalf("%s/%s: %v", kind, algorithm, err)
			}
			if !bytes.Equal(got.csr.Raw, csr.Raw) || !bytes.Equal(got.signer.Raw, f.client.Raw) || got.challenge != "single-use-challenge" {
				t.Fatal("request association changed")
			}
		}
	}
	csr := testSCEPCSR(t, f.newKey, "")
	if _, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), f.ra, f.raKey, time.Now()); !errors.Is(err, errSCEPMessage) {
		t.Fatal("initial request signed with unrelated key accepted", err)
	}
	bad := testSCEPCSR(t, f.newKey, "")
	bad.Raw[len(bad.Raw)-1] ^= 1
	if _, err := parseSCEPRequest(testSCEPWire(t, f, bad, scepWireOptions{kind: scep.RenewalReq}), f.ra, f.raKey, time.Now()); !errors.Is(err, errSCEPMessage) {
		t.Fatal("renewal without valid new-key proof accepted", err)
	}
}

func TestSCEPRejectsMalformedAndAmbiguousMessages(t *testing.T) {
	f := testSCEPFixture(t)
	csr := testSCEPCSR(t, f.clientKey, "challenge")
	cases := map[string]scepWireOptions{
		"sha1":                  {digest: pkcs7.OIDDigestAlgorithmSHA1},
		"update":                {kind: scep.UpdateReq},
		"nonce_short":           {nonce: make([]byte, 15)},
		"nonce_long":            {nonce: make([]byte, 17)},
		"unknown_message_type":  {kind: scep.MessageType("999")},
		"bad_cms_signature":     {changeSigned: func(s *pkcs7.SignedData) { s.GetSignedData().SignerInfos[0].EncryptedDigest[0] ^= 1 }},
		"transaction_long":      {transaction: strings.Repeat("a", 129)},
		"transaction_control":   {transaction: "unsafe\nidentifier"},
		"duplicate_transaction": {extra: []pkcs7.Attribute{{Type: scepTransactionOID, Value: "another-transaction"}}},
		"weak_signature_label": {changeSigned: func(s *pkcs7.SignedData) {
			s.GetSignedData().SignerInfos[0].DigestEncryptionAlgorithm.Algorithm = pkcs7.OIDEncryptionAlgorithmRSASHA1
		}},
		"two_signers": {changeSigned: func(s *pkcs7.SignedData) {
			if err := s.AddSigner(f.client, f.clientKey, pkcs7.SignerInfoConfig{}); err != nil {
				t.Fatal(err)
			}
		}},
		"duplicate_signer_certificate": {changeSigned: func(s *pkcs7.SignedData) { s.AddCertificate(f.client) }},
		"unenveloped_content":          {changeEnvelope: func([]byte) []byte { return []byte{0x30, 0} }},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			data := testSCEPWire(t, f, csr, options)
			if _, err := parseSCEPRequest(data, f.ra, f.raKey, time.Now()); !errors.Is(err, errSCEPMessage) {
				t.Fatal("invalid request accepted", err)
			}
		})
	}
	valid := testSCEPWire(t, f, csr, scepWireOptions{})
	for _, data := range [][]byte{append(append([]byte{}, valid...), 0), valid[:len(valid)-1], make([]byte, maxSCEPMessage+1), {0x30, 0x80, 0, 0}} {
		if _, err := parseSCEPRequest(data, f.ra, f.raKey, time.Now()); !errors.Is(err, errSCEPMessage) {
			t.Fatal("invalid DER accepted", err)
		}
	}
	if _, err := parseSCEPRequest(valid, f.ra, f.raKey, f.client.NotAfter); !errors.Is(err, errSCEPMessage) {
		t.Fatal("expired signer accepted", err)
	}
	if _, err := parseSCEPRequest(valid, f.ca, f.caKey, time.Now()); !errors.Is(err, errSCEPMessage) {
		t.Fatal("wrong RA decrypted envelope", err)
	}
}

func TestSCEPResponseSignatureEncryptionAndNonces(t *testing.T) {
	f := testSCEPFixture(t)
	csr := testSCEPCSR(t, f.clientKey, "challenge")
	req, err := parseSCEPRequest(testSCEPWire(t, f, csr, scepWireOptions{}), f.ra, f.raKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, success := range []bool{false, true} {
		var leaf *x509.Certificate
		if success {
			leaf = f.client
		}
		response, err := req.response(f.ra, f.raKey, f.ca, leaf, scep.BadRequest)
		if err != nil {
			t.Fatal(err)
		}
		p7, err := pkcs7.Parse(response)
		if err != nil {
			t.Fatal(err)
		}
		if !p7.Signers[0].DigestAlgorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256) {
			t.Fatal("response used weak digest")
		}
		got, err := scep.ParsePKIMessage(response, scep.WithCACerts([]*x509.Certificate{f.ra, f.ca}))
		if err != nil {
			t.Fatal("independent SCEP client rejected response", err)
		}
		if got.TransactionID != req.message.TransactionID || !bytes.Equal(got.RecipientNonce, req.message.SenderNonce) {
			t.Fatal("response lost transaction or nonce")
		}
		var nonce []byte
		if err = p7.UnmarshalSignedAttribute(scepSenderNonceOID, &nonce); err != nil || len(nonce) != 16 || bytes.Equal(nonce, req.message.SenderNonce) {
			t.Fatal("response did not generate fresh sender nonce", err)
		}
		if success {
			if got.PKIStatus != scep.SUCCESS || validateSCEPEnvelope(p7.Content) != nil {
				t.Fatal("invalid successful response")
			}
			if err = got.DecryptPKIEnvelope(f.client, f.clientKey); err != nil || !bytes.Equal(got.Certificate.Raw, leaf.Raw) {
				t.Fatal("client could not decrypt issued certificate", err)
			}
		} else if got.PKIStatus != scep.FAILURE || got.FailInfo != scep.BadRequest {
			t.Fatal("incorrect failure response")
		}
	}
}

func TestSCEPResponseWithOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is unavailable")
	}
	f := testSCEPFixture(t)
	req, err := parseSCEPRequest(testSCEPWire(t, f, testSCEPCSR(t, f.clientKey, "challenge"), scepWireOptions{}), f.ra, f.raKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err := req.response(f.ra, f.raKey, f.ca, f.client, scep.BadRequest)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(f.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"response.der": response, "ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw}), "client.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.client.Raw}), "client.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), openssl, args...)
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("OpenSSL interoperability: %v\n%s", err, output)
		}
	}
	// Every nested CMS layer is binary DER. OpenSSL's text-mode output changes
	// line endings on Windows unless -binary is explicit for each operation.
	run("cms", "-verify", "-binary", "-inform", "DER", "-in", "response.der", "-CAfile", "ca.pem", "-purpose", "any", "-out", "envelope.der")
	verified, err := os.ReadFile(filepath.Join(dir, "envelope.der"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.Parse(response)
	if err != nil || !bytes.Equal(verified, signed.Content) {
		t.Fatal("OpenSSL verification changed binary envelope bytes", err)
	}
	run("cms", "-decrypt", "-binary", "-inform", "DER", "-in", "envelope.der", "-recip", "client.pem", "-inkey", "client.key", "-out", "issued.der")
	issued, err := os.ReadFile(filepath.Join(dir, "issued.der"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := scep.CACerts(issued)
	if err != nil || len(certs) != 2 || !bytes.Equal(certs[0].Raw, f.client.Raw) {
		t.Fatal("OpenSSL recovered a different certificate", err)
	}
	if err = os.WriteFile(filepath.Join(dir, "request.csr"), req.csr.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "ra.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ra.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	run("cms", "-encrypt", "-binary", "-aes256", "-in", "request.csr", "-outform", "DER", "-out", "request-envelope.der", "ra.pem")
	envelope, err := os.ReadFile(filepath.Join(dir, "request-envelope.der"))
	if err != nil {
		t.Fatal(err)
	}
	request := testSCEPWire(t, f, req.csr, scepWireOptions{changeEnvelope: func([]byte) []byte { return envelope }})
	if _, err = parseSCEPRequest(request, f.ra, f.raKey, time.Now()); err != nil {
		t.Fatal("OpenSSL AES-256 request rejected", err)
	}
}

func TestSCEPDERResourceLimits(t *testing.T) {
	data := []byte{5, 0}
	for range 30 {
		var err error
		data, err = asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: data})
		if err != nil {
			t.Fatal(err)
		}
	}
	if boundSCEPDER(data) == nil {
		t.Fatal("excessive nesting accepted")
	}
	data, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Repeat([]byte{5, 0}, 4097)})
	if err != nil {
		t.Fatal(err)
	}
	if boundSCEPDER(data) == nil {
		t.Fatal("excessive node count accepted")
	}
}

func rewriteSCEPDER(t *testing.T, data []byte, change func(*asn1.RawValue)) []byte {
	t.Helper()
	var output []byte
	for len(data) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(data, &v)
		if err != nil {
			t.Fatal(err)
		}
		v.FullBytes = nil
		if v.IsCompound {
			v.Bytes = rewriteSCEPDER(t, v.Bytes, change)
		}
		change(&v)
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, der...)
		data = rest
	}
	return output
}

func TestSCEPRejectsCiphertextAndWeakEnvelopeBeforeDecryption(t *testing.T) {
	f := testSCEPFixture(t)
	csr := testSCEPCSR(t, f.clientKey, "challenge")
	for _, tc := range []struct {
		name   string
		change func(*asn1.RawValue)
	}{
		{"partial CBC block", func(v *asn1.RawValue) {
			if v.Class == asn1.ClassContextSpecific && !v.IsCompound && len(v.Bytes) > 512 {
				v.Bytes = v.Bytes[:len(v.Bytes)-1]
			}
		}},
		{"empty CBC ciphertext", func(v *asn1.RawValue) {
			if v.Class == asn1.ClassContextSpecific && !v.IsCompound && len(v.Bytes) > 512 {
				v.Bytes = nil
			}
		}},
		{"weak DES cipher", func(v *asn1.RawValue) {
			if v.Tag == asn1.TagOID && v.Class == asn1.ClassUniversal {
				var oid asn1.ObjectIdentifier
				der, _ := asn1.Marshal(*v)
				_, _ = asn1.Unmarshal(der, &oid)
				if oid.Equal(pkcs7.OIDEncryptionAlgorithmAES128CBC) {
					raw, _ := asn1.Marshal(pkcs7.OIDEncryptionAlgorithmDESCBC)
					_, _ = asn1.Unmarshal(raw, v)
				}
			}
		}},
		{"invalid RSA transport", func(v *asn1.RawValue) {
			if v.Class == asn1.ClassUniversal && v.Tag == asn1.TagOctetString && len(v.Bytes) == 256 {
				v.Bytes = make([]byte, 256)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := testSCEPWire(t, f, csr, scepWireOptions{changeEnvelope: func(data []byte) []byte { return rewriteSCEPDER(t, data, tc.change) }})
			if _, err := parseSCEPRequest(wire, f.ra, f.raKey, time.Now()); !errors.Is(err, errSCEPMessage) {
				t.Fatal("unsafe envelope accepted", err)
			}
		})
	}
	k := scepSessionDecrypter{PrivateKey: f.raKey, size: 16}
	first, err := k.Decrypt(rand.Reader, make([]byte, 256), nil)
	if err != nil || len(first) != 16 {
		t.Fatal("RSA padding exposed", err)
	}
	second, err := k.Decrypt(rand.Reader, make([]byte, 256), nil)
	if err != nil || len(second) != 16 || bytes.Equal(first, second) {
		t.Fatal("invalid padding did not produce fresh random session key", err)
	}
}

func TestSCEPChallengeAttributesAreUnambiguous(t *testing.T) {
	f := testSCEPFixture(t)
	csr := testSCEPCSR(t, f.clientKey, "challenge")
	type csrInfo struct {
		Version    int
		Subject    asn1.RawValue
		Key        asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}
	type csrEnvelope struct {
		Info      csrInfo
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	for _, mode := range []string{"duplicate", "multiple values", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			var request csrEnvelope
			if _, err := asn1.Unmarshal(csr.Raw, &request); err != nil {
				t.Fatal(err)
			}
			if len(request.Info.Attributes) != 1 {
				t.Fatal("unexpected CSR attributes")
			}
			if mode == "duplicate" {
				request.Info.Attributes = append(request.Info.Attributes, request.Info.Attributes[0])
			} else {
				values := []string{"challenge", "second"}
				if mode == "oversized" {
					values = []string{strings.Repeat("a", 129)}
				}
				attribute := struct {
					Type   asn1.ObjectIdentifier
					Values []string `asn1:"set"`
				}{scepChallengeOID, values}
				raw, err := asn1.Marshal(attribute)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = asn1.Unmarshal(raw, &request.Info.Attributes[0]); err != nil {
					t.Fatal(err)
				}
			}
			info, err := asn1.Marshal(request.Info)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(info)
			signature, err := rsa.SignPKCS1v15(rand.Reader, f.clientKey, crypto.SHA256, hash[:])
			if err != nil {
				t.Fatal(err)
			}
			request.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
			der, err := asn1.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatal(err)
			}
			if err = changed.CheckSignature(); err != nil {
				t.Fatal("test CSR proof is invalid", err)
			}
			if _, err = parseSCEPRequest(testSCEPWire(t, f, changed, scepWireOptions{}), f.ra, f.raKey, time.Now()); !errors.Is(err, errSCEPMessage) {
				t.Fatal("ambiguous challenge accepted", err)
			}
		})
	}
}

func TestSCEPResponseDoesNotEncryptToUntrustedExtraCertificate(t *testing.T) {
	f := testSCEPFixture(t)
	wire := testSCEPWire(t, f, testSCEPCSR(t, f.clientKey, "challenge"), scepWireOptions{changeSigned: func(s *pkcs7.SignedData) { s.AddCertificate(f.ra) }})
	request, err := parseSCEPRequest(wire, f.ra, f.raKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err := request.response(f.ra, f.raKey, f.ca, f.client, scep.BadRequest)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(response)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := pkcs7.Parse(p7.Content)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = envelope.Decrypt(f.ra, f.raKey); err == nil {
		t.Fatal("extra certificate received issued identity")
	}
	if _, err = envelope.Decrypt(f.client, f.clientKey); err != nil {
		t.Fatal("authenticated signer cannot decrypt", err)
	}
}

func FuzzSCEPStructuralParsers(f *testing.F) {
	f.Add([]byte{0x30, 0})
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if boundSCEPDER(data) != nil {
			return
		}
		_ = validateSCEPEnvelope(data)
		_, _ = scepChallenge(data)
	})
}

func FuzzSCEPRequestParsing(f *testing.F) {
	fixture := testSCEPFixture(f)
	csr := testSCEPCSR(f, fixture.clientKey, "challenge")
	f.Add(testSCEPWire(f, fixture, csr, scepWireOptions{}))
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseSCEPRequest(data, fixture.ra, fixture.raKey, time.Now()) })
}
