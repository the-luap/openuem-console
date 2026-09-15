package windows

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

type renewalTestRequestInfo struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes []renewalAttribute `asn1:"set,tag:0"`
}

type renewalTestCSRWire struct {
	Info      asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

func renewalTestCertificate(t testing.TB, key crypto.Signer) *x509.Certificate {
	t.Helper()
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic renewal signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func renewalTestCSR(t testing.TB, key *rsa.PrivateKey, existingDER []byte, change func(*renewalTestRequestInfo)) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-new-subject"}, DNSNames: []string{"untrusted.example.test"}, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		t.Fatal(err)
	}
	var wire renewalTestCSRWire
	var info renewalTestRequestInfo
	if !renewalASN1(der, &wire) || !renewalASN1(wire.Info.FullBytes, &info) {
		t.Fatal("invalid synthetic CSR")
	}
	info.Attributes = append(info.Attributes, renewalAttribute{Type: renewalOIDCertificate, Values: asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: existingDER}})
	if change != nil {
		change(&info)
	}
	data, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	wire.Info = asn1.RawValue{FullBytes: data}
	wire.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, err = asn1.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The established PKCS#7 library supplies the independent CMS encoder. All keys
// and certificates are ephemeral fixtures; nothing enters a host certificate store.
func renewalTestCMS(t testing.TB, csr []byte, cert *x509.Certificate, key crypto.Signer, digest asn1.ObjectIdentifier, attributes bool) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(csr)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(digest)
	if attributes {
		err = sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{})
	} else {
		err = sd.SignWithoutAttr(cert, key, pkcs7.SignerInfoConfig{})
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func renewalTestChange(t testing.TB, data []byte, change func(*renewalSignedData)) []byte {
	t.Helper()
	data = bytes.Clone(data)
	var outer renewalContentInfo
	var sd renewalSignedData
	if !renewalASN1(data, &outer) || !renewalASN1(outer.Content.Bytes, &sd) {
		t.Fatal("invalid synthetic CMS")
	}
	change(&sd)
	inner, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	outer.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner}
	der, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestWindowsRenewalProofBindsBothKeysAndExactCertificate(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	cert := renewalTestCertificate(t, oldKey)
	for _, key := range []*rsa.PrivateKey{oldKey, newKey} {
		csr := renewalTestCSR(t, key, cert.Raw, nil)
		for _, digest := range []asn1.ObjectIdentifier{pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA384, pkcs7.OIDDigestAlgorithmSHA512} {
			for _, attributes := range []bool{false, true} {
				wire := renewalTestCMS(t, csr, cert, oldKey, digest, attributes)
				proof, err := VerifyWindowsRenewalProof(wire, cert.Raw, key.N.BitLen())
				if err != nil || !bytes.Equal(proof.CSR.Raw, csr) || !proof.CSR.PublicKey.(*rsa.PublicKey).Equal(&key.PublicKey) || proof.CertificateSHA256 != sha256.Sum256(cert.Raw) {
					t.Fatal("valid renewal continuity rejected", digest, attributes, err)
				}
				// Names remain untrusted input; only the later issuing transaction
				// may derive the device subject from its existing enrollment.
				if proof.CSR.Subject.CommonName != "untrusted-new-subject" {
					t.Fatal("proof rewrote the signed CSR")
				}
				encoded, err := json.Marshal(proof)
				if err != nil || string(encoded) != "{}" || strings.Contains(fmt.Sprintf("%v %+v %#v", proof, proof, proof), "untrusted-new-subject") {
					t.Fatal("renewal proof formatting exposed input")
				}
				if result, err := VerifyWindowsRenewalProof(wire, cert.Raw, 4096); !errors.Is(err, ErrRenewalProof) || result != nil {
					t.Fatal("new-key policy floor ignored")
				}
			}
		}
	}
	csr := renewalTestCSR(t, newKey, cert.Raw, nil)
	base := renewalTestCMS(t, csr, cert, oldKey, pkcs7.OIDDigestAlgorithmSHA256, true)
	for name, change := range map[string]func(*renewalSignedData){
		"no signer":           func(s *renewalSignedData) { s.Signers = nil },
		"multiple signers":    func(s *renewalSignedData) { s.Signers = append(s.Signers, s.Signers[0]) },
		"version":             func(s *renewalSignedData) { s.Version = 3 },
		"signer version":      func(s *renewalSignedData) { s.Signers[0].Version = 3 },
		"missing certificate": func(s *renewalSignedData) { s.Certificates = asn1.RawValue{} },
		"duplicate certificate": func(s *renewalSignedData) {
			s.Certificates.Bytes = append(s.Certificates.Bytes, s.Certificates.Bytes...)
			s.Certificates.FullBytes = nil
		},
		"signer serial":   func(s *renewalSignedData) { s.Signers[0].Issuer.Serial = big.NewInt(2) },
		"signer issuer":   func(s *renewalSignedData) { s.Signers[0].Issuer.Name = asn1.RawValue{FullBytes: []byte{48, 0}} },
		"missing digest":  func(s *renewalSignedData) { s.Digests = nil },
		"digest mismatch": func(s *renewalSignedData) { s.Digests[0].Algorithm = pkcs7.OIDDigestAlgorithmSHA384 },
		"MD5 digest": func(s *renewalSignedData) {
			s.Digests[0].Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
			s.Signers[0].Digest.Algorithm = s.Digests[0].Algorithm
		},
		"signature algorithm mismatch": func(s *renewalSignedData) {
			s.Signers[0].Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
		},
		"signature parameters": func(s *renewalSignedData) {
			s.Signers[0].Algorithm.Parameters = asn1.RawValue{FullBytes: []byte{2, 1, 0}}
		},
		"digest parameters": func(s *renewalSignedData) { s.Signers[0].Digest.Parameters = asn1.RawValue{FullBytes: []byte{2, 1, 0}} },
		"bad signature":     func(s *renewalSignedData) { s.Signers[0].Signature[0] ^= 1 },
		"content type":      func(s *renewalSignedData) { s.Content.Type = renewalOIDSignedData },
		"detached content": func(s *renewalSignedData) {
			s.Content.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{4, 0}}
		},
		"extra content": func(s *renewalSignedData) {
			s.Content.Content.FullBytes = nil
			s.Content.Content.Bytes = append(s.Content.Content.Bytes, 5, 0)
		},
		"duplicate signed attribute": func(s *renewalSignedData) {
			s.Signers[0].Attributes = append(s.Signers[0].Attributes, s.Signers[0].Attributes[0])
		},
		"unsigned attributes": func(s *renewalSignedData) { s.Signers[0].Unsigned = s.Signers[0].Attributes[:1] },
		"missing content attribute": func(s *renewalSignedData) {
			for i, a := range s.Signers[0].Attributes {
				if a.Type.Equal(renewalOIDContent) {
					s.Signers[0].Attributes = append(s.Signers[0].Attributes[:i], s.Signers[0].Attributes[i+1:]...)
					break
				}
			}
		},
		"bad content digest": func(s *renewalSignedData) {
			for i, a := range s.Signers[0].Attributes {
				if a.Type.Equal(renewalOIDDigest) {
					s.Signers[0].Attributes[i].Values.FullBytes = nil
					s.Signers[0].Attributes[i].Values.Bytes = []byte{4, 1, 0}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := VerifyWindowsRenewalProof(renewalTestChange(t, base, change), cert.Raw, 2048); !errors.Is(err, ErrRenewalProof) || result != nil {
				t.Fatal("invalid renewal envelope accepted", err)
			}
		})
	}
	if _, err := VerifyWindowsRenewalProof(base, cert.Raw, 2048); err != nil {
		t.Fatal("corruption cases modified their original fixture", err)
	}
	// Extra certificates may accompany CMS, but none broadens the pinned signer.
	certificates := bytes.Clone(cert.Raw)
	for n := 2; n <= 9; n++ {
		template := *cert
		template.SerialNumber = big.NewInt(int64(n))
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &oldKey.PublicKey, oldKey)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, der...)
		wire := renewalTestChange(t, base, func(s *renewalSignedData) {
			s.Certificates = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certificates}
		})
		proof, err := VerifyWindowsRenewalProof(wire, cert.Raw, 2048)
		if n <= 8 && (err != nil || proof == nil) {
			t.Fatal("bounded certificate bag rejected", n, err)
		}
		if n == 9 && (err == nil || proof != nil) {
			t.Fatal("unbounded certificate bag accepted")
		}
	}
	var extraOuter renewalContentInfo
	var extraInner asn1.RawValue
	if !renewalASN1(base, &extraOuter) || !renewalASN1(extraOuter.Content.Bytes, &extraInner) {
		t.Fatal("invalid extra-field fixture")
	}
	extraInner.FullBytes = nil
	extraInner.Bytes = append(bytes.Clone(extraInner.Bytes), 5, 0)
	extra, err := asn1.Marshal(extraInner)
	if err != nil {
		t.Fatal(err)
	}
	extraOuter.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: extra}
	extra, err = asn1.Marshal(extraOuter)
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := VerifyWindowsRenewalProof(extra, cert.Raw, 2048); err == nil || proof != nil {
		t.Fatal("unknown SignedData fields were ignored")
	}
	for _, data := range [][]byte{nil, make([]byte, MaxWindowsRenewalProofBytes+1), append(bytes.Clone(base), 0), csr, []byte("-----BEGIN PKCS7-----")} {
		if result, err := VerifyWindowsRenewalProof(data, cert.Raw, 2048); err == nil || result != nil {
			t.Fatal("invalid proof boundary accepted")
		}
	}
	other := renewalTestCertificate(t, newKey)
	if result, err := VerifyWindowsRenewalProof(base, other.Raw, 2048); err == nil || result != nil {
		t.Fatal("embedded signer replaced the pinned existing certificate")
	}
	for _, digest := range []asn1.ObjectIdentifier{pkcs7.OIDDigestAlgorithmSHA1} {
		if result, err := VerifyWindowsRenewalProof(renewalTestCMS(t, csr, cert, oldKey, digest, true), cert.Raw, 2048); err == nil || result != nil {
			t.Fatal("legacy renewal signature accepted")
		}
	}
	for name, change := range map[string]func(*renewalTestRequestInfo){
		"missing renewal attribute": func(i *renewalTestRequestInfo) { i.Attributes = i.Attributes[:1] },
		"duplicate renewal attribute": func(i *renewalTestRequestInfo) {
			i.Attributes = append(i.Attributes, i.Attributes[len(i.Attributes)-1])
		},
		"different renewal certificate": func(i *renewalTestRequestInfo) { i.Attributes[len(i.Attributes)-1].Values.Bytes = other.Raw },
		"octet-wrapped renewal certificate": func(i *renewalTestRequestInfo) {
			i.Attributes[len(i.Attributes)-1].Values.Bytes, _ = asn1.Marshal(cert.Raw)
		},
		"extra renewal value": func(i *renewalTestRequestInfo) {
			i.Attributes[len(i.Attributes)-1].Values.Bytes = append(bytes.Clone(cert.Raw), 5, 0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := renewalTestCSR(t, newKey, cert.Raw, change)
			wire := renewalTestCMS(t, invalid, cert, oldKey, pkcs7.OIDDigestAlgorithmSHA256, true)
			if result, err := VerifyWindowsRenewalProof(wire, cert.Raw, 2048); err == nil || result != nil {
				t.Fatal("signed CSR did not identify its renewing certificate")
			}
		})
	}
	badCSR := bytes.Clone(csr)
	badCSR[len(badCSR)-1] ^= 1
	if result, err := VerifyWindowsRenewalProof(renewalTestCMS(t, badCSR, cert, oldKey, pkcs7.OIDDigestAlgorithmSHA256, true), cert.Raw, 2048); err == nil || result != nil {
		t.Fatal("old-key signature substituted for new-key proof")
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "unsupported new key"}}, ec)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := VerifyWindowsRenewalProof(renewalTestCMS(t, ecCSR, cert, oldKey, pkcs7.OIDDigestAlgorithmSHA256, true), cert.Raw, 2048); err == nil || result != nil {
		t.Fatal("unsupported new key admitted")
	}
}

func TestWindowsRenewalDERResourceBounds(t *testing.T) {
	wrap := func(data []byte) []byte {
		t.Helper()
		der, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: data})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for name, data := range map[string][]byte{"indefinite": {48, 128, 0, 0}, "nonminimal length": {4, 129, 1, 0}, "leading zero length": {4, 130, 0, 128}, "long length": {4, 132, 0, 0, 1, 0}, "truncated": {48, 3, 5, 0}, "high tag": {31, 1, 0}, "end of contents": {0, 0}} {
		if boundedRenewalDER(data) {
			t.Fatal("invalid DER boundary accepted", name)
		}
	}
	nested := []byte{5, 0}
	for n := 1; n <= 17; n++ {
		nested = wrap(nested)
		if boundedRenewalDER(nested) != (n <= 16) {
			t.Fatal("DER depth bound incorrect", n)
		}
	}
	if !boundedRenewalDER(wrap(bytes.Repeat([]byte{5, 0}, 2047))) || boundedRenewalDER(wrap(bytes.Repeat([]byte{5, 0}, 2048))) {
		t.Fatal("DER node bound incorrect")
	}
}

func TestWindowsRenewalProofUsesExistingEnrolledIdentityWithoutIssuing(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	i, request, key := enrollmentTestRequest(t, s)
	if _, err := s.EnrollWindows(context.Background(), request, enrollmentTestOptions()); err != nil {
		t.Fatal(err)
	}
	before := readEnrollmentTestResult(t, s, i.ID)
	cert, err := x509.ParseCertificate(before.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr := renewalTestCSR(t, newKey, cert.Raw, nil)
	proof, err := VerifyWindowsRenewalProof(renewalTestCMS(t, csr, cert, key, pkcs7.OIDDigestAlgorithmSHA256, true), cert.Raw, 2048)
	if err != nil || proof.CertificateSHA256 != sha256.Sum256(before.Certificate) {
		t.Fatal("stored enrollment certificate could not prove renewal continuity", err)
	}
	after := readEnrollmentTestResult(t, s, i.ID)
	if before.DeviceID != after.DeviceID || !bytes.Equal(before.Auth, after.Auth) || !bytes.Equal(before.Certificate, after.Certificate) {
		t.Fatal("proof verification changed enrollment")
	}
	assertEnrollmentCounts(t, s, 1)
}

func FuzzWindowsRenewalProof(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	cert := renewalTestCertificate(f, key)
	csr := renewalTestCSR(f, key, cert.Raw, nil)
	f.Add(renewalTestCMS(f, csr, cert, key, pkcs7.OIDDigestAlgorithmSHA256, true), cert.Raw)
	f.Add([]byte{48, 128, 0, 0}, cert.Raw)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, data, existing []byte) {
		proof, err := VerifyWindowsRenewalProof(data, existing, 2048)
		if err == nil && (proof == nil || proof.CSR == nil || len(proof.CSR.Raw) > MaxEnrollmentCSRBytes || proof.CSR.CheckSignature() != nil || proof.CertificateSHA256 != sha256.Sum256(existing)) {
			t.Fatal("accepted proof lost its invariants")
		}
		if err != nil && proof != nil {
			t.Fatal("failed proof returned identity")
		}
	})
}
