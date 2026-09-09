package ade

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"
)

func machineTestIdentity(t testing.TB) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic device issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)}
	issuer = machineTestCertificate(t, issuer, issuer, &issuerKey.PublicKey, issuerKey)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic device"}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: issuer.NotBefore, NotAfter: issuer.NotAfter}
	return issuer, issuerKey, machineTestCertificate(t, leaf, issuer, &leafKey.PublicKey, issuerKey), leafKey
}

func machineTestCertificate(t testing.TB, template, parent *x509.Certificate, public any, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func machineTestFields() map[string]any {
	return map[string]any{"UDID": "00000000-0000-4000-8000-000000000001", "SERIAL": "SYNTHETIC123", "PRODUCT": "Mac14,8", "VERSION": "25A100", "OS_VERSION": "26.0", "LANGUAGE": "en", "MDM_CAN_REQUEST_PSSO_CONFIG": true, "MDM_CAN_REQUEST_SOFTWARE_UPDATE": true, "MANDATORY_SOFTWARE_UPDATE_REQUIRED": false}
}

func machineTestPlist(t testing.TB, format int) []byte {
	t.Helper()
	b, err := plist.Marshal(machineTestFields(), format)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func machineTestSigned(t testing.TB, plain []byte, leaf *x509.Certificate, key crypto.Signer, digest asn1.ObjectIdentifier, attributes bool) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(plain)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(digest)
	if attributes {
		err = sd.AddSigner(leaf, key, pkcs7.SignerInfoConfig{})
	} else {
		err = sd.SignWithoutAttr(leaf, key, pkcs7.SignerInfoConfig{})
	}
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func machineTestChange(t *testing.T, wire []byte, change func(*machineSignedData), key crypto.Signer) []byte {
	t.Helper()
	der, err := machineDER(wire)
	if err != nil {
		t.Fatal(err)
	}
	var outer machineContentInfo
	var sd machineSignedData
	if !machineASN1(der, &outer) || !machineASN1(outer.Content.Bytes, &sd) {
		t.Fatal("invalid test CMS")
	}
	change(&sd)
	if key != nil {
		s := &sd.Signers[0]
		signed, err := asn1.MarshalWithParams(s.Attributes, "set")
		if err != nil {
			t.Fatal(err)
		}
		hash, _ := machineAlgorithms(s.Digest.Algorithm.String(), s.Algorithm.Algorithm.String())
		h := hash.New()
		h.Write(signed)
		s.Signature, err = key.Sign(rand.Reader, h.Sum(nil), hash)
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	outer.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: b}
	b, err = asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMachineInfoSignedIdentityAndCompatibility(t *testing.T) {
	issuer, issuerKey, leaf, key := machineTestIdentity(t)
	for _, digest := range []asn1.ObjectIdentifier{pkcs7.OIDDigestAlgorithmSHA1, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA384, pkcs7.OIDDigestAlgorithmSHA512} {
		for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
			for _, attributes := range []bool{false, true} {
				wire := machineTestSigned(t, machineTestPlist(t, format), leaf, key, digest, attributes)
				info, err := verifyMachineInfo(wire, issuer)
				if err != nil {
					t.Fatalf("valid expired-issuer fixture: %v / %d / %t: %v", digest, format, attributes, err)
				}
				if info.Serial != "SYNTHETIC123" || info.Product != "Mac14,8" || !info.CanRequestPSSO || !info.CanRequestSoftwareUpdate || len(info.SignerFingerprint) != 64 || attributes == info.SignedAt.IsZero() {
					t.Fatal("verified metadata missing")
				}
				if strings.Contains(fmt.Sprintf("%v %#v", info, info), "SYNTHETIC") {
					t.Fatal("diagnostics exposed device identity")
				}
				if _, err := VerifyMachineInfo(wire); !errors.Is(err, ErrMachineInfo) {
					t.Fatal("production trust accepted synthetic issuer")
				}
				// Apple's CMS commonly uses an indefinite outer sequence.
				var raw asn1.RawValue
				if !machineASN1(wire, &raw) {
					t.Fatal("invalid test envelope")
				}
				ber := append([]byte{0x30, 0x80}, raw.Bytes...)
				ber = append(ber, 0, 0)
				if _, err := verifyMachineInfo(ber, issuer); err != nil {
					t.Fatal("valid indefinite BER rejected", err)
				}
			}
		}
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaLeaf := machineTestCertificate(t, leaf, issuer, &ecdsaKey.PublicKey, issuerKey)
	for _, digest := range []asn1.ObjectIdentifier{pkcs7.OIDDigestAlgorithmSHA1, pkcs7.OIDDigestAlgorithmSHA256, pkcs7.OIDDigestAlgorithmSHA384, pkcs7.OIDDigestAlgorithmSHA512} {
		wire := machineTestSigned(t, machineTestPlist(t, plist.BinaryFormat), ecdsaLeaf, ecdsaKey, digest, true)
		if _, err := verifyMachineInfo(wire, issuer); err != nil {
			t.Fatal("valid ECDSA rejected", err)
		}
	}
}

func TestMachineInfoRejectsForgedAndAmbiguousCMS(t *testing.T) {
	issuer, issuerKey, leaf, key := machineTestIdentity(t)
	wire := machineTestSigned(t, machineTestPlist(t, plist.XMLFormat), leaf, key, pkcs7.OIDDigestAlgorithmSHA256, true)
	for name, change := range map[string]func(*machineSignedData){
		"multiple signers": func(s *machineSignedData) { s.Signers = append(s.Signers, s.Signers[0]) },
		"missing signer":   func(s *machineSignedData) { s.Signers = nil },
		"duplicate certificate": func(s *machineSignedData) {
			s.Certificates.FullBytes = nil
			s.Certificates.Bytes = append(s.Certificates.Bytes, s.Certificates.Bytes...)
		},
		"missing certificate": func(s *machineSignedData) { s.Certificates = asn1.RawValue{} },
		"wrong signer":        func(s *machineSignedData) { s.Signers[0].Issuer.Serial = big.NewInt(999) },
		"wrong version":       func(s *machineSignedData) { s.Version = 3 },
		"wrong content type":  func(s *machineSignedData) { s.Content.Type = machineOIDSignedData },
		"missing digest":      func(s *machineSignedData) { s.Digests = nil },
		"mismatched digest":   func(s *machineSignedData) { s.Digests[0].Algorithm = pkcs7.OIDDigestAlgorithmSHA1 },
		"mismatched algorithm": func(s *machineSignedData) {
			s.Signers[0].Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
		},
		"bad signature": func(s *machineSignedData) { s.Signers[0].Signature[0] ^= 1 },
		"trailing content": func(s *machineSignedData) {
			s.Content.Content.FullBytes = nil
			s.Content.Content.Bytes = append(s.Content.Content.Bytes, 5, 0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := machineTestChange(t, wire, change, nil)
			if _, err := verifyMachineInfo(bad, issuer); !errors.Is(err, ErrMachineInfo) {
				t.Fatal("invalid CMS accepted", err)
			}
		})
	}
	for name, change := range map[string]func(*machineSignedData){
		"duplicate signed attribute": func(s *machineSignedData) {
			s.Signers[0].Attributes = append(s.Signers[0].Attributes, s.Signers[0].Attributes[0])
		},
		"missing content attribute": func(s *machineSignedData) {
			for i, a := range s.Signers[0].Attributes {
				if a.Type.Equal(machineOIDContent) {
					s.Signers[0].Attributes = append(s.Signers[0].Attributes[:i], s.Signers[0].Attributes[i+1:]...)
					break
				}
			}
		},
		"multiple content values": func(s *machineSignedData) {
			for i, a := range s.Signers[0].Attributes {
				if a.Type.Equal(machineOIDContent) {
					s.Signers[0].Attributes[i].Value.FullBytes = nil
					s.Signers[0].Attributes[i].Value.Bytes = append(a.Value.Bytes, a.Value.Bytes...)
				}
			}
		},
		"different signed content type": func(s *machineSignedData) {
			for i, a := range s.Signers[0].Attributes {
				if a.Type.Equal(machineOIDContent) {
					v, _ := asn1.Marshal(machineOIDSignedData)
					s.Signers[0].Attributes[i].Value = asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: v}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Re-sign each malformed set to distinguish structural rejection from
			// a trivially broken cryptographic signature.
			bad := machineTestChange(t, wire, change, key)
			if _, err := verifyMachineInfo(bad, issuer); !errors.Is(err, ErrMachineInfo) {
				t.Fatal("ambiguous signed attributes accepted", err)
			}
		})
	}
	for name, change := range map[string]func(*x509.Certificate){
		"CA leaf":         func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true },
		"wrong key usage": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"unknown critical extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			template := *leaf
			change(&template)
			badLeaf := machineTestCertificate(t, &template, issuer, &key.PublicKey, issuerKey)
			bad := machineTestSigned(t, machineTestPlist(t, plist.XMLFormat), badLeaf, key, pkcs7.OIDDigestAlgorithmSHA256, true)
			if _, err := verifyMachineInfo(bad, issuer); !errors.Is(err, ErrMachineInfo) {
				t.Fatal("invalid identity certificate accepted")
			}
		})
	}
	other, _, _, _ := machineTestIdentity(t)
	if _, err := verifyMachineInfo(wire, other); !errors.Is(err, ErrMachineInfo) {
		t.Fatal("same-name foreign issuer accepted")
	}
	for _, bad := range [][]byte{nil, wire[:len(wire)-1], append(bytes.Clone(wire), 0), append(bytes.Clone(wire), wire...), bytes.Replace(wire, []byte("SYNTHETIC123"), []byte("SYNTHETIC124"), 1), bytes.Repeat([]byte{0}, MaxMachineInfo+1)} {
		if _, err := verifyMachineInfo(bad, issuer); !errors.Is(err, ErrMachineInfo) {
			t.Fatal("malformed or changed CMS accepted")
		}
	}
}

func TestMachineInfoPlistIdentityTypesAndBounds(t *testing.T) {
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		fields := machineTestFields()
		delete(fields, "OS_VERSION")
		fields["FUTURE_PROPERTY"] = "supported additive scalar"
		b, _ := plist.Marshal(fields, format)
		if _, err := parseMachinePlist(b); err != nil {
			t.Fatal("legacy OS/additive property rejected", err)
		}
		for name, value := range map[string]any{"UDID": "../../", "SERIAL": "lowercase", "PRODUCT": 1, "VERSION": "", "OS_VERSION": false, "MDM_CAN_REQUEST_PSSO_CONFIG": "true", "FUTURE_PROPERTY": map[string]any{"nested": true}} {
			bad := machineTestFields()
			bad[name] = value
			b, _ := plist.Marshal(bad, format)
			if _, err := parseMachinePlist(b); !errors.Is(err, ErrMachineInfo) {
				t.Fatalf("invalid property %s accepted in format %d", name, format)
			}
		}
	}
	xmlWire := machineTestPlist(t, plist.XMLFormat)
	for _, bad := range [][]byte{
		bytes.Replace(xmlWire, []byte("</dict>"), []byte("<key>SERIAL</key><string>OTHER123</string></dict>"), 1),
		bytes.Replace(xmlWire, []byte("<key>SERIAL</key>"), []byte("<key>SERIAL</key><dict><key>value</key><string>OTHER123</string></dict>"), 1),
		bytes.Replace(xmlWire, []byte("<string>SYNTHETIC123</string>"), []byte("<string>&undefined;</string>"), 1),
		append(bytes.Clone(xmlWire), []byte("<dict/>")...),
		bytes.Replace(xmlWire, []byte("version=\"1.0\"><dict>"), []byte("version=\"1.0\" extra=\"true\"><dict>"), 1),
		bytes.Repeat([]byte{'x'}, maxMachinePlist+1),
	} {
		if bytes.Equal(bad, xmlWire) {
			continue
		}
		if _, err := parseMachinePlist(bad); !errors.Is(err, ErrMachineInfo) {
			t.Fatal("ambiguous XML accepted")
		}
	}
	// A top-level binary dictionary referring to itself as a value must never
	// reach a recursive generic plist decoder.
	cycle := append([]byte("bplist00"), 0xd1, 1, 0, 0x51, 'K', 8, 11)
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 1, 1
	binary.BigEndian.PutUint64(trailer[8:16], 2)
	binary.BigEndian.PutUint64(trailer[24:32], 13)
	cycle = append(cycle, trailer...)
	if _, err := parseMachinePlist(cycle); !errors.Is(err, ErrMachineInfo) {
		t.Fatal("binary cycle accepted")
	}
	for _, offset := range []int{6, 7, 8, 16, 24} {
		b := machineTestPlist(t, plist.BinaryFormat)
		b[len(b)-32+offset] = 255
		if _, err := parseMachinePlist(b); !errors.Is(err, ErrMachineInfo) {
			t.Fatal("invalid binary trailer accepted")
		}
	}
}

func TestMachineInfoCMSContentAndTimestampStructure(t *testing.T) {
	issuer, _, leaf, key := machineTestIdentity(t)
	wire := machineTestSigned(t, machineTestPlist(t, plist.XMLFormat), leaf, key, pkcs7.OIDDigestAlgorithmSHA256, true)
	chunked := machineTestChange(t, wire, func(s *machineSignedData) {
		var plain []byte
		if !machineASN1(s.Content.Content.Bytes, &plain) {
			t.Fatal("invalid test content")
		}
		first, _ := asn1.Marshal(plain[:len(plain)/2])
		second, _ := asn1.Marshal(plain[len(plain)/2:])
		chunks, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagOctetString, IsCompound: true, Bytes: append(first, second...)})
		s.Content.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: chunks}
	}, nil)
	if _, err := verifyMachineInfo(chunked, issuer); err != nil {
		t.Fatal("valid chunked CMS content rejected", err)
	}
	noTimestamp := machineTestChange(t, wire, func(s *machineSignedData) {
		for i, a := range s.Signers[0].Attributes {
			if a.Type.Equal(machineOIDTime) {
				s.Signers[0].Attributes = append(s.Signers[0].Attributes[:i], s.Signers[0].Attributes[i+1:]...)
				break
			}
		}
	}, key)
	info, err := verifyMachineInfo(noTimestamp, issuer)
	if err != nil || !info.SignedAt.IsZero() {
		t.Fatal("absent timestamp rejected or invented", err)
	}
	var outer machineContentInfo
	if !machineASN1(wire, &outer) {
		t.Fatal("invalid test wrapper")
	}
	var inner asn1.RawValue
	if !machineASN1(outer.Content.Bytes, &inner) {
		t.Fatal("invalid test SignedData")
	}
	inner.FullBytes = nil
	inner.Bytes = append(inner.Bytes, 5, 0)
	changed, _ := asn1.Marshal(inner)
	outer.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: changed}
	bad, _ := asn1.Marshal(outer)
	if _, err := verifyMachineInfo(bad, issuer); !errors.Is(err, ErrMachineInfo) {
		t.Fatal("extra SignedData field ignored")
	}
	for _, plain := range [][]byte{
		bytes.Repeat([]byte{'x'}, maxMachinePlist+1),
		[]byte(`<plist version="1.0"><dict><key>SERIAL</key><string>A</string></dict></plist>`),
	} {
		bad := machineTestSigned(t, plain, leaf, key, pkcs7.OIDDigestAlgorithmSHA256, true)
		if _, err := verifyMachineInfo(bad, issuer); !errors.Is(err, ErrMachineInfo) {
			t.Fatal("valid signature bypassed plist identity/size validation")
		}
	}
}

func TestMachineInfoExternalProtocolCapture(t *testing.T) {
	path := os.Getenv("APPLE_ADE_MACHINEINFO_FIXTURE")
	if path == "" {
		t.Skip("optional external Apple CMS capture is not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("could not read external CMS fixture")
	}
	info, err := VerifyMachineInfo(data)
	if err != nil || info.Serial == "" || info.UDID == "" || info.SignerFingerprint == "" {
		t.Fatal("external Apple CMS verification failed", err)
	}
}

func FuzzMachineInfoBoundary(f *testing.F) {
	issuer, _, leaf, key := machineTestIdentity(f)
	f.Add(machineTestPlist(f, plist.XMLFormat))
	f.Add(machineTestPlist(f, plist.BinaryFormat))
	f.Add(machineTestSigned(f, machineTestPlist(f, plist.BinaryFormat), leaf, key, pkcs7.OIDDigestAlgorithmSHA256, true))
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add([]byte("bplist00"))
	f.Add([]byte(`<plist version="1.0"><dict><key>SERIAL</key><string>A</string></dict></plist>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMachineInfo+1 {
			return
		}
		info, err := VerifyMachineInfo(data)
		if err == nil && (info == nil || info.SignerFingerprint == "") {
			t.Fatal("unverified identity returned")
		}
		if err != nil && !errors.Is(err, ErrMachineInfo) {
			t.Fatal("decoder details escaped boundary")
		}
		_, _ = verifyMachineInfo(data, issuer)
		if len(data) <= maxMachinePlist {
			_, _ = parseMachinePlist(data)
		}
	})
}
