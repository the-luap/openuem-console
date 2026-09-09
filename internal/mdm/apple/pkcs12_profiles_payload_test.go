package apple

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func pkcs12IdentityFixture(t testing.TB, encoder *pkcs12.Encoder, password string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic identity"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := encoder.Encode(key, cert, []*x509.Certificate{ca}, password)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPKCS12PayloadPreservesOpaqueIdentityAndPassword(t *testing.T) {
	for _, encoder := range []*pkcs12.Encoder{pkcs12.LegacyRC2, pkcs12.Modern2023} {
		for _, password := range []string{"", " synthetic-identity-pässword "} {
			data := pkcs12IdentityFixture(t, encoder, password)
			p := map[string]any{}
			if err := buildPKCS12Payload(p, map[string]any{"IdentityData": data, "Password": password, "KeyIsExtractable": false, "AllowAllAppsAccess": false}, "User"); err != nil {
				t.Fatal(err)
			}
			encoded, err := plist.Marshal(p, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if _, err = plist.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded["Password"] != password || decoded["KeyIsExtractable"] != false || decoded["AllowAllAppsAccess"] != false || !bytes.Equal(decoded["PayloadContent"].([]byte), data) {
				t.Fatal("archive, password or explicit false changed")
			}
			if err = validatePKCS12Payload(decoded, "User", &Device{Model: "Mac16,1", OSVersion: "15.0"}); err != nil {
				t.Fatal(err)
			}
			// Decode only this bounded, locally generated fixture, never an upload.
			if _, _, chain, decodeErr := pkcs12.DecodeChain(decoded["PayloadContent"].([]byte), password); decodeErr != nil || len(chain) != 1 {
				t.Fatal("fixture identity or chain changed", decodeErr)
			}
			decoded["Password"] = "different-password"
			if err = validatePKCS12Payload(decoded, "System", nil); err != nil {
				t.Fatal("envelope check unexpectedly attempted password verification", err)
			}
		}
	}
}

func TestPKCS12ScopeAndMacOnlyOptions(t *testing.T) {
	data := pkcs12IdentityFixture(t, pkcs12.Modern2023, "synthetic")
	base := func() map[string]any {
		return map[string]any{"PayloadType": "com.apple.security.pkcs12", "PayloadContent": data}
	}
	p := base()
	for _, tc := range []struct {
		model, version, scope string
		bad                   bool
	}{
		{"Mac16,1", "10.7", "System", false}, {"Mac16,1", "10.7", "User", false}, {"Mac16,1", "10.6", "System", true},
		{"iPhone16,1", "4.0", "System", false}, {"iPad16,1", "18.0", "System", false}, {"iPhone16,1", "18.0", "User", true},
		{"iPhone16,1", "3.2", "System", true}, {"unknown", "18.0", "System", true}, {"Mac16,1", "unknown", "System", true}, {"Mac16,1", "15.0", "invalid", true},
	} {
		if err := validatePKCS12Payload(p, tc.scope, &Device{Model: tc.model, OSVersion: tc.version}); (err != nil) != tc.bad {
			t.Fatal(tc, err)
		}
	}
	for _, option := range []struct{ key, before, minimum string }{{"KeyIsExtractable", "10.14.6", "10.15"}, {"AllowAllAppsAccess", "10.9.5", "10.10"}} {
		for _, value := range []bool{false, true} {
			p := base()
			p[option.key] = value
			for _, scope := range []string{"System", "User"} {
				if err := validatePKCS12Payload(p, scope, &Device{Model: "Mac16,1", OSVersion: option.before}); err == nil {
					t.Fatal("old Mac accepted option", option.key)
				}
				if err := validatePKCS12Payload(p, scope, &Device{Model: "Mac16,1", OSVersion: option.minimum}); err != nil {
					t.Fatal(err)
				}
			}
			if err := validatePKCS12Payload(p, "System", &Device{Model: "iPhone16,1", OSVersion: "18.0"}); err == nil {
				t.Fatal("Mac option reached phone", option.key)
			}
		}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"PayloadContent", "not binary"}, {"Password", true}, {"Password", strings.Repeat("x", 8193)}, {"Password", "secret\x00value"},
		{"PayloadCertificateFileName", false}, {"PayloadCertificateFileName", ""}, {"KeyIsExtractable", "false"}, {"AllowAllAppsAccess", 0},
	} {
		p := base()
		p[tc.key] = tc.value
		if err := validatePKCS12Payload(p, "System", nil); err == nil {
			t.Fatal("invalid identity setting accepted", tc.key)
		}
	}
	if _, exists := p["Password"]; exists {
		t.Fatal("omitted password changed")
	}
}

func pkcs12TestDER(t *testing.T, value any) []byte {
	t.Helper()
	data, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPKCS12EnvelopeBoundariesAndNoKDF(t *testing.T) {
	data := pkcs12IdentityFixture(t, pkcs12.Modern2023, "synthetic")
	for _, invalid := range [][]byte{nil, []byte("synthetic-private-data"), bytes.Repeat([]byte{0}, MaxPKCS12Bytes+1), data[:len(data)-1], append(append([]byte{}, data...), 0), {0x30, 0x80, 0, 0}} {
		if err := validatePKCS12Envelope(invalid); err == nil {
			t.Fatal("invalid identity envelope accepted")
		}
	}
	root, _ := pkcs12Value(data)
	fields, _ := pkcs12Sequence(root, 2, 3)
	sequence := func(parts ...[]byte) []byte {
		return pkcs12TestDER(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(parts, nil)})
	}
	if err := validatePKCS12Envelope(sequence(pkcs12TestDER(t, 2), fields[1].FullBytes)); err == nil {
		t.Fatal("wrong PFX version accepted")
	}
	if err := validatePKCS12Envelope(sequence(fields[0].FullBytes, fields[1].FullBytes, fields[2].FullBytes, pkcs12TestDER(t, 1))); err == nil {
		t.Fatal("extra PFX field accepted")
	}
	mac, _ := pkcs12Sequence(fields[2], 2, 3)
	// A huge count is deliberately not executed. The integrity bytes are now
	// invalid, which is also intentionally outside this structural check.
	highCost := sequence(fields[0].FullBytes, fields[1].FullBytes, sequence(mac[0].FullBytes, mac[1].FullBytes, pkcs12TestDER(t, int64(1<<62))))
	if err := validatePKCS12Envelope(highCost); err != nil {
		t.Fatal("opaque high-cost envelope rejected", err)
	}
	for _, n := range []int{0, -1} {
		if err := validatePKCS12Envelope(sequence(fields[0].FullBytes, fields[1].FullBytes, sequence(mac[0].FullBytes, mac[1].FullBytes, pkcs12TestDER(t, n)))); err == nil {
			t.Fatal("invalid MAC count accepted")
		}
	}
	_, content, _ := pkcs12Content(fields[1])
	authenticated, _ := pkcs12Value(content.Bytes)
	sections, _ := pkcs12Sequence(authenticated, 1, 64)
	contentInfo := func(oid asn1.ObjectIdentifier, inner []byte) []byte {
		return sequence(pkcs12TestDER(t, oid), pkcs12TestDER(t, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner}))
	}
	dataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	for _, safe := range [][]byte{sequence(), sequence(bytes.Repeat(sections[0].FullBytes, 65)), sequence(contentInfo(asn1.ObjectIdentifier{1, 2, 3}, pkcs12TestDER(t, []byte{1})))} {
		if err := validatePKCS12Envelope(sequence(fields[0].FullBytes, contentInfo(dataOID, pkcs12TestDER(t, safe)))); err == nil {
			t.Fatal("invalid AuthenticatedSafe accepted")
		}
	}
}

func FuzzPKCS12Envelope(f *testing.F) {
	f.Add(pkcs12IdentityFixture(f, pkcs12.Modern2023, "synthetic-fuzz-password"))
	f.Add([]byte{0x30, 0})
	f.Add([]byte("not an archive"))
	f.Fuzz(func(t *testing.T, data []byte) { _ = validatePKCS12Envelope(data) })
}
