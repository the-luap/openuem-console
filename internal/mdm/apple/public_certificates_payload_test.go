package apple

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func publicCertificateFixture(t *testing.T, serial int64, ca bool, start, end time.Time) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Synthetic certificate"}, NotBefore: start, NotAfter: end, BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		certificate.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPublicCertificateParsingAndPayloadSeparation(t *testing.T) {
	now := time.Now()
	first := publicCertificateFixture(t, 1, true, now.Add(-time.Hour), now.Add(time.Hour))
	second := publicCertificateFixture(t, 2, false, now.Add(-time.Hour), now.Add(time.Hour))
	encode := func(data []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}) }
	bundle := append(append(encode(first), encode(second)...), encode(first)...)
	p := map[string]any{"PayloadIdentifier": "com.example.certificates.settings", "PayloadUUID": "first-uuid", "PayloadVersion": 1, "PayloadDisplayName": "Certificates"}
	extra, err := buildPublicCertificatePayload(p, map[string]any{"CertificateData": bundle}, "System")
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) != 1 || !bytes.Equal(p["PayloadContent"].([]byte), first) {
		t.Fatal("certificate bundle was not split and deduplicated")
	}
	other := extra[0].(map[string]any)
	if !bytes.Equal(other["PayloadContent"].([]byte), second) || other["PayloadUUID"] == p["PayloadUUID"] || other["PayloadIdentifier"] == p["PayloadIdentifier"] {
		t.Fatal("separate certificate lost its identity")
	}
	for _, payload := range []map[string]any{p, other} {
		if payload["PayloadType"] != "com.apple.security.pkcs1" || validatePublicCertificatePayload(payload, "System", nil) != nil {
			t.Fatal("invalid certificate payload generated")
		}
	}
	if certs, err := parsePublicCertificates(append(append([]byte{}, first...), second...), false); err != nil || len(certs) != 2 {
		t.Fatal("DER bundle rejected", err)
	}
	for _, data := range [][]byte{nil, []byte("not a certificate"), bytes.Repeat([]byte("x"), MaxPublicCertificateBytes+1), append([]byte("unexpected preamble\n"), bundle...), append(bundle, []byte("unexpected trailer")...), append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic")})...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Comment": "unexpected"}, Bytes: first}), bytes.Repeat(encode(first), 17)} {
		if _, err := parsePublicCertificates(data, false); err == nil {
			t.Fatal("malformed or private certificate input accepted")
		}
	}
	if _, err := parsePublicCertificates(first, true); err == nil {
		t.Fatal("DER accepted in PEM payload")
	}
	if _, err := buildPublicCertificatePayload(map[string]any{}, map[string]any{"CertificateData": "not binary"}, "System"); err == nil {
		t.Fatal("nonbinary upload accepted")
	}
}

func TestPublicCertificateScopeValidityAndDataTypes(t *testing.T) {
	now := time.Now()
	der := publicCertificateFixture(t, 1, true, now.Add(-time.Hour), now.Add(time.Hour))
	for _, kind := range []string{"com.apple.security.pkcs1", "com.apple.security.root", "com.apple.security.pem"} {
		data := der
		if kind == "com.apple.security.pem" {
			data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		p := map[string]any{"PayloadType": kind, "PayloadContent": data}
		for _, test := range []struct {
			model, version, scope string
			invalid               bool
		}{{"Mac16,1", "10.7", "System", false}, {"Mac16,1", "10.7", "User", false}, {"Mac16,1", "10.6", "System", true}, {"iPhone16,1", "4.0", "System", false}, {"iPad16,1", "18.0", "System", false}, {"iPhone16,1", "18.0", "User", true}, {"iPhone16,1", "3.2", "System", true}, {"unknown", "18.0", "System", true}, {"Mac16,1", "unknown", "System", true}} {
			if err := validatePublicCertificatePayload(p, test.scope, &Device{Model: test.model, OSVersion: test.version}); (err != nil) != test.invalid {
				t.Fatal("certificate platform boundary", kind, test, err)
			}
		}
		for _, invalid := range []any{true, "base64 text", nil} {
			p["PayloadContent"] = invalid
			if err := validatePublicCertificatePayload(p, "System", nil); err == nil {
				t.Fatal("nonbinary certificate accepted")
			}
		}
		p["PayloadContent"] = data
		p["PayloadCertificateFileName"] = "bad\x00name"
		if err := validatePublicCertificatePayload(p, "System", nil); err == nil {
			t.Fatal("invalid certificate filename accepted")
		}
	}
	for _, dates := range [][2]time.Time{{now.Add(-2 * time.Hour), now.Add(-time.Hour)}, {now.Add(time.Hour), now.Add(2 * time.Hour)}} {
		p := map[string]any{"PayloadType": "com.apple.security.pkcs1", "PayloadContent": publicCertificateFixture(t, 2, false, dates[0], dates[1])}
		if err := validatePublicCertificatePayload(p, "System", nil); err != nil {
			t.Fatal("catalog cannot retain a future or expired certificate", err)
		}
		if err := validatePublicCertificatePayload(p, "System", &Device{Model: "Mac16,1", OSVersion: "15.0"}); err == nil {
			t.Fatal("certificate validity ignored during assignment")
		}
	}
	p := map[string]any{"PayloadType": "com.apple.security.pkcs1", "PayloadContent": append(append([]byte{}, der...), der...)}
	if err := validatePublicCertificatePayload(p, "System", nil); err == nil {
		t.Fatal("multiple DER certificates accepted in a single certificate payload")
	}
}
