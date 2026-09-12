package apple

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

type vendorFixture struct {
	trust    *VendorTrust
	key      *rsa.PrivateKey
	chain    []*x509.Certificate
	chainPEM []byte
	csr      []byte
	now      time.Time
}

func newVendorFixture(t *testing.T) vendorFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vendorKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(template, parent *x509.Certificate, public any, key crypto.Signer) *x509.Certificate {
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
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Apple Root CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 1}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediate := issue(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic vendor intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}, root, &intermediateKey.PublicKey, rootKey)
	leaf := issue(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Synthetic vendor signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, intermediate, &vendorKey.PublicKey, intermediateKey)
	chain := []*x509.Certificate{leaf, intermediate, root}
	var chainPEM []byte
	for _, cert := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	customerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Synthetic customer"}, SignatureAlgorithm: x509.SHA256WithRSA}, customerKey)
	if err != nil {
		t.Fatal(err)
	}
	return vendorFixture{trust: &VendorTrust{root: root, pins: map[string]struct{}{digest(leaf.Raw): {}}}, key: vendorKey, chain: chain, chainPEM: chainPEM, csr: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), now: now}
}

// Construct the documented envelope independently of the production encoder.
func (f vendorFixture) envelope(t *testing.T) []byte {
	t.Helper()
	csr, _ := pem.Decode(f.csr)
	hash := sha256.Sum256(csr.Bytes)
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>PushCertRequestCSR</key><string>%s</string><key>PushCertCertificateChain</key><string>%s</string><key>PushCertSignature</key><string>%s</string></dict></plist>`, base64.StdEncoding.EncodeToString(csr.Bytes), f.chainPEM, base64.StdEncoding.EncodeToString(signature))
	return []byte(base64.StdEncoding.EncodeToString([]byte(data)))
}

func TestVendorPortalFormatAndIndependentSignature(t *testing.T) {
	f := newVendorFixture(t)
	verified, err := f.trust.VerifyPortalRequest(f.csr, f.envelope(t), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Fingerprint != digest(f.chain[0].Raw) || !verified.ExpiresAt.Equal(f.chain[0].NotAfter) {
		t.Fatal("verified metadata does not describe signer")
	}
	signed, err := f.trust.SignVendorPortal(f.csr, f.chainPEM, f.key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(signed.Encoded))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if _, err := plist.Unmarshal(decoded, &fields); err != nil || len(fields) != 3 {
		t.Fatal("output is not the Apple portal plist", err)
	}
	csr, _ := pem.Decode(f.csr)
	if fields["PushCertRequestCSR"] != base64.StdEncoding.EncodeToString(csr.Bytes) || fields["PushCertCertificateChain"] != string(f.chainPEM) {
		t.Fatal("output lost CSR or complete chain")
	}
	signature, err := base64.StdEncoding.DecodeString(fields["PushCertSignature"])
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(csr.Bytes)
	if err := rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Fatal("not a SHA-256/RSA signature over DER", err)
	}
	if !bytes.Equal(verified.Encoded, signed.Encoded) {
		t.Fatal("normalization changed verified content")
	}
	for _, line := range strings.Split(fields["PushCertCertificateChain"], "\n") {
		if !strings.HasPrefix(line, "-----") && len(line) > 64 {
			t.Fatal("PEM wrapping exceeds Apple format")
		}
	}
}

func TestVendorPortalRejectsUntrustedChangedAndMalformedRequests(t *testing.T) {
	f := newVendorFixture(t)
	encoded := f.envelope(t)
	xmlData, _ := base64.StdEncoding.DecodeString(string(encoded))
	mutate := func(old, new string) []byte {
		return []byte(base64.StdEncoding.EncodeToString(bytes.Replace(xmlData, []byte(old), []byte(new), 1)))
	}
	for name, data := range map[string][]byte{
		"raw CSR":          f.csr,
		"raw XML":          xmlData,
		"duplicate key":    mutate("</dict>", "<key>PushCertRequestCSR</key><string>duplicate</string></dict>"),
		"unknown field":    mutate("</dict>", "<key>Injected</key><string>extra</string></dict>"),
		"missing field":    mutate("PushCertRequestCSR", "UnknownCSR"),
		"nested value":     mutate("<string>", "<string><string>nested</string>"),
		"wrong value type": mutate("<string>", "<data>"),
		"namespace":        mutate(`<plist version="1.0">`, `<plist xmlns="urn:foreign" version="1.0">`),
		"second document":  []byte(base64.StdEncoding.EncodeToString(append(bytes.Clone(xmlData), xmlData...))),
		"external entity":  mutate(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`, `<!DOCTYPE plist [<!ENTITY attack SYSTEM "file:///never-read">]>`),
		"oversized":        bytes.Repeat([]byte("A"), MaxVendorPortalRequest+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.trust.VerifyPortalRequest(f.csr, data, f.now); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	other := newVendorFixture(t)
	if _, err := f.trust.VerifyPortalRequest(other.csr, encoded, f.now); err == nil {
		t.Fatal("another CSR accepted")
	}
	if _, err := f.trust.VerifyPortalRequest(f.csr, encoded, f.now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired vendor signer accepted")
	}
	if _, err := f.trust.VerifyPortalRequest(f.csr, encoded, f.now.Add(-2*time.Hour)); err == nil {
		t.Fatal("future chain accepted")
	}
	unpinned := &VendorTrust{root: f.trust.root, pins: map[string]struct{}{digest(other.chain[0].Raw): {}}}
	if _, err := unpinned.VerifyPortalRequest(f.csr, encoded, f.now); err == nil {
		t.Fatal("unapproved vendor accepted")
	}
	production, err := NewVendorTrust([]string{digest(f.chain[0].Raw)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := production.VerifyPortalRequest(f.csr, encoded, f.now); err == nil {
		t.Fatal("production trusted a synthetic Apple-named root")
	}
	var fields map[string]string
	if _, err := plist.Unmarshal(xmlData, &fields); err != nil {
		t.Fatal(err)
	}
	csr, _ := pem.Decode(f.csr)
	oldHash := sha1.Sum(csr.Bytes)
	oldSignature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA1, oldHash[:])
	if err != nil {
		t.Fatal(err)
	}
	fields["PushCertSignature"] = base64.StdEncoding.EncodeToString(oldSignature)
	oldXML, err := plist.Marshal(fields, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.trust.VerifyPortalRequest(f.csr, []byte(base64.StdEncoding.EncodeToString(oldXML)), f.now); err == nil {
		t.Fatal("legacy SHA-1 vendor signature accepted")
	}
}

func TestVendorPortalRequiresOrderedCompleteChainAndMatchingKey(t *testing.T) {
	f := newVendorFixture(t)
	for _, chain := range [][]*x509.Certificate{{f.chain[0], f.chain[1]}, {f.chain[0], f.chain[2], f.chain[1]}, {f.chain[0], f.chain[1], f.chain[1], f.chain[2]}, {f.chain[2], f.chain[1], f.chain[0]}} {
		var data []byte
		for _, cert := range chain {
			data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		}
		if _, err := f.trust.SignVendorPortal(f.csr, data, f.key, f.now); err == nil {
			t.Fatal("invalid chain accepted")
		}
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []*rsa.PrivateKey{nil, {}, wrongKey} {
		if _, err := f.trust.SignVendorPortal(f.csr, f.chainPEM, key, f.now); err == nil {
			t.Fatal("wrong vendor key accepted")
		}
	}
	for _, pins := range [][]string{nil, {""}, {"invalid"}, {strings.Repeat("A", 64)}, {strings.Repeat("a", 64), strings.Repeat("a", 64)}} {
		if _, err := NewVendorTrust(pins); err == nil {
			t.Fatal("invalid operator pin configuration accepted")
		}
	}
}
