package apple

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

// Test-only roots exercise the same verifier without making test trust available
// through a production constructor, environment variable or HTTP endpoint.
type testPushIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var syntheticPushCA = sync.OnceValues(func() (*testPushIssuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Synthetic push root"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 2}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return &testPushIssuer{cert, key}, err
})

func testPushCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	issuer, err := syntheticPushCA()
	if err != nil {
		t.Fatal(err)
	}
	return issuer.cert, issuer.key
}

func testPushTrust(t *testing.T) *pushCertificateTrust {
	t.Helper()
	cert, _ := testPushCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &pushCertificateTrust{roots: roots, intermediates: x509.NewCertPool()}
}

func testProductionPushExtensions() []pkix.Extension {
	return []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 3, 2}, Value: []byte{5, 0}}}
}

func pushLeafTemplate() *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(20), Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "com.apple.mgmt.External.test"}}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, ExtraExtensions: testProductionPushExtensions()}
}

func signPushLeaf(t *testing.T, template, issuer *x509.Certificate, publicKey any, signer any) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPushCertificateTrust(t *testing.T) {
	root, signer := testPushCA(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	trust := testPushTrust(t)
	good := signPushLeaf(t, pushLeafTemplate(), root, &key.PublicKey, signer)
	if out, err := trust.verify(good, time.Now()); err != nil || !bytes.Equal(out, good) {
		t.Fatal("valid client certificate rejected", err)
	}
	production, err := newPushCertificateTrust()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = production.verify(good, time.Now()); !errors.Is(err, ErrPushCertificate) {
		t.Fatal("synthetic root trusted by production", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"future", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{"CA", func(c *x509.Certificate) { c.IsCA = true }},
		{"no signing usage", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
		{"no client usage", func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"any usage", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		{"server usage", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"no production extension", func(c *x509.Certificate) { c.ExtraExtensions = nil }},
		{"development extension", func(c *x509.Certificate) {
			c.ExtraExtensions[0].Id = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 3, 1}
		}},
		{"unknown critical", func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}})
		}},
		{"ambiguous UID", func(c *x509.Certificate) {
			c.Subject.ExtraNames = append(c.Subject.ExtraNames, c.Subject.ExtraNames[0])
		}},
		{"header injection", func(c *x509.Certificate) { c.Subject.ExtraNames[0].Value = "com.apple.mgmt.test\r\nX-Injected: yes" }},
		{"empty topic suffix", func(c *x509.Certificate) { c.Subject.ExtraNames[0].Value = "com.apple.mgmt." }},
		{"wrong topic", func(c *x509.Certificate) { c.Subject.ExtraNames[0].Value = "com.example.app" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := pushLeafTemplate()
			tc.change(template)
			cert := signPushLeaf(t, template, root, &key.PublicKey, signer)
			if _, err := trust.verify(cert, time.Now()); !errors.Is(err, ErrPushCertificate) {
				t.Fatal("invalid certificate accepted", err)
			}
		})
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = trust.verify(signPushLeaf(t, pushLeafTemplate(), root, &weak.PublicKey, signer), time.Now()); !errors.Is(err, ErrPushCertificate) {
		t.Fatal("weak RSA key accepted", err)
	}
	for _, bad := range [][]byte{nil, []byte("not PEM"), append(append([]byte{}, good...), good...), append([]byte("preamble\n"), good...)} {
		if _, err := trust.verify(bad, time.Now()); !errors.Is(err, ErrPushCertificate) {
			t.Fatal("malformed chain accepted", err)
		}
	}
	if _, err := (*pushCertificateTrust)(nil).verify(good, time.Now()); !errors.Is(err, ErrPushCertificate) {
		t.Fatal("missing trust accepted", err)
	}
}

func TestPushCertificateIntermediateChain(t *testing.T) {
	root, signer := testPushCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(30), Subject: pkix.Name{CommonName: "Synthetic intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	intermediatePEM := signPushLeaf(t, template, root, &key.PublicKey, signer)
	block, _ := pem.Decode(intermediatePEM)
	intermediate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := pushLeafTemplate()
	leafTemplate.NotAfter = time.Now().Add(2 * time.Hour)
	leaf := signPushLeaf(t, leafTemplate, intermediate, &signer.PublicKey, key)
	chain := append(append([]byte{}, leaf...), intermediatePEM...)
	trust := testPushTrust(t)
	if _, err := trust.verify(leaf, time.Now()); !errors.Is(err, ErrPushCertificate) {
		t.Fatal("missing issuer accepted", err)
	}
	if out, err := trust.verify(chain, time.Now()); err != nil || !bytes.Equal(out, chain) {
		t.Fatal("supplied issuer rejected", err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	if out, err := trust.verify(append(append([]byte{}, chain...), rootPEM...), time.Now()); err != nil || !bytes.Equal(out, chain) {
		t.Fatal("root was not omitted from client chain", err)
	}
	trust.intermediates.AddCert(intermediate)
	if out, err := trust.verify(leaf, time.Now()); err != nil || !bytes.Equal(out, chain) {
		t.Fatal("bundled issuer was not added to client chain", err)
	}
	for _, bad := range [][]byte{append(append([]byte{}, leaf...), rootPEM...), append(append([]byte{}, chain...), intermediatePEM...)} {
		if _, err := trust.verify(bad, time.Now()); !errors.Is(err, ErrPushCertificate) {
			t.Fatal("noncontiguous or duplicate chain accepted", err)
		}
	}
	if _, err := trust.verify(leaf, intermediate.NotAfter.Add(time.Second)); !errors.Is(err, ErrPushCertificate) {
		t.Fatal("expired chain accepted", err)
	}
}

func TestBundledPushCertificateAuthorities(t *testing.T) {
	trust, err := newPushCertificateTrust()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"AppleIncRootCertificate.cer":          "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
		"AppleRootCA-G2.cer":                   "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
		"AppleRootCA-G3.cer":                   "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
		"AppleAAI2CA.cer":                      "d3496f4b73cd67aab9f2fcb1d5aa41f8dc457769c455c792b70ddb19e92023d6",
		"AppleAAICAG3.cer":                     "a64b099dbd73ebb036b4204e1675e8aa821637d09b84980899104ad59d664a3b",
		"AppleApplicationIntegrationCA5G1.cer": "c0d8efbea821079d1b8a98e1198bfcc669331fa7a9c14f09b969f0af08ce4a43",
		"AppleApplicationIntegrationCA7G1.cer": "928265664dcb4f3e2ec82d93598f0782615e541d975e2254a27d0aa98724502e",
		"AppleWWDRCAG4.cer":                    "ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c",
	} {
		der, err := pushTrustFiles.ReadFile("certs/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("public trust certificate changed", name)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		// Fixed provenance date keeps this test useful after normal CA expiry.
		if _, err = cert.Verify(x509.VerifyOptions{Roots: trust.roots, CurrentTime: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Fatal(name, err)
		}
	}
}

func TestPushCertificateUntrustedImportPreservesState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	old := testSettings(t, s, 1)
	request := newTestPushRequest(t, s, 1)
	certificate := issueTestPushCertificate(t, s, 1, request.ID, old.Topic, time.Now().Add(time.Hour))
	// A fresh production constructor must not inherit test-only trust.
	production, err := NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	if err = production.ImportPushCertificate(ctx, 1, request.ID, certificate, "test-admin"); !errors.Is(err, ErrPushCertificate) {
		t.Fatal("untrusted request import accepted", err)
	}
	if err = production.Configure(ctx, *old, "test-admin"); !errors.Is(err, ErrPushCertificate) {
		t.Fatal("legacy import bypassed trust", err)
	}
	current, err := s.Settings(ctx, 1)
	if err != nil || !bytes.Equal(current.PushCertificate, old.PushCertificate) || !bytes.Equal(current.PushKey, old.PushKey) || !bytes.Equal(current.CACertificate, old.CACertificate) {
		t.Fatal("failed validation replaced active settings", err)
	}
	var pending bool
	if err = s.db.QueryRow(`SELECT status='pending' AND encrypted_key IS NOT NULL FROM mdm_apple_push_requests WHERE id=$1`, request.ID).Scan(&pending); err != nil || !pending {
		t.Fatal("failed validation consumed request", err)
	}
}
