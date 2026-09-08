package apple

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"howett.net/plist"
)

const MaxVendorPortalRequest = 128 << 10

var (
	ErrVendorNotConfigured = errors.New("an authorized Apple MDM vendor certificate must be configured by the server operator")
	ErrVendorRequest       = errors.New("the vendor request does not match this CSR, the authorized vendor certificate or a valid Apple certificate chain")
)

// VendorTrust is immutable. Pins identify the specific vendor credentials whose
// authorization the operator has verified out of band. Apple chain validation
// alone does not establish that a vendor may sign for this installation.
type VendorTrust struct {
	root *x509.Certificate
	pins map[string]struct{}
}

// NewVendorTrust trusts only Apple's embedded public root and up to ten explicit
// certificate SHA-256 pins. It does not use OS roots or download trust material.
func NewVendorTrust(fingerprints []string) (*VendorTrust, error) {
	root, err := x509.ParseCertificate(appleRootDER)
	if err != nil {
		return nil, ErrVendorNotConfigured
	}
	if len(fingerprints) == 0 || len(fingerprints) > 10 {
		return nil, ErrVendorNotConfigured
	}
	trust := &VendorTrust{root: root, pins: make(map[string]struct{})}
	for _, fingerprint := range fingerprints {
		fingerprint = strings.TrimSpace(fingerprint)
		decoded, err := hex.DecodeString(fingerprint)
		if err != nil || len(decoded) != sha256.Size || fingerprint != strings.ToLower(fingerprint) {
			return nil, ErrVendorNotConfigured
		}
		if _, exists := trust.pins[fingerprint]; exists {
			return nil, ErrVendorNotConfigured
		}
		trust.pins[fingerprint] = struct{}{}
	}
	return trust, nil
}

func (v *VendorTrust) accepts(fingerprint string) bool {
	if v == nil || v.root == nil {
		return false
	}
	_, ok := v.pins[fingerprint]
	return ok
}

type VendorPortalRequest struct {
	Encoded     []byte
	Fingerprint string
	ExpiresAt   time.Time
}

// VerifyPortalRequest verifies the complete base64 XML envelope required by
// Apple's current device management documentation. A raw CSR is never accepted.
// The result is normalized to Apple's PEM wrapping and outer base64 format;
// the signature still covers the exact original DER CSR.
func (v *VendorTrust) VerifyPortalRequest(csrPEM, encoded []byte, now time.Time) (*VendorPortalRequest, error) {
	if v == nil || len(v.pins) == 0 || v.root == nil {
		return nil, ErrVendorNotConfigured
	}
	if len(encoded) == 0 || len(encoded) > MaxVendorPortalRequest {
		return nil, ErrVendorRequest
	}
	data, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, ErrVendorRequest
	}
	fields, err := parseVendorPlist(data)
	if err != nil {
		return nil, ErrVendorRequest
	}
	csr, err := publicPushCSR(csrPEM)
	if err != nil {
		return nil, ErrVendorRequest
	}
	providedCSR, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(fields["PushCertRequestCSR"]))
	if err != nil || subtle.ConstantTimeCompare(csr, providedCSR) != 1 {
		return nil, ErrVendorRequest
	}
	chain, fingerprint, expires, err := v.vendorChain([]byte(fields["PushCertCertificateChain"]), now)
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(fields["PushCertSignature"]))
	if err != nil {
		return nil, ErrVendorRequest
	}
	hash := sha256.Sum256(csr)
	if err = rsa.VerifyPKCS1v15(chain[0].PublicKey.(*rsa.PublicKey), crypto.SHA256, hash[:], signature); err != nil {
		return nil, ErrVendorRequest
	}
	return encodeVendorPortal(csr, chain, signature, fingerprint, expires)
}

func publicPushCSR(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if len(data) > 32<<10 || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE REQUEST-----")) || bytes.Count(data, []byte("-----BEGIN")) != 1 {
		return nil, ErrVendorRequest
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrVendorRequest
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, ErrVendorRequest
	}
	key, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || csr.CheckSignature() != nil {
		return nil, ErrVendorRequest
	}
	return csr.Raw, nil
}

func (v *VendorTrust) vendorChain(data []byte, now time.Time) ([]*x509.Certificate, string, time.Time, error) {
	if v == nil || v.root == nil || len(v.pins) == 0 {
		return nil, "", time.Time{}, ErrVendorNotConfigured
	}
	if certificateOnlyPEM(data) != nil {
		return nil, "", time.Time{}, ErrVendorRequest
	}
	var chain []*x509.Certificate
	seen := make(map[string]bool)
	for len(bytes.TrimSpace(data)) != 0 {
		block, rest := pem.Decode(data)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || seen[digest(cert.Raw)] {
			return nil, "", time.Time{}, ErrVendorRequest
		}
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok && (key.N.BitLen() < 2048 || key.N.BitLen() > 8192) {
			return nil, "", time.Time{}, ErrVendorRequest
		}
		seen[digest(cert.Raw)] = true
		chain = append(chain, cert)
		data = rest
	}
	// The portal requires the complete chain, including the root. The root is
	// supplied by this binary, not by the untrusted envelope or the OS store.
	if len(chain) < 3 || !bytes.Equal(chain[len(chain)-1].Raw, v.root.Raw) {
		return nil, "", time.Time{}, ErrVendorRequest
	}
	leaf := chain[0]
	fingerprint := digest(leaf.Raw)
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !v.accepts(fingerprint) || !ok || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, "", time.Time{}, ErrVendorRequest
	}
	roots := x509.NewCertPool()
	roots.AddCert(v.root)
	intermediates := x509.NewCertPool()
	expires := leaf.NotAfter
	for i, cert := range chain {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, "", time.Time{}, ErrVendorRequest
		}
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
		if i > 0 && i < len(chain)-1 {
			intermediates.AddCert(cert)
		}
		if i < len(chain)-1 && cert.CheckSignatureFrom(chain[i+1]) != nil {
			return nil, "", time.Time{}, ErrVendorRequest
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, "", time.Time{}, ErrVendorRequest
	}
	return chain, fingerprint, expires, nil
}

// SignVendorPortal is for the authorized vendor's own infrastructure. The input
// is the customer's public CSR only; never move a customer private key here or
// configure this vendor private key on a customer console.
func (v *VendorTrust) SignVendorPortal(csrPEM, chainPEM []byte, key *rsa.PrivateKey, now time.Time) (*VendorPortalRequest, error) {
	chain, fingerprint, expires, err := v.vendorChain(chainPEM, now)
	if err != nil {
		return nil, err
	}
	if key == nil || key.N == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.Validate() != nil {
		return nil, ErrVendorRequest
	}
	public := chain[0].PublicKey.(*rsa.PublicKey)
	if public.E != key.E || public.N.Cmp(key.N) != 0 {
		return nil, ErrVendorRequest
	}
	csr, err := publicPushCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(csr)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return nil, ErrVendorRequest
	}
	return encodeVendorPortal(csr, chain, signature, fingerprint, expires)
}

func encodeVendorPortal(csr []byte, chain []*x509.Certificate, signature []byte, fingerprint string, expires time.Time) (*VendorPortalRequest, error) {
	var certificates bytes.Buffer
	for _, cert := range chain {
		if err := pem.Encode(&certificates, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, ErrVendorRequest
		}
	}
	data, err := plist.Marshal(map[string]string{
		"PushCertRequestCSR":       base64.StdEncoding.EncodeToString(csr),
		"PushCertCertificateChain": certificates.String(),
		"PushCertSignature":        base64.StdEncoding.EncodeToString(signature),
	}, plist.XMLFormat)
	if err != nil {
		return nil, ErrVendorRequest
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(data))
	if len(encoded) > MaxVendorPortalRequest {
		return nil, ErrVendorRequest
	}
	return &VendorPortalRequest{Encoded: encoded, Fingerprint: fingerprint, ExpiresAt: expires}, nil
}
