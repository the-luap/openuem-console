package windows

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

const maxAuthoritySecretBytes = 8192
const maxAuthorityCertificateBytes = 16384

var ErrMasterKey = errors.New("native Windows CA operations require a base64-encoded 32-byte encryption key")
var ErrAuthoritySecret = errors.New("native Windows CA key could not be authenticated")

type authoritySecretBox struct{ aead cipher.AEAD }

func newAuthoritySecretBox(encoded string) (*authoritySecretBox, error) {
	if len(encoded) != 44 {
		return nil, ErrMasterKey
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, ErrMasterKey
	}
	defer clear(key)
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("openuem/windows/authority-encryption/v1"))
	derived := h.Sum(nil)
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, ErrMasterKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrMasterKey
	}
	return &authoritySecretBox{aead: aead}, nil
}

func (b *authoritySecretBox) seal(data []byte, purpose string) ([]byte, error) {
	return b.sealBounded(data, purpose, maxAuthoritySecretBytes)
}

func (b *authoritySecretBox) sealBounded(data []byte, purpose string, maximum int) ([]byte, error) {
	if b == nil {
		return nil, ErrMasterKey
	}
	if len(data) == 0 || len(data) > maximum || len(purpose) == 0 || len(purpose) > 1024 {
		return nil, ErrAuthoritySecret
	}
	nonce := make([]byte, 1+b.aead.NonceSize())
	nonce[0] = 1
	if _, err := rand.Read(nonce[1:]); err != nil {
		return nil, ErrAuthoritySecret
	}
	return b.aead.Seal(nonce, nonce[1:], data, []byte(purpose)), nil
}

func (b *authoritySecretBox) open(data []byte, purpose string) ([]byte, error) {
	return b.openBounded(data, purpose, maxAuthoritySecretBytes)
}

func (b *authoritySecretBox) openBounded(data []byte, purpose string, maximum int) ([]byte, error) {
	if b == nil {
		return nil, ErrMasterKey
	}
	n := b.aead.NonceSize()
	if len(data) <= 1+n+b.aead.Overhead() || len(data) > 1+n+b.aead.Overhead()+maximum || data[0] != 1 || len(purpose) == 0 || len(purpose) > 1024 {
		return nil, ErrAuthoritySecret
	}
	plain, err := b.aead.Open(nil, data[1:1+n], data[1+n:], []byte(purpose))
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	return plain, nil
}

func authoritySecretPurpose(a EnrollmentAuthority) string {
	hash := sha256.Sum256(a.Certificate)
	return fmt.Sprintf("openuem/windows/authority/v1/%d/%s/%x/%s/%d/%d/%d", a.TenantID, a.ID, hash, base64.RawURLEncoding.EncodeToString([]byte(a.Organization)), a.MinimumKeyBits, a.ValiditySeconds, a.RenewalSeconds)
}

func generateAuthorityCertificate(a EnrollmentAuthority, now time.Time) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, ErrAuthority
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serial.Sign() == 0 {
		return nil, nil, ErrAuthority
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM Windows CA " + a.ID, Organization: []string{a.Organization}, OrganizationalUnit: []string{fmt.Sprintf("Organization %d", a.TenantID)}},
		NotBefore: now.UTC().Add(-5 * time.Minute).Truncate(time.Second), NotAfter: now.UTC().Add(5 * 365 * 24 * time.Hour).Truncate(time.Second),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SignatureAlgorithm: x509.SHA256WithRSA,
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, ErrAuthority
	}
	identifier := sha256.Sum256(public)
	template.SubjectKeyId = append([]byte(nil), identifier[:20]...)
	template.AuthorityKeyId = append([]byte(nil), template.SubjectKeyId...)
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, ErrAuthority
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, ErrAuthority
	}
	return certificate, private, nil
}

func parseAuthorityCertificate(a EnrollmentAuthority) (*x509.Certificate, error) {
	if !canonicalInvitationID(a.ID) || a.TenantID <= 0 || a.AuthorityOptions.validate() != nil || len(a.Certificate) == 0 || len(a.Certificate) > maxAuthorityCertificateBytes {
		return nil, ErrAuthority
	}
	certificate, err := x509.ParseCertificate(a.Certificate)
	if err != nil {
		return nil, ErrAuthority
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 3072 || public.E != 65537 || !certificate.IsCA || !certificate.BasicConstraintsValid || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 || certificate.SignatureAlgorithm != x509.SHA256WithRSA || certificate.CheckSignatureFrom(certificate) != nil || len(certificate.UnhandledCriticalExtensions) != 0 || certificate.KeyUsage != (x509.KeyUsageCertSign|x509.KeyUsageCRLSign) || len(certificate.ExtKeyUsage) != 0 || len(certificate.UnknownExtKeyUsage) != 0 || !certificate.NotAfter.Equal(a.ExpiresAt) {
		return nil, ErrAuthority
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, ErrAuthority
	}
	identifier := sha256.Sum256(publicDER)
	if !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) || !bytes.Equal(certificate.SubjectKeyId, identifier[:20]) || !bytes.Equal(certificate.AuthorityKeyId, identifier[:20]) || certificate.SerialNumber.Sign() <= 0 {
		return nil, ErrAuthority
	}
	if certificate.Subject.CommonName != "OpenUEM Windows CA "+a.ID || !slices.Equal(certificate.Subject.Organization, []string{a.Organization}) || !slices.Equal(certificate.Subject.OrganizationalUnit, []string{fmt.Sprintf("Organization %d", a.TenantID)}) {
		return nil, ErrAuthority
	}
	return certificate, nil
}

type authoritySigner struct {
	metadata    EnrollmentAuthority
	certificate *x509.Certificate
	key         *rsa.PrivateKey
}

func (authoritySigner) String() string   { return "[protected native Windows CA]" }
func (authoritySigner) GoString() string { return "[protected native Windows CA]" }

func (s *Store) decryptAuthority(a EnrollmentAuthority, encrypted []byte, now time.Time) (*authoritySigner, error) {
	certificate, err := parseAuthorityCertificate(a)
	if err != nil {
		return nil, err
	}
	if a.CreatedAt.After(now) || certificate.NotBefore.After(now) || !certificate.NotAfter.After(now.Add(time.Duration(a.ValiditySeconds)*time.Second+5*time.Minute)) {
		return nil, ErrAuthorityUnavailable
	}
	return s.authenticateAuthority(a, encrypted)
}

// authenticateAuthority verifies stored issuer identity and policy without
// authorizing issuance. Health reporting must remain possible after expiry.
func (s *Store) authenticateAuthority(a EnrollmentAuthority, encrypted []byte) (*authoritySigner, error) {
	certificate, err := parseAuthorityCertificate(a)
	if err != nil {
		return nil, err
	}
	plain, err := s.secrets.open(encrypted, authoritySecretPurpose(a))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	parsed, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() != 3072 || !key.PublicKey.Equal(certificate.PublicKey) || key.Validate() != nil {
		return nil, ErrAuthoritySecret
	}
	return &authoritySigner{metadata: a, certificate: certificate, key: key}, nil
}
