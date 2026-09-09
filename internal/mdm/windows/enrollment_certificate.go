package windows

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func issueEnrollmentCertificate(a *authoritySigner, id string, scope access.Scope, csr *x509.CertificateRequest, now time.Time) (*x509.Certificate, error) {
	if a == nil || a.key == nil || a.certificate == nil || csr == nil || !canonicalInvitationID(id) || scope.SiteID <= 0 || a.metadata.TenantID != scope.TenantID {
		return nil, ErrAuthority
	}
	if !a.certificate.NotAfter.After(now.Add(time.Duration(a.metadata.ValiditySeconds)*time.Second+5*time.Minute)) || a.certificate.NotBefore.After(now) {
		return nil, ErrAuthorityUnavailable
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serial.Sign() == 0 {
		return nil, ErrAuthority
	}
	public, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, ErrCSR
	}
	keyID := sha256.Sum256(public)
	identity := &url.URL{Scheme: "urn", Opaque: "openuem:windows:device:" + id}
	template := &x509.Certificate{
		SerialNumber: serial, SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:   pkix.Name{CommonName: "OpenUEM Windows " + id, Organization: []string{a.metadata.Organization}, OrganizationalUnit: []string{fmt.Sprintf("Organization %d", scope.TenantID), fmt.Sprintf("Site %d", scope.SiteID)}},
		NotBefore: now.UTC().Add(-5 * time.Minute).Truncate(time.Second), NotAfter: now.UTC().Add(time.Duration(a.metadata.ValiditySeconds) * time.Second).Truncate(time.Second),
		BasicConstraintsValid: true, IsCA: false, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
		SubjectKeyId: append([]byte(nil), keyID[:20]...), AuthorityKeyId: append([]byte(nil), a.certificate.SubjectKeyId...),
	}
	// The CSR's subject, requested SANs, CA constraints and extensions are never
	// copied. Organization/site/device identity is exclusively server assigned.
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.key)
	if err != nil {
		return nil, ErrAuthority
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrAuthority
	}
	return certificate, nil
}
