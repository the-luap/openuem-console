package clientidentity

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

const SessionCertificateKey = "login-certificate"

var ErrCertificateBinding = errors.New("certificate sign-in evidence is missing or no longer valid")

// EncodeSessionCertificate retains only the public certificate already verified
// by the TLS authentication listener. It must never be populated from a form.
func EncodeSessionCertificate(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 || len(cert.Raw) > 16<<10 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// ReadSessionCertificate binds the retained public certificate to the exact
// first-factor proof and checks its lifetime before a pending MFA step.
func ReadSessionCertificate(raw, uid, credential string, now time.Time) (*x509.Certificate, error) {
	cert, err := DecodeSessionCertificate(raw, uid, now)
	if err != nil || credential != loginproof.Digest(string(cert.Raw)) {
		return nil, ErrCertificateBinding
	}
	return cert, nil
}

// DecodeSessionCertificate reads a public certificate retained by successful TLS
// admission. Completed sessions keep this evidence independently of the shorter
// pending primary proof. Callers must also check current registry authorization.
func DecodeSessionCertificate(raw, uid string, now time.Time) (*x509.Certificate, error) {
	if raw == "" || len(raw) > 24<<10 {
		return nil, ErrCertificateBinding
	}
	der, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(der) > 16<<10 {
		return nil, ErrCertificateBinding
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || !CurrentUserCertificate(cert, uid, now) {
		return nil, ErrCertificateBinding
	}
	return cert, nil
}

// CurrentUserCertificate checks fields relevant to the user-certificate registry.
// TLS chain verification and proof of possession remain the listener's job.
func CurrentUserCertificate(cert *x509.Certificate, uid string, now time.Time) bool {
	if cert == nil || len(cert.Raw) == 0 || len(cert.Raw) > 16<<10 || uid == "" || cert.Subject.CommonName != uid || cert.IsCA || cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || !cert.SerialNumber.IsInt64() || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
