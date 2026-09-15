package apple

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"time"
)

var ErrPushCertificate = errors.New("the push certificate must have a valid Apple certificate chain, client authentication usage and a production MDM topic")

// These public certificates are scoped to offline push credential validation.
// They are not installed in the OS or added to enrollment or APNs server trust.
// Sources, fingerprints and expiry dates are recorded in certs/README.md.
//
//go:embed certs/*.cer
var pushTrustFiles embed.FS

type pushCertificateTrust struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

func newPushCertificateTrust() (*pushCertificateTrust, error) {
	t := &pushCertificateTrust{roots: x509.NewCertPool(), intermediates: x509.NewCertPool()}
	for _, group := range []struct {
		pool  *x509.CertPool
		names []string
	}{
		{t.roots, []string{"AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer"}},
		{t.intermediates, []string{"AppleAAI2CA.cer", "AppleAAICAG3.cer", "AppleApplicationIntegrationCA5G1.cer", "AppleApplicationIntegrationCA7G1.cer", "AppleWWDRCAG4.cer"}},
	} {
		for _, name := range group.names {
			der, err := pushTrustFiles.ReadFile("certs/" + name)
			if err != nil {
				return nil, ErrPushCertificate
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil || !cert.IsCA {
				return nil, ErrPushCertificate
			}
			group.pool.AddCert(cert)
		}
	}
	return t, nil
}

func strongPushPublicKey(cert *x509.Certificate) bool {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N != nil && key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.E >= 3 && key.E%2 == 1
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256() || key.Curve == elliptic.P384() || key.Curve == elliptic.P521()
	default:
		return false
	}
}

// verify does not use system roots, fetch AIA URLs, check revocation or contact
// APNs. A complete verified client chain is returned without its root so that
// certificate-only portal downloads work when the TLS server needs intermediates.
func (t *pushCertificateTrust) verify(data []byte, now time.Time) ([]byte, error) {
	if t == nil || t.roots == nil || t.intermediates == nil || certificateOnlyPEM(data) != nil {
		return nil, ErrPushCertificate
	}
	var supplied []*x509.Certificate
	seen := make(map[string]bool)
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		cert, err := x509.ParseCertificate(block.Bytes) // certificateOnlyPEM checked all blocks.
		if err != nil || seen[string(cert.Raw)] || !strongPushPublicKey(cert) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, ErrPushCertificate
		}
		seen[string(cert.Raw)] = true
		supplied = append(supplied, cert)
		data = rest
	}
	leaf := supplied[0]
	clientAuth, production := false, false
	for _, usage := range leaf.ExtKeyUsage {
		clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth
	}
	// Apple AAI CPS section 4.11.2 identifies the production push extension.
	for _, extension := range leaf.Extensions {
		production = production || extension.Id.Equal(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 3, 2})
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !clientAuth || !production || PushTopic(leaf) == "" {
		return nil, ErrPushCertificate
	}
	intermediates := t.intermediates.Clone()
	for i := 1; i < len(supplied); i++ {
		if !supplied[i].IsCA || supplied[i-1].CheckSignatureFrom(supplied[i]) != nil {
			return nil, ErrPushCertificate
		}
		intermediates.AddCert(supplied[i])
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: t.roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, ErrPushCertificate
	}
	for _, chain := range chains {
		if len(chain) < 2 || len(chain) < len(supplied) {
			continue
		}
		matches := true
		for i, cert := range chain {
			if !strongPushPublicKey(cert) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || (i < len(supplied) && !bytes.Equal(cert.Raw, supplied[i].Raw)) {
				matches = false
				break
			}
		}
		if matches {
			var result []byte
			for _, cert := range chain[:len(chain)-1] {
				result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
			}
			return result, nil
		}
	}
	return nil, ErrPushCertificate
}
