package windows

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

const MaxWindowsRenewalProofBytes = 64 << 10

var ErrRenewalProof = errors.New("invalid Windows certificate renewal proof")

// WindowsRenewalProof proves continuity between an existing certificate's key
// and a PKCS#10 request. It conveys no scope, authorization or certificate trust.
type WindowsRenewalProof struct {
	CSR               *x509.CertificateRequest `json:"-" xml:"-" yaml:"-"`
	CertificateSHA256 [32]byte                 `json:"-" xml:"-" yaml:"-"`
}

func (WindowsRenewalProof) String() string     { return "[protected Windows certificate renewal proof]" }
func (v WindowsRenewalProof) GoString() string { return v.String() }

type renewalContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

type renewalAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type renewalSigner struct {
	Version int
	Issuer  struct {
		Name   asn1.RawValue
		Serial *big.Int
	}
	Digest     pkix.AlgorithmIdentifier
	Attributes []renewalAttribute `asn1:"optional,set,tag:0"`
	Algorithm  pkix.AlgorithmIdentifier
	Signature  []byte
	Unsigned   []renewalAttribute `asn1:"optional,set,tag:1"`
}

type renewalSignedData struct {
	Version      int
	Digests      []pkix.AlgorithmIdentifier `asn1:"set"`
	Content      renewalContentInfo
	Certificates asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue   `asn1:"optional,tag:1"`
	Signers      []renewalSigner `asn1:"set"`
}

var (
	renewalOIDData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	renewalOIDSignedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	renewalOIDContent     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	renewalOIDDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	renewalOIDCertificate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 13, 1}
)

// VerifyWindowsRenewalProof verifies the MS-WCCE CMS/PKCS#10 renewal form against
// the exact existing certificate supplied by the caller, never an embedded root.
// The caller must independently authenticate and lock that certificate's live
// enrollment, scope, validity, renewal window and revocation state before issuing.
// This function performs no storage, network, certificate issuance or host changes.
// CMC, detached content, multiple signers and legacy SHA-1/MD5 are not accepted.
func VerifyWindowsRenewalProof(data, existingCertificateDER []byte, minimumKeyBits int) (*WindowsRenewalProof, error) {
	if len(data) == 0 || len(data) > MaxWindowsRenewalProofBytes || !boundedRenewalDER(data) || len(existingCertificateDER) == 0 || len(existingCertificateDER) > MaxEnrollmentCSRBytes || !boundedRenewalDER(existingCertificateDER) {
		return nil, ErrRenewalProof
	}
	existing, err := x509.ParseCertificate(existingCertificateDER)
	if err != nil || existing.IsCA || existing.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, ErrRenewalProof
	}
	key, ok := existing.PublicKey.(*rsa.PublicKey)
	if !ok || key.E != 65537 || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 {
		return nil, ErrRenewalProof
	}
	var outer renewalContentInfo
	var sd renewalSignedData
	if !renewalASN1(data, &outer) || !outer.Type.Equal(renewalOIDSignedData) || !renewalASN1(outer.Content.Bytes, &sd) || sd.Version != 1 || len(sd.Digests) != 1 || len(sd.Signers) != 1 || len(sd.CRLs.FullBytes) != 0 || !sd.Content.Type.Equal(renewalOIDData) {
		return nil, ErrRenewalProof
	}
	if !renewalCanonical(data, outer) || !renewalCanonical(outer.Content.Bytes, sd) {
		return nil, ErrRenewalProof
	}
	var csrDER []byte
	if !renewalASN1(sd.Content.Content.Bytes, &csrDER) || len(csrDER) == 0 || len(csrDER) > MaxEnrollmentCSRBytes || !boundedRenewalDER(csrDER) {
		return nil, ErrRenewalProof
	}
	signer := sd.Signers[0]
	if signer.Version != 1 || signer.Issuer.Serial == nil || signer.Issuer.Serial.Cmp(existing.SerialNumber) != 0 || !bytes.Equal(signer.Issuer.Name.FullBytes, existing.RawIssuer) || !renewalAlgorithmParameters(sd.Digests[0]) || !renewalAlgorithmParameters(signer.Digest) || !renewalAlgorithmParameters(signer.Algorithm) || !sd.Digests[0].Algorithm.Equal(signer.Digest.Algorithm) || len(signer.Attributes) > 16 || len(signer.Unsigned) != 0 {
		return nil, ErrRenewalProof
	}
	hash, algorithm := renewalAlgorithms(signer.Digest.Algorithm.String(), signer.Algorithm.Algorithm.String())
	if hash == 0 {
		return nil, ErrRenewalProof
	}
	if sd.Certificates.Class != 2 || sd.Certificates.Tag != 0 || !sd.Certificates.IsCompound {
		return nil, ErrRenewalProof
	}
	certificates, found, seen := sd.Certificates.Bytes, false, map[[32]byte]bool{}
	for count := 0; len(certificates) > 0; count++ {
		if count == 8 {
			return nil, ErrRenewalProof
		}
		var raw asn1.RawValue
		certificates, err = asn1.Unmarshal(certificates, &raw)
		if err != nil {
			return nil, ErrRenewalProof
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, ErrRenewalProof
		}
		fingerprint := sha256.Sum256(cert.Raw)
		if seen[fingerprint] {
			return nil, ErrRenewalProof
		}
		seen[fingerprint] = true
		if cert.SerialNumber.Cmp(signer.Issuer.Serial) == 0 && bytes.Equal(cert.RawIssuer, signer.Issuer.Name.FullBytes) {
			if found || !bytes.Equal(cert.Raw, existing.Raw) {
				return nil, ErrRenewalProof
			}
			found = true
		}
	}
	if !found {
		return nil, ErrRenewalProof
	}
	signed := csrDER
	if len(signer.Attributes) > 0 {
		seen := map[string]bool{}
		for _, attribute := range signer.Attributes {
			if seen[attribute.Type.String()] || attribute.Values.Class != 0 || attribute.Values.Tag != asn1.TagSet || !attribute.Values.IsCompound || len(attribute.Values.Bytes) == 0 {
				return nil, ErrRenewalProof
			}
			seen[attribute.Type.String()] = true
			switch {
			case attribute.Type.Equal(renewalOIDContent):
				var contentType asn1.ObjectIdentifier
				if !renewalASN1(attribute.Values.Bytes, &contentType) || !contentType.Equal(renewalOIDData) {
					return nil, ErrRenewalProof
				}
			case attribute.Type.Equal(renewalOIDDigest):
				var digest []byte
				h := hash.New()
				h.Write(csrDER)
				if !renewalASN1(attribute.Values.Bytes, &digest) || !bytes.Equal(digest, h.Sum(nil)) {
					return nil, ErrRenewalProof
				}
			}
		}
		if !seen[renewalOIDContent.String()] || !seen[renewalOIDDigest.String()] {
			return nil, ErrRenewalProof
		}
		signed, err = asn1.MarshalWithParams(signer.Attributes, "set")
		if err != nil {
			return nil, ErrRenewalProof
		}
	}
	if existing.CheckSignature(algorithm, signed, signer.Signature) != nil {
		return nil, ErrRenewalProof
	}
	csr, err := verifyEnrollmentCSR(csrDER, minimumKeyBits)
	if err != nil || !renewalCSRNamesCertificate(csr, existing.Raw) {
		return nil, ErrRenewalProof
	}
	return &WindowsRenewalProof{CSR: csr, CertificateSHA256: sha256.Sum256(existing.Raw)}, nil
}

func renewalCSRNamesCertificate(csr *x509.CertificateRequest, existingDER []byte) bool {
	// crypto/x509's compatibility Attributes field omits nonstandard attribute
	// value shapes. Read the signed request-info bytes to check the renewal OID.
	var info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []renewalAttribute `asn1:"set,tag:0"`
	}
	if !renewalASN1(csr.RawTBSCertificateRequest, &info) || !renewalCanonical(csr.RawTBSCertificateRequest, info) || len(info.Attributes) > 32 {
		return false
	}
	seen, found := map[string]bool{}, false
	for _, attribute := range info.Attributes {
		if seen[attribute.Type.String()] || attribute.Values.Class != 0 || attribute.Values.Tag != asn1.TagSet || !attribute.Values.IsCompound || len(attribute.Values.Bytes) == 0 {
			return false
		}
		seen[attribute.Type.String()] = true
		if attribute.Type.Equal(renewalOIDCertificate) {
			// The attribute value is the DER Certificate itself, not an octet
			// string, subject name, hash, PEM or an independently selected signer.
			if !bytes.Equal(attribute.Values.Bytes, existingDER) {
				return false
			}
			found = true
		}
	}
	return found
}

func renewalASN1(data []byte, target any) bool {
	rest, err := asn1.Unmarshal(data, target)
	return err == nil && len(rest) == 0
}

func renewalCanonical(data []byte, value any) bool {
	encoded, err := asn1.Marshal(value)
	return err == nil && bytes.Equal(data, encoded)
}

func renewalAlgorithmParameters(a pkix.AlgorithmIdentifier) bool {
	return len(a.Parameters.FullBytes) == 0 || bytes.Equal(a.Parameters.FullBytes, []byte{5, 0})
}

func renewalAlgorithms(digest, signature string) (crypto.Hash, x509.SignatureAlgorithm) {
	for _, a := range []struct {
		digest, signature string
		hash              crypto.Hash
		algorithm         x509.SignatureAlgorithm
	}{
		{"2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", crypto.SHA256, x509.SHA256WithRSA},
		{"2.16.840.1.101.3.4.2.2", "1.2.840.113549.1.1.12", crypto.SHA384, x509.SHA384WithRSA},
		{"2.16.840.1.101.3.4.2.3", "1.2.840.113549.1.1.13", crypto.SHA512, x509.SHA512WithRSA},
	} {
		if a.digest == digest && (signature == "1.2.840.113549.1.1.1" || signature == a.signature) {
			return a.hash, a.algorithm
		}
	}
	return 0, 0
}

// Bound all constructed values before generic ASN.1 or X.509 decoding. This
// admits definite DER only, without unbounded recursion or BER conversion.
func boundedRenewalDER(data []byte) bool {
	nodes := 0
	var visit func([]byte, int) bool
	visit = func(data []byte, depth int) bool {
		if depth > 16 {
			return false
		}
		for len(data) > 0 {
			nodes++
			if nodes > 2048 || len(data) < 2 || data[0]&31 == 31 || data[0] == 0 {
				return false
			}
			tag, size, header := data[0], int(data[1]), 2
			if size&128 != 0 {
				count := size & 127
				if count == 0 || count > 3 || len(data) < 2+count || data[2] == 0 {
					return false
				}
				size = 0
				for _, b := range data[2 : 2+count] {
					size = size<<8 | int(b)
				}
				if size < 128 {
					return false
				}
				header += count
			}
			if size > len(data)-header {
				return false
			}
			if tag&32 != 0 && !visit(data[header:header+size], depth+1) {
				return false
			}
			data = data[header+size:]
		}
		return true
	}
	return len(data) > 0 && len(data) <= MaxWindowsRenewalProofBytes && visit(data, 0)
}
