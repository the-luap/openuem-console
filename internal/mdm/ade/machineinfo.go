package ade

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1" // Apple's legacy device signatures still use SHA-1.
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

const MaxMachineInfo = 128 << 10

var ErrMachineInfo = errors.New("invalid signed Automated Device Enrollment information")

// Apple's device identity issuer, published in its OTA enrollment documentation:
// https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html
// This is a public trust anchor, not an organization enrollment CA. Never replace
// it with system roots or accept an issuer supplied by the enrolling device.
//
//go:embed apple_device_ca.pem
var appleDeviceCAPEM []byte

var appleDeviceCA = func() *x509.Certificate {
	p, rest := pem.Decode(appleDeviceCAPEM)
	if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		panic("invalid embedded Apple device issuer")
	}
	sum := sha256.Sum256(p.Bytes)
	if hex.EncodeToString(sum[:]) != "76f27d00e1333bc88de0e2916c38c9a7f2b75774c25a794c092a80e3c4c66cce" {
		panic("unexpected embedded Apple device issuer")
	}
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		panic("invalid embedded Apple device issuer")
	}
	return c
}()

// MachineInfo describes a verified Apple device statement. It is not proof of
// current ADE assignment, successful MDM enrollment, or hardware attestation.
// SignedAt may be absent; a caller must enforce admission and replay policy.
type MachineInfo struct {
	UDID, Serial, Product, Build, OSVersion, Language string
	CanRequestSoftwareUpdate, CanRequestPSSO          bool
	MandatorySoftwareUpdate                           bool
	SignerFingerprint                                 string
	SignatureDigest                                   string
	SignedAt                                          time.Time
}

func (*MachineInfo) String() string     { return "[verified Apple device information]" }
func (m *MachineInfo) GoString() string { return m.String() }

// VerifyMachineInfo accepts Apple's attached CMS SignedData, in DER or bounded
// BER encoding. Only a leaf directly issued by the pinned Apple device CA is
// trusted. Apple's documented certificate date exception is confined to this
// issuer; it does not affect TLS, SCEP or any other certificate verification.
func VerifyMachineInfo(data []byte) (*MachineInfo, error) {
	return verifyMachineInfo(data, appleDeviceCA)
}

type machineContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

type machineAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type machineSigner struct {
	Version int
	Issuer  struct {
		Name   asn1.RawValue
		Serial *big.Int
	}
	Digest     pkix.AlgorithmIdentifier
	Attributes []machineAttribute `asn1:"optional,tag:0"`
	Algorithm  pkix.AlgorithmIdentifier
	Signature  []byte
	Unsigned   []machineAttribute `asn1:"optional,tag:1"`
}

type machineSignedData struct {
	Version      int
	Digests      []pkix.AlgorithmIdentifier `asn1:"set"`
	Content      machineContentInfo
	Certificates asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue   `asn1:"optional,tag:1"`
	Signers      []machineSigner `asn1:"set"`
}

var (
	machineOIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	machineOIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	machineOIDContent    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	machineOIDDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	machineOIDTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

func verifyMachineInfo(data []byte, issuer *x509.Certificate) (*MachineInfo, error) {
	if issuer == nil || len(data) == 0 || len(data) > MaxMachineInfo || !boundedBER(data) {
		return nil, ErrMachineInfo
	}
	der, err := machineDER(data)
	if err != nil {
		return nil, ErrMachineInfo
	}
	var outer machineContentInfo
	var sd machineSignedData
	if !machineASN1(der, &outer) || !outer.Type.Equal(machineOIDSignedData) || !machineASN1(outer.Content.Bytes, &sd) || sd.Version != 1 || len(sd.Signers) != 1 || len(sd.Digests) != 1 || len(sd.CRLs.FullBytes) != 0 || !sd.Content.Type.Equal(machineOIDData) {
		return nil, ErrMachineInfo
	}
	// ASN.1 struct decoding alone ignores extra fields inside a sequence. A
	// canonical round trip also rejects those ambiguous or unknown CMS fields.
	canonical, err := asn1.Marshal(sd)
	if err != nil || !bytes.Equal(canonical, outer.Content.Bytes) {
		return nil, ErrMachineInfo
	}
	canonical, err = asn1.Marshal(outer)
	if err != nil || !bytes.Equal(canonical, der) {
		return nil, ErrMachineInfo
	}
	var content asn1.RawValue
	if !machineASN1(sd.Content.Content.Bytes, &content) {
		return nil, ErrMachineInfo
	}
	plain, err := machineOctets(content)
	if err != nil || len(plain) == 0 || len(plain) > maxMachinePlist {
		return nil, ErrMachineInfo
	}
	signer := sd.Signers[0]
	if signer.Version != 1 || signer.Issuer.Serial == nil || !machineAlgorithmParameters(signer.Digest) || !machineAlgorithmParameters(signer.Algorithm) || !machineAlgorithmParameters(sd.Digests[0]) || !signer.Digest.Algorithm.Equal(sd.Digests[0].Algorithm) || len(signer.Attributes) > 16 || len(signer.Unsigned) > 16 {
		return nil, ErrMachineInfo
	}
	hash, signature := machineAlgorithms(signer.Digest.Algorithm.String(), signer.Algorithm.Algorithm.String())
	if hash == 0 {
		return nil, ErrMachineInfo
	}
	if sd.Certificates.Class != 2 || sd.Certificates.Tag != 0 || !sd.Certificates.IsCompound {
		return nil, ErrMachineInfo
	}
	certs := sd.Certificates.Bytes
	var leaf *x509.Certificate
	for count := 0; len(certs) != 0; count++ {
		var raw asn1.RawValue
		if count == 6 {
			return nil, ErrMachineInfo
		}
		certs, err = asn1.Unmarshal(certs, &raw)
		if err != nil {
			return nil, ErrMachineInfo
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, ErrMachineInfo
		}
		if cert.SerialNumber.Cmp(signer.Issuer.Serial) == 0 && bytes.Equal(cert.RawIssuer, signer.Issuer.Name.FullBytes) {
			if leaf != nil {
				return nil, ErrMachineInfo
			}
			leaf = cert
		}
	}
	if leaf == nil || leaf.IsCA || len(leaf.UnhandledCriticalExtensions) != 0 || leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) || !machineKey(leaf.PublicKey) {
		return nil, ErrMachineInfo
	}
	// CheckSignature deliberately supports legacy SHA-1 signatures. Trust is
	// still anchored to this exact public key, never just an issuer common name.
	if issuer.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		return nil, ErrMachineInfo
	}
	signed := plain
	var signedAt time.Time
	if len(signer.Attributes) != 0 {
		seen := make(map[string]bool)
		for _, a := range signer.Attributes {
			if seen[a.Type.String()] || a.Value.Class != 0 || a.Value.Tag != asn1.TagSet || !a.Value.IsCompound {
				return nil, ErrMachineInfo
			}
			seen[a.Type.String()] = true
			switch {
			case a.Type.Equal(machineOIDContent):
				var oid asn1.ObjectIdentifier
				if !machineASN1(a.Value.Bytes, &oid) || !oid.Equal(machineOIDData) {
					return nil, ErrMachineInfo
				}
			case a.Type.Equal(machineOIDDigest):
				var digest []byte
				h := hash.New()
				h.Write(plain)
				if !machineASN1(a.Value.Bytes, &digest) || subtle.ConstantTimeCompare(digest, h.Sum(nil)) != 1 {
					return nil, ErrMachineInfo
				}
			case a.Type.Equal(machineOIDTime):
				if !machineASN1(a.Value.Bytes, &signedAt) || signedAt.IsZero() {
					return nil, ErrMachineInfo
				}
			}
		}
		if !seen[machineOIDContent.String()] || !seen[machineOIDDigest.String()] {
			return nil, ErrMachineInfo
		}
		signed, err = asn1.MarshalWithParams(signer.Attributes, "set")
		if err != nil {
			return nil, ErrMachineInfo
		}
	}
	if leaf.CheckSignature(signature, signed, signer.Signature) != nil {
		return nil, ErrMachineInfo
	}
	info, err := parseMachinePlist(plain)
	if err != nil {
		return nil, ErrMachineInfo
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	info.SignerFingerprint = hex.EncodeToString(fingerprint[:])
	info.SignatureDigest, info.SignedAt = hash.String(), signedAt
	return info, nil
}

func machineASN1(data []byte, target any) bool {
	rest, err := asn1.Unmarshal(data, target)
	return err == nil && len(rest) == 0
}

func machineAlgorithmParameters(a pkix.AlgorithmIdentifier) bool {
	return len(a.Parameters.FullBytes) == 0 || bytes.Equal(a.Parameters.FullBytes, []byte{5, 0})
}

func machineAlgorithms(digest, signature string) (crypto.Hash, x509.SignatureAlgorithm) {
	type algorithms struct {
		digest, rsa, ecdsa string
		hash               crypto.Hash
		rsaAlg, ecdsaAlg   x509.SignatureAlgorithm
	}
	for _, a := range []algorithms{
		{"1.3.14.3.2.26", "1.2.840.113549.1.1.5", "1.2.840.10045.4.1", crypto.SHA1, x509.SHA1WithRSA, x509.ECDSAWithSHA1},
		{"2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2", crypto.SHA256, x509.SHA256WithRSA, x509.ECDSAWithSHA256},
		{"2.16.840.1.101.3.4.2.2", "1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3", crypto.SHA384, x509.SHA384WithRSA, x509.ECDSAWithSHA384},
		{"2.16.840.1.101.3.4.2.3", "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.4", crypto.SHA512, x509.SHA512WithRSA, x509.ECDSAWithSHA512},
	} {
		if digest != a.digest {
			continue
		}
		if signature == "1.2.840.113549.1.1.1" || signature == a.rsa {
			return a.hash, a.rsaAlg
		}
		if signature == a.ecdsa {
			return a.hash, a.ecdsaAlg
		}
	}
	return 0, x509.UnknownSignatureAlgorithm
}

func machineKey(key any) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N != nil && k.N.BitLen() >= 1024 && k.N.BitLen() <= 8192 && k.E >= 3 && k.E&1 == 1
	case *ecdsa.PublicKey:
		return k.Curve != nil && k.Curve.Params().BitSize >= 256 && k.Curve.Params().BitSize <= 521
	}
	return false
}

func machineOctets(value asn1.RawValue) ([]byte, error) {
	if value.Class != 0 || value.Tag != asn1.TagOctetString {
		return nil, ErrMachineInfo
	}
	if !value.IsCompound {
		return value.Bytes, nil
	}
	var result []byte
	for rest := value.Bytes; len(rest) != 0; {
		var child asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &child)
		if err != nil {
			return nil, ErrMachineInfo
		}
		part, err := machineOctets(child)
		if err != nil || len(result)+len(part) > maxMachinePlist {
			return nil, ErrMachineInfo
		}
		result = append(result, part...)
	}
	return result, nil
}
