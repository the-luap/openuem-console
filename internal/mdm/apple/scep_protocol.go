package apple

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

const maxSCEPMessage = 128 << 10

var errSCEPMessage = errors.New("invalid SCEP message")

var (
	scepMessageTypeOID    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	scepStatusOID         = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	scepFailInfoOID       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	scepSenderNonceOID    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	scepRecipientNonceOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	scepTransactionOID    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	scepChallengeOID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

func init() {
	// This separate PKCS#7 package is used only by the SCEP adapter. Set its
	// process-wide encryption choice once, before any goroutine can use it.
	// AES-128-CBC is the mandatory interoperable SCEP cipher (RFC 8894 §2.9).
	// Its default DES encryption must never be used for our responses.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
}

type scepRequest struct {
	message   *scep.PKIMessage
	signer    *x509.Certificate
	csr       *x509.CertificateRequest
	challenge string
}

// The upstream CMS decoder requests RSA PKCS#1 v1.5 decryption without a
// session-key length. Supply it explicitly so invalid RSA padding produces a
// random AES key instead of an observable padding error (RFC 3218).
type scepSessionDecrypter struct {
	*rsa.PrivateKey
	size int
}

func (k scepSessionDecrypter) Decrypt(random io.Reader, ciphertext []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return k.PrivateKey.Decrypt(random, ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: k.size})
}

// boundSCEPDER bounds ASN.1 recursion before the library's BER decoder runs.
// This endpoint accepts complete, definite-length DER objects, never trailing
// messages, indefinite lengths or an unbounded nested ASN.1 input.
func boundSCEPDER(data []byte) error {
	if len(data) == 0 || len(data) > maxSCEPMessage {
		return errSCEPMessage
	}
	nodes := 0
	var walk func([]byte, int, bool) error
	walk = func(data []byte, depth int, single bool) error {
		if depth > 24 {
			return errSCEPMessage
		}
		count := 0
		for len(data) > 0 {
			nodes++
			count++
			if nodes > 4096 || (single && count > 1) {
				return errSCEPMessage
			}
			var value asn1.RawValue
			rest, err := asn1.Unmarshal(data, &value)
			if err != nil || len(rest) >= len(data) {
				return errSCEPMessage
			}
			if value.IsCompound {
				if err = walk(value.Bytes, depth+1, false); err != nil {
					return err
				}
			}
			data = rest
		}
		return nil
	}
	return walk(data, 0, true)
}

func scepRSA(key any) bool {
	rsaKey, ok := key.(*rsa.PublicKey)
	return ok && rsaKey.N != nil && rsaKey.N.Sign() > 0 && rsaKey.N.Bit(0) == 1 && rsaKey.N.BitLen() >= 2048 && rsaKey.N.BitLen() <= 4096 && rsaKey.E >= 65537 && rsaKey.E <= 1<<31-1 && rsaKey.E%2 == 1
}

func scepDigest(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(pkcs7.OIDDigestAlgorithmSHA256) || oid.Equal(pkcs7.OIDDigestAlgorithmSHA384) || oid.Equal(pkcs7.OIDDigestAlgorithmSHA512)
}

func scepSignature(oid, digest asn1.ObjectIdentifier) bool {
	return oid.Equal(pkcs7.OIDEncryptionAlgorithmRSA) ||
		(oid.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256) && digest.Equal(pkcs7.OIDDigestAlgorithmSHA256)) ||
		(oid.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA384) && digest.Equal(pkcs7.OIDDigestAlgorithmSHA384)) ||
		(oid.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA512) && digest.Equal(pkcs7.OIDDigestAlgorithmSHA512))
}

func parseSCEPRequest(data []byte, ra *x509.Certificate, key crypto.PrivateKey, now time.Time) (*scepRequest, error) {
	if err := boundSCEPDER(data); err != nil {
		return nil, err
	}
	p7, err := pkcs7.Parse(data)
	if err != nil || len(p7.Signers) != 1 || len(p7.Certificates) == 0 || len(p7.Certificates) > 5 {
		return nil, errSCEPMessage
	}
	signer := p7.GetOnlySigner()
	if signer == nil || signer.IsCA || !scepRSA(signer.PublicKey) || now.Before(signer.NotBefore) || !now.Before(signer.NotAfter) {
		return nil, errSCEPMessage
	}
	// An untrusted certificate set must not make issuer/serial lookup ambiguous.
	for i, c := range p7.Certificates {
		for _, other := range p7.Certificates[:i] {
			if c.SerialNumber.Cmp(other.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, other.RawIssuer) {
				return nil, errSCEPMessage
			}
		}
	}
	info := p7.Signers[0]
	if !scepDigest(info.DigestAlgorithm.Algorithm) || !scepSignature(info.DigestEncryptionAlgorithm.Algorithm, info.DigestAlgorithm.Algorithm) || len(info.AuthenticatedAttributes) > 12 {
		return nil, errSCEPMessage
	}
	seen := make(map[string]bool)
	for _, attribute := range info.AuthenticatedAttributes {
		name := attribute.Type.String()
		if seen[name] || attribute.Value.Class != asn1.ClassUniversal || attribute.Value.Tag != asn1.TagSet || !attribute.Value.IsCompound {
			return nil, errSCEPMessage
		}
		seen[name] = true
		var value asn1.RawValue
		if rest, err := asn1.Unmarshal(attribute.Value.Bytes, &value); err != nil || len(rest) != 0 {
			return nil, errSCEPMessage
		}
	}
	for _, oid := range []asn1.ObjectIdentifier{scepMessageTypeOID, scepTransactionOID, scepSenderNonceOID, pkcs7.OIDAttributeMessageDigest, pkcs7.OIDAttributeContentType} {
		if !seen[oid.String()] {
			return nil, errSCEPMessage
		}
	}
	var contentType asn1.ObjectIdentifier
	if err = p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType); err != nil || !contentType.Equal(pkcs7.OIDData) {
		return nil, errSCEPMessage
	}
	// Verify the outer signature before decrypting. This verifies possession,
	// not authorization: the store separately validates the challenge or pins
	// this signer to the still-authorized device's active certificate.
	message, err := scep.ParsePKIMessage(data)
	if err != nil || (message.MessageType != scep.PKCSReq && message.MessageType != scep.RenewalReq) || len(message.SenderNonce) != 16 || len(message.TransactionID) == 0 || len(message.TransactionID) > 128 {
		return nil, errSCEPMessage
	}
	for _, c := range string(message.TransactionID) {
		if c < 32 || c > 126 {
			return nil, errSCEPMessage
		}
	}
	keySize, err := scepEnvelopeKeySize(p7.Content)
	if err != nil {
		return nil, err
	}
	raKey, ok := key.(*rsa.PrivateKey)
	if !ok || raKey == nil {
		return nil, errSCEPMessage
	}
	if err = message.DecryptPKIEnvelope(ra, scepSessionDecrypter{PrivateKey: raKey, size: keySize}); err != nil || message.CSRReqMessage == nil || message.CSR == nil {
		return nil, errSCEPMessage
	}
	csr := message.CSR
	if err = boundSCEPDER(csr.Raw); err != nil || len(csr.Raw) > 32<<10 || csr.Version != 0 || !scepRSA(csr.PublicKey) {
		return nil, errSCEPMessage
	}
	if csr.SignatureAlgorithm != x509.SHA256WithRSA && csr.SignatureAlgorithm != x509.SHA384WithRSA && csr.SignatureAlgorithm != x509.SHA512WithRSA {
		return nil, errSCEPMessage
	}
	// The library decrypts a request without verifying its independent CSR
	// signature. Renewal may use different old/new keys, so both proofs matter.
	if err = csr.CheckSignature(); err != nil {
		return nil, errSCEPMessage
	}
	challenge, err := scepChallenge(csr.Raw)
	if err != nil || challenge != message.ChallengePassword {
		return nil, errSCEPMessage
	}
	if message.MessageType == scep.PKCSReq && !bytes.Equal(csr.RawSubjectPublicKeyInfo, signer.RawSubjectPublicKeyInfo) {
		return nil, errSCEPMessage
	}
	return &scepRequest{message: message, signer: signer, csr: csr, challenge: challenge}, nil
}

// Inspect only the envelope metadata; cryptography remains in the library.
// RSA key transport and AES-CBC match the advertised SCEP capabilities.
func validateSCEPEnvelope(data []byte) error {
	_, err := scepEnvelopeKeySize(data)
	return err
}

func scepEnvelopeKeySize(data []byte) (int, error) {
	if err := boundSCEPDER(data); err != nil {
		return 0, err
	}
	var outer struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if rest, err := asn1.Unmarshal(data, &outer); err != nil || len(rest) != 0 || !outer.Type.Equal(pkcs7.OIDEnvelopedData) {
		return 0, errSCEPMessage
	}
	var envelope struct {
		Version    int
		Recipients []struct {
			Version   int
			Issuer    asn1.RawValue
			Algorithm pkix.AlgorithmIdentifier
			Key       []byte
		} `asn1:"set"`
		Content struct {
			Type      asn1.ObjectIdentifier
			Algorithm pkix.AlgorithmIdentifier
			Encrypted asn1.RawValue `asn1:"tag:0"`
		}
	}
	if rest, err := asn1.Unmarshal(outer.Content.Bytes, &envelope); err != nil || len(rest) != 0 || len(envelope.Recipients) == 0 || len(envelope.Recipients) > 5 || !envelope.Content.Type.Equal(pkcs7.OIDData) {
		return 0, errSCEPMessage
	}
	// The library's CBC decoder panics for partial blocks and recursively joins
	// constructed ciphertext. Accept only a bounded, primitive full-block value.
	content := envelope.Content.Encrypted
	if envelope.Version != 0 || content.Class != asn1.ClassContextSpecific || content.Tag != 0 || content.IsCompound || len(content.Bytes) == 0 || len(content.Bytes)%16 != 0 {
		return 0, errSCEPMessage
	}
	algorithm := envelope.Content.Algorithm.Algorithm
	if !algorithm.Equal(pkcs7.OIDEncryptionAlgorithmAES128CBC) && !algorithm.Equal(pkcs7.OIDEncryptionAlgorithmAES256CBC) {
		return 0, errSCEPMessage
	}
	if envelope.Content.Algorithm.Parameters.Class != asn1.ClassUniversal || envelope.Content.Algorithm.Parameters.Tag != asn1.TagOctetString || envelope.Content.Algorithm.Parameters.IsCompound || len(envelope.Content.Algorithm.Parameters.Bytes) != 16 {
		return 0, errSCEPMessage
	}
	for _, recipient := range envelope.Recipients {
		if recipient.Version != 0 || !recipient.Algorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA) || len(recipient.Key) < 256 || len(recipient.Key) > 512 {
			return 0, errSCEPMessage
		}
	}
	if algorithm.Equal(pkcs7.OIDEncryptionAlgorithmAES256CBC) {
		return 32, nil
	}
	return 16, nil
}

// Reject duplicated/multivalued challenge attributes instead of accepting the
// library parser's last matching attribute. A challenge is a single-use secret.
func scepChallenge(data []byte) (string, error) {
	var request struct {
		Info struct {
			Raw        asn1.RawContent
			Version    int
			Subject    asn1.RawValue
			Key        asn1.RawValue
			Attributes []asn1.RawValue `asn1:"tag:0"`
		}
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(data, &request); err != nil || len(rest) != 0 || len(request.Info.Attributes) > 16 {
		return "", errSCEPMessage
	}
	seen := false
	challenge := ""
	for _, raw := range request.Info.Attributes {
		var attribute struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		if rest, err := asn1.Unmarshal(raw.FullBytes, &attribute); err != nil || len(rest) != 0 {
			return "", errSCEPMessage
		}
		if attribute.Type.Equal(scepChallengeOID) {
			if seen || attribute.Values.Class != asn1.ClassUniversal || attribute.Values.Tag != asn1.TagSet || !attribute.Values.IsCompound {
				return "", errSCEPMessage
			}
			seen = true
			if rest, err := asn1.Unmarshal(attribute.Values.Bytes, &challenge); err != nil || len(rest) != 0 || len(challenge) > 128 {
				return "", errSCEPMessage
			}
		}
	}
	return challenge, nil
}

func (r *scepRequest) response(ra *x509.Certificate, key crypto.PrivateKey, issuer, certificate *x509.Certificate, failure scep.FailInfo) ([]byte, error) {
	var content []byte
	status := scep.FAILURE
	if certificate != nil {
		degenerate, err := scep.DegenerateCertificates([]*x509.Certificate{certificate, issuer})
		if err != nil {
			return nil, errSCEPMessage
		}
		// Encrypt only to the authenticated signer, never every certificate an
		// unauthenticated peer happened to include in its outer CMS certificate set.
		content, err = pkcs7.Encrypt(degenerate, []*x509.Certificate{r.signer})
		if err != nil {
			return nil, errSCEPMessage
		}
		status = scep.SUCCESS
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	attributes := []pkcs7.Attribute{{Type: scepTransactionOID, Value: r.message.TransactionID}, {Type: scepMessageTypeOID, Value: scep.CertRep}, {Type: scepStatusOID, Value: status}, {Type: scepSenderNonceOID, Value: nonce}, {Type: scepRecipientNonceOID, Value: r.message.SenderNonce}}
	if status == scep.FAILURE {
		attributes = append(attributes, pkcs7.Attribute{Type: scepFailInfoOID, Value: failure})
	}
	signed, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, errSCEPMessage
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err = signed.AddSignerChain(ra, key, []*x509.Certificate{issuer}, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attributes}); err != nil {
		return nil, errSCEPMessage
	}
	return signed.Finish()
}
