package apple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

var errFileVaultEnvelope = errors.New("FileVault recovery envelope could not be verified")

const maxFileVaultCMSBytes = 64 << 10

var (
	fileVaultDataOID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	fileVaultEnvelopeOID  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	fileVaultRSAOID       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	fileVaultTripleDESOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	fileVaultAES128OID    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	fileVaultAES256OID    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// Apple publishes FileVault responses using indefinite-length BER, constructed
// ciphertext and legacy 3DES. This decoder is separate from SCEP's strict DER
// and AES policy. It is only for decrypting escrow, never for encrypting data.
// All failures have the same public error, without ciphertext or key material.
func decryptFileVaultRecoveryKey(data []byte, certificate *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	if certificate == nil || privateKey == nil || privateKey.N == nil || privateKey.Size() < 256 || privateKey.Size() > 512 || len(data) == 0 || len(data) > maxFileVaultCMSBytes {
		return nil, errFileVaultEnvelope
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey == nil || publicKey.N == nil || publicKey.N.Cmp(privateKey.N) != 0 || publicKey.E != privateKey.E {
		return nil, errFileVaultEnvelope
	}
	nodes := 0
	der, consumed, err := normalizeFileVaultBER(data, 0, &nodes)
	if err != nil || consumed != len(data) {
		return nil, errFileVaultEnvelope
	}
	var outer struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if !fileVaultSequenceFields(der, 2) {
		return nil, errFileVaultEnvelope
	}
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 || !outer.Type.Equal(fileVaultEnvelopeOID) {
		return nil, errFileVaultEnvelope
	}
	var envelope struct {
		Version    int
		Recipients []struct {
			Version         int
			IssuerAndSerial struct {
				Issuer asn1.RawValue
				Serial *big.Int
			}
			Algorithm pkix.AlgorithmIdentifier
			Key       []byte
		} `asn1:"set"`
		Content struct {
			Type      asn1.ObjectIdentifier
			Algorithm pkix.AlgorithmIdentifier
			Encrypted asn1.RawValue `asn1:"tag:0"`
		}
	}
	if !fileVaultSequenceFields(outer.Content.Bytes, 3) {
		return nil, errFileVaultEnvelope
	}
	if rest, err := asn1.Unmarshal(outer.Content.Bytes, &envelope); err != nil || len(rest) != 0 || envelope.Version != 0 || len(envelope.Recipients) != 1 || !envelope.Content.Type.Equal(fileVaultDataOID) {
		return nil, errFileVaultEnvelope
	}
	recipient := envelope.Recipients[0]
	if recipient.Version != 0 || recipient.IssuerAndSerial.Serial == nil || certificate.SerialNumber == nil || recipient.IssuerAndSerial.Serial.Cmp(certificate.SerialNumber) != 0 || !bytes.Equal(recipient.IssuerAndSerial.Issuer.FullBytes, certificate.RawIssuer) || !recipient.Algorithm.Algorithm.Equal(fileVaultRSAOID) || len(recipient.Key) != privateKey.Size() {
		return nil, errFileVaultEnvelope
	}
	if parameters := recipient.Algorithm.Parameters; len(parameters.FullBytes) != 0 && !bytes.Equal(parameters.FullBytes, []byte{5, 0}) {
		return nil, errFileVaultEnvelope
	}
	keySize, blockSize := 0, 16
	switch algorithm := envelope.Content.Algorithm.Algorithm; {
	case algorithm.Equal(fileVaultAES128OID):
		keySize = 16
	case algorithm.Equal(fileVaultAES256OID):
		keySize = 32
	case algorithm.Equal(fileVaultTripleDESOID):
		keySize, blockSize = 24, 8
	default:
		return nil, errFileVaultEnvelope
	}
	iv := envelope.Content.Algorithm.Parameters
	if iv.Class != asn1.ClassUniversal || iv.Tag != asn1.TagOctetString || iv.IsCompound || len(iv.Bytes) != blockSize {
		return nil, errFileVaultEnvelope
	}
	encrypted := envelope.Content.Encrypted
	if encrypted.Class != asn1.ClassContextSpecific || encrypted.Tag != 0 {
		return nil, errFileVaultEnvelope
	}
	ciphertext, err := fileVaultCiphertext(encrypted, 0)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 || len(ciphertext) > 1024 {
		return nil, errFileVaultEnvelope
	}
	// SessionKeyLen replaces an invalid PKCS#1 v1.5 session key with random
	// bytes, avoiding a distinguishable RSA padding error before CBC decoding.
	key, err := privateKey.Decrypt(rand.Reader, recipient.Key, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: keySize})
	if err != nil {
		return nil, errFileVaultEnvelope
	}
	defer clear(key)
	var block cipher.Block
	if blockSize == 8 {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, errFileVaultEnvelope
	}
	plain := make([]byte, len(ciphertext))
	defer clear(plain)
	cipher.NewCBCDecrypter(block, iv.Bytes).CryptBlocks(plain, ciphertext)
	padding := int(plain[len(plain)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, blockSize)
	for i := 0; i < blockSize; i++ {
		match := subtle.ConstantTimeByteEq(plain[len(plain)-1-i], byte(padding))
		selected := subtle.ConstantTimeLessOrEq(i+1, padding)
		valid &= (1 - selected) | match
	}
	if valid != 1 {
		return nil, errFileVaultEnvelope
	}
	plain = plain[:len(plain)-padding]
	if !validFileVaultRecoveryKey(plain) {
		return nil, errFileVaultEnvelope
	}
	return bytes.Clone(plain), nil
}

func validFileVaultRecoveryKey(key []byte) bool {
	if len(key) != 29 {
		return false
	}
	for i, value := range key {
		if i%5 == 4 {
			if value != '-' {
				return false
			}
			continue
		}
		if !(value >= 'A' && value <= 'Z') && !(value >= '0' && value <= '9') {
			return false
		}
	}
	return true
}

func fileVaultSequenceFields(data []byte, count int) bool {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(data, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return false
	}
	data = sequence.Bytes
	for i := 0; i < count; i++ {
		var value asn1.RawValue
		data, err = asn1.Unmarshal(data, &value)
		if err != nil {
			return false
		}
	}
	return len(data) == 0
}

func fileVaultCiphertext(value asn1.RawValue, depth int) ([]byte, error) {
	if depth > 16 {
		return nil, errFileVaultEnvelope
	}
	if !value.IsCompound {
		return value.Bytes, nil
	}
	result := []byte{}
	data := value.Bytes
	for len(data) > 0 {
		var part asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &part)
		if err != nil || part.Class != asn1.ClassUniversal || part.Tag != asn1.TagOctetString {
			return nil, errFileVaultEnvelope
		}
		chunk, err := fileVaultCiphertext(part, depth+1)
		if err != nil || len(result)+len(chunk) > 1024 {
			return nil, errFileVaultEnvelope
		}
		result = append(result, chunk...)
	}
	return result, nil
}

// Bound BER before traversing its values, and produce definite-length encoding
// for encoding/asn1. High-tag-number encodings are not needed by FileVault CMS.
func normalizeFileVaultBER(data []byte, depth int, nodes *int) ([]byte, int, error) {
	*nodes = *nodes + 1
	if depth > 16 || *nodes > 512 || len(data) < 2 || len(data) > maxFileVaultCMSBytes || data[0] == 0 || data[0]&31 == 31 {
		return nil, 0, errFileVaultEnvelope
	}
	tag := data[0]
	position := 2
	indefinite := data[1] == 0x80
	length := int(data[1])
	if indefinite && tag&32 == 0 {
		return nil, 0, errFileVaultEnvelope
	}
	if !indefinite && data[1]&128 != 0 {
		count := int(data[1] & 127)
		if count == 0 || count > 3 || len(data) < 2+count {
			return nil, 0, errFileVaultEnvelope
		}
		length = 0
		for _, b := range data[2 : 2+count] {
			length = length*256 + int(b)
		}
		position += count
	}
	end := len(data)
	if !indefinite {
		if length > len(data)-position {
			return nil, 0, errFileVaultEnvelope
		}
		end = position + length
	}
	var content []byte
	if tag&32 == 0 {
		content = data[position:end]
		position = end
	} else {
		for {
			if indefinite && position+2 <= end && data[position] == 0 && data[position+1] == 0 {
				position += 2
				break
			}
			if position == end && !indefinite {
				break
			}
			if position >= end {
				return nil, 0, errFileVaultEnvelope
			}
			child, consumed, err := normalizeFileVaultBER(data[position:end], depth+1, nodes)
			if err != nil || consumed == 0 {
				return nil, 0, errFileVaultEnvelope
			}
			content = append(content, child...)
			position += consumed
		}
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: int(tag >> 6), Tag: int(tag & 31), IsCompound: tag&32 != 0, Bytes: content})
	if err != nil || len(der) > maxFileVaultCMSBytes {
		return nil, 0, errFileVaultEnvelope
	}
	return der, position, nil
}
