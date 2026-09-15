package apple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func testFileVaultRecipient(t testing.TB) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "FileVault escrow test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func testFileVaultEnvelope(t testing.TB, certificate *x509.Certificate, plain []byte, algorithm asn1.ObjectIdentifier, constructed bool) []byte {
	t.Helper()
	keySize := 16
	if algorithm.Equal(fileVaultAES256OID) {
		keySize = 32
	}
	if algorithm.Equal(fileVaultTripleDESOID) {
		keySize = 24
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	var block cipher.Block
	var err error
	if keySize == 24 {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, block.BlockSize())
	if _, err = rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	padding := block.BlockSize() - len(plain)%block.BlockSize()
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(padding)}, padding)...)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, certificate.PublicKey.(*rsa.PublicKey), key)
	if err != nil {
		t.Fatal(err)
	}
	marshal := func(value any) []byte {
		t.Helper()
		result, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	encrypted := asn1.RawValue{Class: 2, Tag: 0, Bytes: ciphertext}
	if constructed {
		encrypted.IsCompound = true
		encrypted.Bytes = append(marshal(ciphertext[:5]), marshal(ciphertext[5:])...)
	}
	type issuerAndSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	type recipient struct {
		Version         int
		IssuerAndSerial issuerAndSerial
		Algorithm       pkix.AlgorithmIdentifier
		Key             []byte
	}
	type content struct {
		Type      asn1.ObjectIdentifier
		Algorithm pkix.AlgorithmIdentifier
		Encrypted asn1.RawValue `asn1:"tag:0"`
	}
	type envelope struct {
		Version    int
		Recipients []recipient `asn1:"set"`
		Content    content
	}
	body := marshal(envelope{0, []recipient{{0, issuerAndSerial{asn1.RawValue{FullBytes: certificate.RawIssuer}, certificate.SerialNumber}, pkix.AlgorithmIdentifier{Algorithm: fileVaultRSAOID, Parameters: asn1.NullRawValue}, wrapped}}, content{fileVaultDataOID, pkix.AlgorithmIdentifier{Algorithm: algorithm, Parameters: asn1.RawValue{Tag: 4, Bytes: iv}}, encrypted}})
	return marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{fileVaultEnvelopeOID, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: body}})
}

func testIndefiniteBER(t testing.TB, der []byte) []byte {
	t.Helper()
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(der, &value)
	if err != nil || len(rest) != 0 {
		t.Fatal("invalid test DER", err)
	}
	if !value.IsCompound {
		return der
	}
	result := []byte{der[0], 0x80}
	children := value.Bytes
	for len(children) > 0 {
		var child asn1.RawValue
		children, err = asn1.Unmarshal(children, &child)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, testIndefiniteBER(t, child.FullBytes)...)
	}
	return append(result, 0, 0)
}

func TestFileVaultCMSDecryptsAppleBERAndModernAES(t *testing.T) {
	certificate, key := testFileVaultRecipient(t)
	plain := []byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ")
	for _, algorithm := range []asn1.ObjectIdentifier{fileVaultAES128OID, fileVaultAES256OID, fileVaultTripleDESOID} {
		for _, constructed := range []bool{false, true} {
			data := testFileVaultEnvelope(t, certificate, plain, algorithm, constructed)
			for _, wire := range [][]byte{data, testIndefiniteBER(t, data)} {
				result, err := decryptFileVaultRecoveryKey(wire, certificate, key)
				if err != nil || !bytes.Equal(result, plain) {
					t.Fatalf("algorithm %v constructed %v: %v", algorithm, constructed, err)
				}
			}
		}
	}
}

func TestFileVaultCMSRejectsWrongRecipientsAndMalformedData(t *testing.T) {
	certificate, key := testFileVaultRecipient(t)
	data := testFileVaultEnvelope(t, certificate, []byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"), fileVaultAES256OID, true)
	for i := 0; i < len(data); i++ {
		if _, err := decryptFileVaultRecoveryKey(data[:i], certificate, key); !errors.Is(err, errFileVaultEnvelope) {
			t.Fatalf("truncation %d accepted: %v", i, err)
		}
	}
	if _, err := decryptFileVaultRecoveryKey(append(bytes.Clone(data), 0), certificate, key); !errors.Is(err, errFileVaultEnvelope) {
		t.Fatal("trailing data accepted", err)
	}
	otherCertificate, otherKey := testFileVaultRecipient(t)
	for _, pair := range []struct {
		c *x509.Certificate
		k *rsa.PrivateKey
	}{{otherCertificate, otherKey}, {certificate, otherKey}, {otherCertificate, key}, {nil, key}, {certificate, nil}} {
		if _, err := decryptFileVaultRecoveryKey(data, pair.c, pair.k); !errors.Is(err, errFileVaultEnvelope) {
			t.Fatal("wrong escrow recipient accepted", err)
		}
	}
	for _, plain := range []string{"", "abcd-efgh-jklm-npqr-stuv-wxyz", "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ\n", "ABCD-EFGH-JKLM-NPQR-STUV-WXY!", "<plist>secret</plist>"} {
		wire := testFileVaultEnvelope(t, certificate, []byte(plain), fileVaultAES128OID, false)
		if _, err := decryptFileVaultRecoveryKey(wire, certificate, key); !errors.Is(err, errFileVaultEnvelope) {
			t.Fatal("invalid recovery-key format accepted", err)
		}
	}
	for _, wire := range [][]byte{bytes.Repeat([]byte{0x30, 0x80}, 40), append([]byte{0x30, 0x83, 0xff, 0xff, 0xff}, 0), {0x04, 0x80, 0, 0}, bytes.Repeat([]byte{0}, maxFileVaultCMSBytes+1)} {
		nodes := 0
		if _, _, err := normalizeFileVaultBER(wire, 0, &nodes); !errors.Is(err, errFileVaultEnvelope) {
			t.Fatal("unbounded BER accepted", err)
		}
	}
}

func FuzzFileVaultBERBounds(f *testing.F) {
	f.Add([]byte{0x30, 0x80, 0x04, 1, 7, 0, 0})
	f.Add([]byte{0x30, 3, 2, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		nodes := 0
		der, consumed, err := normalizeFileVaultBER(data, 0, &nodes)
		if err == nil {
			if consumed <= 0 || consumed > len(data) || len(der) > maxFileVaultCMSBytes {
				t.Fatal("invalid normalization bounds")
			}
			var value asn1.RawValue
			if rest, err := asn1.Unmarshal(der, &value); err != nil || len(rest) != 0 {
				t.Fatal("normalizer returned invalid DER", err)
			}
		}
	})
}

func FuzzFileVaultCMSDecode(f *testing.F) {
	certificate, key := testFileVaultRecipient(f)
	valid := testFileVaultEnvelope(f, certificate, []byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"), fileVaultAES256OID, true)
	f.Add(valid)
	f.Add(testIndefiniteBER(f, testFileVaultEnvelope(f, certificate, []byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"), fileVaultTripleDESOID, true)))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := decryptFileVaultRecoveryKey(data, certificate, key)
		if err == nil && !validFileVaultRecoveryKey(result) {
			t.Fatal("unvalidated recovery material returned")
		}
		if err != nil && !errors.Is(err, errFileVaultEnvelope) {
			t.Fatal("envelope error exposed parser details")
		}
	})
}
