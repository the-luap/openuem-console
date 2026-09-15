package ade

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

func testToken(t *testing.T) *Token {
	t.Helper()
	data, _ := json.Marshal(tokenData{ConsumerKey: "synthetic-consumer", ConsumerSecret: "synthetic-consumer-secret", AccessToken: "synthetic-access", AccessSecret: "synthetic-access-secret", Expiry: time.Now().Add(24 * time.Hour)})
	token, err := ParseToken(data, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(token.Close)
	return token
}

func testTokenCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic ADE recipient"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestServerTokenEnvelopeAndSecretBoundaries(t *testing.T) {
	token := testToken(t)
	cert, key := testTokenCertificate(t)
	plain := token.Bytes()
	defer clear(plain)
	before := pkcs7.ContentEncryptionAlgorithm
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	defer func() { pkcs7.ContentEncryptionAlgorithm = before }()
	inner := append([]byte("Content-Type: text/plain;charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"), plain...)
	encrypted, err := pkcs7.Encrypt(inner, []*x509.Certificate{cert})
	clear(inner)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte("Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(encrypted))
	for _, wire := range [][]byte{encrypted, encoded} {
		result, err := DecryptToken(wire, cert, key, time.Now())
		if err != nil {
			t.Fatal("valid envelope rejected", err)
		}
		if !bytes.Equal(result.Bytes(), plain) {
			t.Fatal("token changed during import")
		}
		if strings.Contains(fmt.Sprintf("%v %#v", result, result), "synthetic-consumer") {
			t.Fatal("token diagnostics exposed a credential")
		}
		if _, err := json.Marshal(result); err == nil {
			t.Fatal("public JSON exposes a token")
		}
		borrowed := result.encoded
		result.Close()
		if !bytes.Equal(borrowed, make([]byte, len(borrowed))) || result.Bytes() != nil {
			t.Fatal("owned encoding not cleared")
		}
	}
	other, _ := testTokenCertificate(t)
	for _, wire := range [][]byte{plain, nil, append(bytes.Clone(encrypted), 0), append(bytes.Clone(encrypted), encrypted...), encoded[:len(encoded)-5], bytes.Repeat([]byte{1}, MaxTokenFile+1), bytes.Replace(encoded, []byte("enveloped-data"), []byte("signed-data"), 1)} {
		if _, err := DecryptToken(wire, cert, key, time.Now()); err == nil {
			t.Fatal("invalid token container accepted")
		}
	}
	if _, err := DecryptToken(encrypted, other, key, time.Now()); err == nil {
		t.Fatal("foreign recipient accepted")
	}
	if _, err := DecryptToken(encrypted, cert, &rsa.PrivateKey{}, time.Now()); err == nil {
		t.Fatal("missing private key accepted")
	}
}

func TestTokenRejectsAmbiguityExpiryAndUnsafeCredentials(t *testing.T) {
	token := testToken(t)
	wire := token.Bytes()
	defer clear(wire)
	for _, bad := range [][]byte{
		append(bytes.Clone(wire), []byte(" {}")...),
		bytes.Replace(wire, []byte(`"consumer_key":`), []byte(`"consumer_key":"other","consumer_key":`), 1),
		bytes.Replace(wire, []byte("synthetic-consumer-secret"), []byte(`bad\r\nheader`), 1),
		bytes.Replace(wire, []byte("synthetic-access-secret"), nil, 1),
		[]byte("null"), bytes.Repeat([]byte("{"), maxTokenJSON+1),
	} {
		if _, err := ParseToken(bad, time.Now()); err == nil {
			t.Fatal("unsafe token accepted")
		}
	}
	if _, err := ParseToken(wire, token.ExpiresAt()); err == nil {
		t.Fatal("expired token accepted")
	}
	deep := []byte{0x30, 0x80}
	for range 25 {
		deep = append(deep, 0x30, 0x80)
	}
	for range 26 {
		deep = append(deep, 0, 0)
	}
	if boundedBER(deep) {
		t.Fatal("unbounded BER recursion accepted")
	}
	if !boundedBER([]byte{0x30, 0x80, 0x04, 1, 0, 0, 0}) {
		t.Fatal("bounded indefinite BER rejected")
	}
}

func FuzzTokenBoundaries(f *testing.F) {
	f.Add([]byte(`{"consumer_key":"a"}`))
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxTokenFile {
			return
		}
		_ = boundedBER(data)
		token, _ := ParseToken(data, time.Now())
		if token != nil {
			token.Close()
		}
	})
}
