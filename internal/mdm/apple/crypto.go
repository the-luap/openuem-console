package apple

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

type secretBox struct{ aead cipher.AEAD }

func newSecretBox(master string) (*secretBox, error) {
	if len(master) < 32 {
		return nil, errors.New("Apple management requires an encryption master key of at least 32 characters")
	}
	key := sha256.Sum256([]byte("openuem/apple/secrets/v1\x00" + master))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secretBox{aead}, nil
}

func (b *secretBox) seal(data []byte, purpose string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, data, []byte(purpose)), nil
}

func (b *secretBox) open(data []byte, purpose string) ([]byte, error) {
	if len(data) < b.aead.NonceSize() {
		return nil, errors.New("invalid encrypted Apple management secret")
	}
	return b.aead.Open(nil, data[:b.aead.NonceSize()], data[b.aead.NonceSize():], []byte(purpose))
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
