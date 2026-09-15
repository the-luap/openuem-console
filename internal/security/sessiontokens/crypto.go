// Package sessiontokens reads the existing AES-GCM/hex session-token format
// without assuming that every legacy database record is encrypted or well formed.
package sessiontokens

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

func Decode(record, key string) (plain string, encrypted bool, err error) {
	if key == "" {
		return record, false, nil
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false, err
	}
	data, err := hex.DecodeString(record)
	if err != nil || len(data) < gcm.NonceSize()+gcm.Overhead() {
		return record, false, nil
	}
	clear, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return record, false, nil
	}
	return string(clear), true, nil
}
