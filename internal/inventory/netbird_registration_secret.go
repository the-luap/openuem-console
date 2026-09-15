package inventory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const netbirdRegistrationSecretPrefix = "openuem:netbird-registration:v1:"
const maxNetbirdRegistrationSecret = 32768

func registrationCipher(master string) (cipher.AEAD, error) {
	if len(master) != 32 {
		return nil, ErrNetbirdOperationInvalid
	}
	key, err := hkdf.Key(sha256.New, []byte(master), nil, netbirdRegistrationSecretPrefix, 32)
	if err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	return cipher.NewGCM(block)
}

// Every envelope authenticates its original request, scope, reviewed provider
// revision and purpose. Setup-key envelopes additionally bind the exact key ID.
// There is deliberately no plaintext or legacy-format fallback.
func registrationAAD(r *NetbirdRegistration, kind, keyID string) []byte {
	data, _ := json.Marshal([]any{netbirdRegistrationSecretPrefix, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.Actor, r.Individual, r.Revision, kind, keyID})
	return data
}

func sealRegistration(aead cipher.AEAD, r *NetbirdRegistration, kind, keyID string, plain []byte) (string, error) {
	if aead == nil || len(plain) == 0 || len(plain) > maxNetbirdRegistrationSecret {
		return "", ErrNetbirdOperationInvalid
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrNetbirdOperationInvalid
	}
	return netbirdRegistrationSecretPrefix + base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, registrationAAD(r, kind, keyID))), nil
}

func openRegistration(aead cipher.AEAD, r *NetbirdRegistration, kind, keyID, envelope string) ([]byte, error) {
	if aead == nil || len(envelope) > 45000 || !strings.HasPrefix(envelope, netbirdRegistrationSecretPrefix) {
		return nil, ErrNetbirdOperationInvalid
	}
	encoded := strings.TrimPrefix(envelope, netbirdRegistrationSecretPrefix)
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != encoded || len(data) <= aead.NonceSize()+aead.Overhead() || len(data) > maxNetbirdRegistrationSecret+aead.NonceSize()+aead.Overhead() {
		return nil, ErrNetbirdOperationInvalid
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], registrationAAD(r, kind, keyID))
	if err != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	return plain, nil
}
