package windows

import (
	"crypto/hmac"
	"crypto/md5" // Required by OMA DM 1.2 DIGEST; used only inside authenticated TLS.
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrSyncMLCredential = errors.New("invalid native Windows SyncML credential")

const syncMLDigestType = "syncml:auth-md5"

// syncMLDigest implements OMA DM Security 1.2.1 section 5.3.2. This is not HTTP
// Digest or HMAC: B64(MD5(B64(MD5(username:password)):rawNonce)). The base64
// provisioning/challenge nonce is decoded before hashing. This primitive does
// not authorize a session; TLS identity, nonce rotation and message sequencing
// must be enforced by the session transaction before any management operation.
func syncMLDigest(username, secret, nonce string) (string, error) {
	if !validSyncMLDigestText(username, 320) || strings.Contains(username, ":") || !validSyncMLDigestText(secret, 1024) {
		return "", ErrSyncMLCredential
	}
	rawNonce, err := decodeSyncMLNonce(nonce)
	if err != nil {
		return "", err
	}
	defer clear(rawNonce)
	h := md5.New()
	h.Write([]byte(username))
	h.Write([]byte{':'})
	h.Write([]byte(secret))
	inner := h.Sum(nil)
	defer clear(inner)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(inner)))
	base64.StdEncoding.Encode(encoded, inner)
	defer clear(encoded)
	h.Reset()
	h.Write(encoded)
	h.Write([]byte{':'})
	h.Write(rawNonce)
	digest := h.Sum(nil)
	defer clear(digest)
	return base64.StdEncoding.EncodeToString(digest), nil
}

func validSyncMLDigestText(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func decodeSyncMLNonce(value string) ([]byte, error) {
	// Server nonces contain 32 random octets. Accept bounded peer challenges
	// with at least 128 bits, as recommended by OMA DM Security section 5.3.3.
	if len(value) < 24 || len(value) > 344 {
		return nil, ErrSyncMLCredential
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < 16 || len(decoded) > 256 || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, ErrSyncMLCredential
	}
	return decoded, nil
}

func verifySyncMLDigest(username, secret, nonce, credential string) error {
	if len(credential) != 24 {
		return ErrSyncMLCredential
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(credential)
	defer clear(decoded)
	if err != nil || len(decoded) != md5.Size || base64.StdEncoding.EncodeToString(decoded) != credential {
		return ErrSyncMLCredential
	}
	expected, err := syncMLDigest(username, secret, nonce)
	if err != nil || !hmac.Equal([]byte(expected), []byte(credential)) {
		return ErrSyncMLCredential
	}
	return nil
}
