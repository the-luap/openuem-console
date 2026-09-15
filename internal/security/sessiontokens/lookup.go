package sessiontokens

import "crypto/sha256"

// Lookup is an index key, never a browser credential. SCS generates random
// 256-bit tokens, so the digest does not expose a practical token search space.
func Lookup(token string) []byte {
	hash := sha256.Sum256([]byte("openuem/session-token/v1\x00" + token))
	return hash[:]
}
