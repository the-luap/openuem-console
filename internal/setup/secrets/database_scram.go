package secrets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Generated passwords are random ASCII, so SASLprep cannot transform them.
// PostgreSQL accepts an already encoded SCRAM verifier without plaintext SQL.
func databaseSCRAM(password string, salt []byte) string {
	salted := pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)
	defer clear(salted)
	mac := hmac.New(sha256.New, salted)
	mac.Write([]byte("Client Key"))
	client := mac.Sum(nil)
	stored := sha256.Sum256(client)
	clear(client)
	mac.Reset()
	mac.Write([]byte("Server Key"))
	server := mac.Sum(nil)
	defer clear(server)
	return "SCRAM-SHA-256$4096:" + base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(stored[:]) + ":" + base64.StdEncoding.EncodeToString(server)
}

func validDatabaseSCRAM(password, verifier string) bool {
	if !strings.HasPrefix(verifier, "SCRAM-SHA-256$4096:") || len(verifier) > 160 {
		return false
	}
	parts := strings.Split(verifier, "$")
	if len(parts) != 3 {
		return false
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(parts[1], "4096:"))
	defer clear(salt)
	return err == nil && len(salt) == 16 && hmac.Equal([]byte(verifier), []byte(databaseSCRAM(password, salt)))
}
