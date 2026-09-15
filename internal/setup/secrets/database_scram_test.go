package secrets

import (
	"bytes"
	"strings"
	"testing"
)

func TestInstallationSecretsDatabaseSCRAM(t *testing.T) {
	password := strings.Repeat("A", 43)
	salt := bytes.Repeat([]byte{7}, 16)
	verifier := databaseSCRAM(password, salt)
	if !validDatabaseSCRAM(password, verifier) || validDatabaseSCRAM(password+"B", verifier) {
		t.Fatal("SCRAM does not bind the original password")
	}
	for _, invalid := range []string{"", verifier + "\n", strings.Replace(verifier, "4096:", "1:", 1), verifier[:len(verifier)-1], strings.Repeat("x", 8192)} {
		if validDatabaseSCRAM(password, invalid) {
			t.Fatal("malformed SCRAM verifier accepted")
		}
	}
	if databaseSCRAM(password, bytes.Repeat([]byte{8}, 16)) == verifier {
		t.Fatal("SCRAM salt did not separate identities")
	}
}
