package windows

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestWindowsEnrollmentPasswordBoundaries(t *testing.T) {
	id := "d62c6720-0989-4a51-a1b6-103491d8eca4"
	secret := []byte("0123456789abcdef0123456789abcdef")
	if len(secret) != 32 {
		t.Fatal("incorrect synthetic secret length")
	}
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	valid := "owin1." + id + "." + encoded
	decodedID, decoded, err := decodeEnrollmentPassword(valid)
	if err != nil || decodedID != id || string(decoded) != string(secret) {
		t.Fatal("canonical generated password did not round-trip")
	}
	for _, password := range []string{
		"", valid + " ", " " + valid, valid + "=", strings.Replace(valid, "owin1.", "owin2.", 1),
		strings.Replace(valid, id, strings.ToUpper(id), 1), strings.Replace(valid, id, strings.ReplaceAll(id, "-", ""), 1),
		strings.Replace(valid, id, "00000000-0000-0000-0000-000000000000", 1),
		"owin1." + id + "." + strings.Repeat("A", 42) + "!", "owin1." + id + "." + strings.Repeat("A", 42) + "B",
		"owin1." + id + "." + encoded[:10] + "\n" + encoded[11:], strings.Repeat("x", 2048),
	} {
		if got, secret, err := decodeEnrollmentPassword(password); err != ErrCredential || got != "" || secret != nil {
			t.Fatal("noncanonical enrollment secret was admitted")
		}
	}
	if s, err := NewStore(nil); s != nil || err != ErrStore {
		t.Fatal("nil database admitted")
	}
}
