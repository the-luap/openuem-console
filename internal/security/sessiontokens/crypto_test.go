package sessiontokens

import (
	"github.com/open-uem/utils"
	"strings"
	"testing"
)

func TestLegacySessionTokenDecoding(t *testing.T) {
	key := strings.Repeat("k", 32)
	for _, plain := range []string{"", "0", "00", "deadbeef", "not-hex", strings.Repeat("a", 43), strings.Repeat("a", 100)} {
		decoded, encrypted, err := Decode(plain, key)
		if err != nil || encrypted || decoded != plain {
			t.Fatal("legacy record changed", encrypted, err)
		}
	}
	plain := strings.Repeat("b", 43)
	record, err := utils.EncryptSensitiveField(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, encrypted, err := Decode(record, key); err != nil || !encrypted || decoded != plain {
		t.Fatal("existing ciphertext format lost", err)
	}
	if _, encrypted, err := Decode(record, strings.Repeat("x", 32)); err != nil || encrypted {
		t.Fatal("wrong key decoded a session", err)
	}
	if _, _, err = Decode(record, "invalid-key"); err == nil {
		t.Fatal("invalid cipher key accepted")
	}
}

func FuzzSessionTokenDecoder(f *testing.F) {
	for _, seed := range []string{"", "00", "deadbeef", strings.Repeat("0", 56), "non-hex"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, record string) {
		if len(record) > 1<<20 {
			t.Skip()
		}
		if _, _, err := Decode(record, strings.Repeat("k", 32)); err != nil {
			t.Fatal(err)
		}
	})
}
