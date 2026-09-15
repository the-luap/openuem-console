package windows

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestSyncMLDigestIndependentVectors(t *testing.T) {
	// Fixed vectors independently calculated with Python hashlib/base64 from
	// OMA DM Security 1.2.1 section 5.3.2, including raw non-ASCII nonce octets.
	for _, vector := range []struct{ username, secret, nonce, expected string }{
		{"OpenUEM", "synthetic:password", "AAECAwQFBgcICQoLDA0ODw==", "/koTkGRmuxqqJz9KIE1bAw=="},
		{"12345678-1234-4567-89ab-123456789012", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=", "tsN7/CsMWDXmmgkU2iTC5w=="},
		{"Device\u00e9", "p\u00e1ssword", "AP+AOm5vbmNlYnl0ZXMxMjM0NTY3ODk=", "yLuEuwyFyxP7fGGLekpN8w=="},
	} {
		got, err := syncMLDigest(vector.username, vector.secret, vector.nonce)
		if err != nil || got != vector.expected {
			t.Fatal("digest differs from the independent OMA calculation", err)
		}
		if err := verifySyncMLDigest(vector.username, vector.secret, vector.nonce, vector.expected); err != nil {
			t.Fatal("known digest did not authenticate", err)
		}
		for _, wrong := range []struct{ username, secret, nonce string }{
			{vector.username + "x", vector.secret, vector.nonce},
			{vector.username, vector.secret + "x", vector.nonce},
			{vector.username, vector.secret, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))},
		} {
			if err := verifySyncMLDigest(wrong.username, wrong.secret, wrong.nonce, vector.expected); !errors.Is(err, ErrSyncMLCredential) {
				t.Fatal("digest was not bound to username, secret and nonce")
			}
		}
	}
}

func TestSyncMLDigestCanonicalBounds(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32))
	for _, length := range []int{16, 32, 256} {
		value := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, length))
		decoded, err := decodeSyncMLNonce(value)
		if err != nil || len(decoded) != length {
			t.Fatal("valid nonce boundary rejected", err)
		}
		clear(decoded)
		got, err := syncMLDigest(strings.Repeat("u", 320), strings.Repeat("p", 1024), value)
		if err != nil || verifySyncMLDigest(strings.Repeat("u", 320), strings.Repeat("p", 1024), value, got) != nil {
			t.Fatal("valid credential boundary rejected", err)
		}
	}
	for _, invalid := range []string{"", " " + nonce, nonce + "\n", nonce[:4] + "\r\n" + nonce[4:], strings.TrimRight(nonce, "="), strings.ReplaceAll(nonce, "/", "_"), strings.Repeat("!", 24), base64.StdEncoding.EncodeToString(make([]byte, 15)), base64.StdEncoding.EncodeToString(make([]byte, 257)), nonce[:len(nonce)-2] + "9="} {
		if got, err := decodeSyncMLNonce(invalid); !errors.Is(err, ErrSyncMLCredential) || got != nil {
			t.Fatal("invalid or noncanonical nonce accepted")
		}
		if got, err := syncMLDigest("device", "secret", invalid); !errors.Is(err, ErrSyncMLCredential) || got != "" {
			t.Fatal("invalid nonce produced a digest")
		}
	}
	for _, pair := range [][2]string{{"", "secret"}, {"device", ""}, {"user:name", "secret"}, {" device", "secret"}, {"device", "secret "}, {"device\n", "secret"}, {"device", "secret\x00"}, {string([]byte{0xff}), "secret"}, {"device", string([]byte{0xff})}, {strings.Repeat("u", 321), "secret"}, {"device", strings.Repeat("p", 1025)}} {
		if got, err := syncMLDigest(pair[0], pair[1], nonce); !errors.Is(err, ErrSyncMLCredential) || got != "" {
			t.Fatal("invalid credential input produced a digest")
		}
	}
	valid, err := syncMLDigest("device", "secret", nonce)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"", valid + "\n", valid[1:], strings.Repeat("!", 24), strings.Repeat("A", 24), valid[:21] + "B==", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		if err := verifySyncMLDigest("device", "secret", nonce, credential); !errors.Is(err, ErrSyncMLCredential) {
			t.Fatal("wrong or noncanonical digest accepted")
		}
	}
	if err := verifySyncMLDigest("device", "", nonce, valid); !errors.Is(err, ErrSyncMLCredential) {
		t.Fatal("invalid secret admitted during verification")
	}
}

func FuzzSyncMLDigest(f *testing.F) {
	f.Add("OpenUEM", "synthetic:password", "AAECAwQFBgcICQoLDA0ODw==", "/koTkGRmuxqqJz9KIE1bAw==")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, username, secret, nonce, credential string) {
		got, err := syncMLDigest(username, secret, nonce)
		if err == nil {
			if len(got) != 24 || verifySyncMLDigest(username, secret, nonce, got) != nil {
				t.Fatal("generated digest is not canonical or verifiable")
			}
		}
		if verifySyncMLDigest(username, secret, nonce, credential) == nil && (err != nil || got != credential) {
			t.Fatal("different or invalid digest authenticated")
		}
	})
}
