package mfaadmission

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/pquerna/otp/totp"
)

func TestTOTPEvidenceTracksAcceptedCounterAndCanonicalSecret(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 15, 0, time.UTC)
	secret := base32.StdEncoding.EncodeToString([]byte("owned synthetic factor"))
	proof := loginproof.New("owned-user", loginproof.Password, "credential", now)
	for _, offset := range []int64{0, 1, -1} {
		code, err := totp.GenerateCode(secret, now.Add(time.Duration(offset)*30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		var first *Evidence
		for _, encoded := range []string{secret, strings.TrimRight(secret, "="), " \t" + strings.ToLower(secret) + "\n"} {
			evidence, err := TOTP(proof, "owned-user", encoded, code, now)
			if err != nil || evidence.counter != now.Unix()/30+offset {
				t.Fatal("incorrect accepted counter", offset, err)
			}
			if first != nil && first.secretDigest != evidence.secretDigest {
				t.Fatal("equivalent secret encoding changed the replay key")
			}
			first = evidence
		}
	}
	for _, offset := range []int64{-3, 3} {
		code, err := totp.GenerateCode(secret, now.Add(time.Duration(offset)*30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = TOTP(proof, "owned-user", secret, code, now); err == nil {
			t.Fatal("out-of-window TOTP accepted")
		}
	}
}

func TestMFAEvidenceRejectsMissingProofAndMalformedFactors(t *testing.T) {
	now := time.Now()
	const secret = "JBSWY3DPEHPK3PXP"
	proof := loginproof.New("owned-user", loginproof.Password, "credential", now)
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "123", "abcdef", strings.Repeat("1", 257)} {
		if _, err = TOTP(proof, "owned-user", secret, bad, now); err == nil {
			t.Fatal("malformed passcode accepted")
		}
	}
	for _, bad := range []string{"", "00", "invalid!", strings.Repeat("A", 4097)} {
		if _, err = TOTP(proof, "owned-user", bad, code, now); err == nil {
			t.Fatal("malformed secret accepted")
		}
	}
	for _, bad := range []string{"", "{}", loginproof.New("another-user", loginproof.Password, "credential", now), loginproof.New("owned-user", loginproof.Password, "credential", now.Add(-loginproof.Lifetime))} {
		if _, err = TOTP(bad, "owned-user", secret, code, now); err == nil {
			t.Fatal("invalid primary proof authorized TOTP")
		}
		if _, err = Backup(bad, "owned-user", now); err == nil {
			t.Fatal("invalid primary proof authorized backup admission")
		}
	}
	if evidence, err := Backup(proof, "owned-user", now); err != nil || evidence.kind != "backup" {
		t.Fatal("valid primary proof lost backup admission", err)
	}
}
