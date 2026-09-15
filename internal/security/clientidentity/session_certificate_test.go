package clientidentity

import (
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

func TestSessionCertificateRequiresMatchingCurrentProof(t *testing.T) {
	credential, _ := testCertificate(t, "owned-user")
	now := time.Now()
	raw := EncodeSessionCertificate(credential.Leaf)
	digest := loginproof.Digest(string(credential.Leaf.Raw))
	cert, err := ReadSessionCertificate(raw, "owned-user", digest, now)
	if err != nil || cert == nil || cert.SerialNumber.Cmp(credential.Leaf.SerialNumber) != 0 {
		t.Fatal("valid retained certificate failed", err)
	}
	for _, invalid := range []struct {
		name, raw, uid, digest string
		now                    time.Time
	}{
		{"empty", "", "owned-user", digest, now},
		{"oversized", strings.Repeat("A", 24<<10+1), "owned-user", digest, now},
		{"malformed", "%%%", "owned-user", digest, now},
		{"not DER", base64.StdEncoding.EncodeToString([]byte("owned non-certificate")), "owned-user", loginproof.Digest("owned non-certificate"), now},
		{"wrong user", raw, "other-owned-user", digest, now},
		{"wrong primary", raw, "owned-user", loginproof.Digest("different verified certificate"), now},
		{"expired", raw, "owned-user", digest, credential.Leaf.NotAfter},
		{"not yet valid", raw, "owned-user", digest, credential.Leaf.NotBefore.Add(-time.Nanosecond)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if _, err := ReadSessionCertificate(invalid.raw, invalid.uid, invalid.digest, invalid.now); !errors.Is(err, ErrCertificateBinding) {
				t.Fatal("invalid retained certificate accepted", err)
			}
		})
	}
	for _, serial := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 64)} {
		copy := *credential.Leaf
		copy.SerialNumber = serial
		if CurrentUserCertificate(&copy, "owned-user", now) {
			t.Fatal("unrepresentable registry serial accepted")
		}
	}
	if EncodeSessionCertificate(nil) != "" || CurrentUserCertificate(nil, "owned-user", now) {
		t.Fatal("missing certificate accepted")
	}
}
