package sessiongeneration

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

func TestGenerationStampRejectsMissingOrMixedIdentity(t *testing.T) {
	stamp := Stamp{Version: 1, UserID: "owned-user", Method: loginproof.Password, Account: uuid.NewString(), Policy: uuid.NewString()}
	if parsed, err := Read(stamp.Encode(), stamp.UserID, stamp.Method); err != nil || parsed != stamp {
		t.Fatal("valid generation stamp rejected", err)
	}
	for _, raw := range []string{"", "null", "{}", stamp.Encode() + `{}`, stamp.Encode()[:len(stamp.Encode())-1] + `,"unexpected":true}`, strings.Repeat("x", 2049)} {
		if _, err := Read(raw, stamp.UserID, stamp.Method); !errors.Is(err, ErrChanged) {
			t.Fatal("malformed generation accepted", err)
		}
	}
	for _, invalid := range []Stamp{
		{Version: 2, UserID: stamp.UserID, Method: stamp.Method, Account: stamp.Account, Policy: stamp.Policy},
		{Version: 1, UserID: "different-user", Method: stamp.Method, Account: stamp.Account, Policy: stamp.Policy},
		{Version: 1, UserID: stamp.UserID, Method: loginproof.Certificate, Account: stamp.Account, Policy: stamp.Policy},
		{Version: 1, UserID: stamp.UserID, Method: stamp.Method, Account: "invalid", Policy: stamp.Policy},
		{Version: 1, UserID: stamp.UserID, Method: stamp.Method, Account: stamp.Account, Policy: "00000000-0000-0000-0000-000000000000"},
	} {
		if _, err := Read(invalid.Encode(), stamp.UserID, stamp.Method); !errors.Is(err, ErrChanged) {
			t.Fatal("invalid generation accepted", err)
		}
	}
}

func TestCertificateStampRequiresItsOwnGeneration(t *testing.T) {
	s := Stamp{Version: 1, UserID: "owned-user", Method: loginproof.Certificate, Account: uuid.NewString(), Policy: uuid.NewString(), Certificate: uuid.NewString()}
	if got, err := Read(s.Encode(), s.UserID, s.Method); err != nil || got != s {
		t.Fatal("valid certificate stamp rejected", err)
	}
	for _, value := range []string{"", "invalid", "00000000-0000-0000-0000-000000000000"} {
		invalid := s
		invalid.Certificate = value
		if _, err := Read(invalid.Encode(), s.UserID, s.Method); !errors.Is(err, ErrChanged) {
			t.Fatal("missing or malformed certificate generation accepted", err)
		}
	}
	s.Method = loginproof.Password
	if _, err := Read(s.Encode(), s.UserID, s.Method); !errors.Is(err, ErrChanged) {
		t.Fatal("password stamp inherited certificate metadata", err)
	}
}
