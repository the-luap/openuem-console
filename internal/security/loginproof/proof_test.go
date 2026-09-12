package loginproof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPrimaryProofIdentityMethodAndLifetime(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	for _, method := range []string{Password, Certificate, OpenID} {
		raw := New("owned-user", method, "owned-credential", now)
		p, err := Read(raw, "owned-user", now)
		if err != nil || p.Method != method || p.Credential != Digest("owned-credential") {
			t.Fatal("fresh proof lost binding", err)
		}
		if _, err = Read(raw, "other-user", now); err == nil {
			t.Fatal("proof transferred to another account")
		}
		if _, err = Read(raw, "owned-user", now.Add(Lifetime)); err == nil {
			t.Fatal("expired proof accepted")
		}
		if _, err = Read(raw, "owned-user", now.Add(-2*time.Minute)); err == nil {
			t.Fatal("future proof accepted")
		}
	}
	valid, _ := Read(New("owned-user", Password, "credential", now), "owned-user", now)
	for _, mutate := range []func(*Proof){
		func(p *Proof) { p.FlowID = "" }, func(p *Proof) { p.FlowID = "not-a-flow" },
		func(p *Proof) { p.Method = "recovery" }, func(p *Proof) { p.Credential = "00" },
		func(p *Proof) { p.IssuedAt = 0 }, func(p *Proof) { p.ExpiresAt++ },
	} {
		p := valid
		mutate(&p)
		data, _ := json.Marshal(p)
		if _, err := Read(string(data), "owned-user", now); err == nil {
			t.Fatal("malformed proof accepted")
		}
	}
	for _, raw := range []string{"", "null", "{}", "{", strings.Repeat("a", 4097)} {
		if _, err := Read(raw, "owned-user", now); err == nil {
			t.Fatal("missing or oversized proof accepted")
		}
	}
}

func TestPrimaryFlowsAreDistinctWithinTheSameSecond(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	seen := make(map[string]bool)
	for range 32 {
		proof, err := Read(New("owned-user", Password, "owned-credential", now), "owned-user", now)
		if err != nil || seen[proof.FlowID] {
			t.Fatal("separate authentications shared one flow", err)
		}
		seen[proof.FlowID] = true
	}
}
