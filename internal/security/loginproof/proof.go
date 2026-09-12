// Package loginproof binds a pending MFA step to a recently verified first
// factor. Proofs live only in the server-side session, never in browser input.
package loginproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

const SessionKey = "login-primary"
const Password = "password"
const Certificate = "certificate"
const OpenID = "openid"
const Lifetime = 15 * time.Minute

var ErrInvalid = errors.New("primary authentication is missing, changed or expired")

type Proof struct {
	FlowID     string `json:"flow"`
	UserID     string `json:"user"`
	Method     string `json:"method"`
	Credential string `json:"credential"`
	IssuedAt   int64  `json:"issued"`
	ExpiresAt  int64  `json:"expires"`
}

func Digest(value string) string {
	hash := sha256.Sum256([]byte("openuem/login-primary/v1\x00" + value))
	return hex.EncodeToString(hash[:])
}

func New(userID, method, credential string, now time.Time) string {
	proof := Proof{FlowID: uuid.NewString(), UserID: userID, Method: method, Credential: Digest(credential), IssuedAt: now.Unix(), ExpiresAt: now.Add(Lifetime).Unix()}
	data, _ := json.Marshal(proof)
	return string(data)
}

func Read(raw, userID string, now time.Time) (Proof, error) {
	var proof Proof
	if raw == "" || len(raw) > 4096 || json.Unmarshal([]byte(raw), &proof) != nil || userID == "" || proof.UserID != userID || proof.IssuedAt <= 0 || proof.IssuedAt > now.Add(time.Minute).Unix() || proof.ExpiresAt <= now.Unix() || proof.ExpiresAt-proof.IssuedAt != int64(Lifetime/time.Second) {
		return proof, ErrInvalid
	}
	if proof.Method != Password && proof.Method != Certificate && proof.Method != OpenID {
		return proof, ErrInvalid
	}
	flow, err := uuid.Parse(proof.FlowID)
	if err != nil || flow.Version() != 4 || flow.Variant() != uuid.RFC4122 || flow.String() != proof.FlowID {
		return proof, ErrInvalid
	}
	decoded, err := hex.DecodeString(proof.Credential)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != proof.Credential {
		return proof, ErrInvalid
	}
	return proof, nil
}
