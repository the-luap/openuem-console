// Package mfaadmission consumes verified second-factor evidence in the same
// database transaction as the account's final sign-in confirmation.
package mfaadmission

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

var ErrRejected = errors.New("MFA evidence is missing, expired or already consumed")

// Schema runs within startup migration transactions. Retention is deliberately
// separate from admission: neither consumed flows nor counter records expire.
const Schema = `
SELECT pg_advisory_xact_lock(712036480);
CREATE TABLE IF NOT EXISTS uem_mfa_primary_consumptions (
    flow_id UUID PRIMARY KEY,
    user_id TEXT NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS uem_mfa_totp_counters (
    user_id TEXT NOT NULL,
    secret_digest BYTEA NOT NULL CHECK(octet_length(secret_digest)=32),
    last_counter BIGINT NOT NULL CHECK(last_counter>=0),
    used_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(user_id,secret_digest)
);`

// Evidence is constructed only after verification. It never contains the
// submitted passcode or plaintext TOTP secret.
type Evidence struct {
	primary      string
	kind         string
	counter      int64
	secretDigest [32]byte
}

// PrimaryGeneration exposes only the generation carried by the verified
// primary flow, so final local admission can compare it under source locks.
func (e *Evidence) PrimaryGeneration(uid, method string, now time.Time) (string, error) {
	if e == nil {
		return "", ErrRejected
	}
	proof, err := loginproof.Read(e.primary, uid, now)
	if err != nil || proof.Method != method || proof.Generation == "" {
		return "", ErrRejected
	}
	return proof.Generation, nil
}

// TOTP returns the actual accepted counter with the existing 30-second,
// six-digit SHA-1 policy and one-step clock skew.
func TOTP(primary, uid, secret, passcode string, now time.Time) (*Evidence, error) {
	if _, err := loginproof.Read(primary, uid, now); err != nil {
		return nil, ErrRejected
	}
	secret = strings.ToUpper(strings.TrimSpace(secret))
	passcode = strings.TrimSpace(passcode)
	if secret == "" || len(secret) > 4096 || len(passcode) != 6 || now.Unix() < 30 {
		return nil, ErrRejected
	}
	if padding := len(secret) % 8; padding != 0 {
		secret += strings.Repeat("=", 8-padding)
	}
	decoded, err := base32.StdEncoding.DecodeString(secret)
	if err != nil || len(decoded) == 0 {
		return nil, ErrRejected
	}
	digest := sha256.Sum256(append([]byte("openuem/mfa-totp/v1\x00"), decoded...))
	current := now.Unix() / 30
	for _, counter := range []int64{current, current + 1, current - 1} {
		valid, err := hotp.ValidateCustom(passcode, uint64(counter), secret, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			return nil, ErrRejected
		}
		if valid {
			return &Evidence{primary: primary, kind: "totp", counter: counter, secretDigest: digest}, nil
		}
	}
	return nil, ErrRejected
}

// Backup follows successful atomic recovery-code consumption by the caller.
// It adds one-use primary-flow admission; it does not verify a recovery code.
func Backup(primary, uid string, now time.Time) (*Evidence, error) {
	if _, err := loginproof.Read(primary, uid, now); err != nil {
		return nil, ErrRejected
	}
	return &Evidence{primary: primary, kind: "backup"}, nil
}

// Consume requires the caller to hold its account lock and to have rechecked
// the exact credential/MFA snapshot. Certificate flows have no current password
// digest; their first factor was verified by the certificate listener.
func Consume(ctx context.Context, tx *sql.Tx, uid, method, credentialDigest string, evidence *Evidence) error {
	if evidence == nil || tx == nil {
		return ErrRejected
	}
	now := time.Now()
	proof, err := loginproof.Read(evidence.primary, uid, now)
	if err != nil || proof.Method != method || credentialDigest != "" && proof.Credential != credentialDigest {
		return ErrRejected
	}
	if evidence.kind != "totp" && evidence.kind != "backup" {
		return ErrRejected
	}
	if evidence.kind == "totp" && (evidence.counter < now.Unix()/30-1 || evidence.counter > now.Unix()/30+1) {
		return ErrRejected
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO uem_mfa_primary_consumptions (flow_id,user_id) VALUES ($1,$2) ON CONFLICT (flow_id) DO NOTHING`, proof.FlowID, uid)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrRejected
	}
	if evidence.kind == "totp" {
		result, err = tx.ExecContext(ctx, `INSERT INTO uem_mfa_totp_counters (user_id,secret_digest,last_counter) VALUES ($1,$2,$3) ON CONFLICT (user_id,secret_digest) DO UPDATE SET last_counter=EXCLUDED.last_counter,used_at=clock_timestamp() WHERE uem_mfa_totp_counters.last_counter<EXCLUDED.last_counter`, uid, evidence.secretDigest[:], evidence.counter)
		if err != nil {
			return err
		}
		count, err = result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrRejected
		}
	}
	return nil
}
