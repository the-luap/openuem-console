package models

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
)

var ErrMFAState = errors.New("MFA enrollment or account authorization changed")

// SaveTOTPSecretKey stages an unconfirmed secret against the account snapshot
// whose authorization was checked. Confirmed enrollment must be disabled first.
func (m *Model) SaveTOTPSecretKey(ctx context.Context, expected *ent.User, secret string) error {
	if expected == nil || expected.TotpSecretConfirmed || secret == "" || len(secret) > 4096 {
		return ErrMFAState
	}
	return m.changeMFAState(ctx, expected, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret=$2,modified=clock_timestamp() WHERE uid=$1`, expected.ID, secret)
		return err
	})
}

// SaveRecoveryCodes confirms the exact staged secret and replaces the full code
// set in one transaction. Hashing finishes before any database locks are held.
func (m *Model) SaveRecoveryCodes(parent context.Context, expected *ent.User, codes []string) error {
	if expected == nil || expected.TotpSecret == "" || expected.TotpSecretConfirmed || len(codes) != 10 {
		return ErrMFAState
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	seen := make(map[string]bool, len(codes))
	for _, code := range codes {
		if code == "" || len(code) > 256 || seen[code] {
			return ErrMFAState
		}
		seen[code] = true
	}
	hashes := make([]string, len(codes))
	for i, code := range codes {
		if err := ctx.Err(); err != nil {
			return err
		}
		hash, err := argon2id.CreateHash(code, argon2id.DefaultParams)
		if err != nil {
			return err
		}
		hashes[i] = hash
	}
	return m.changeMFAState(ctx, expected, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_recoverycodes=$1`, expected.ID); err != nil {
			return err
		}
		for _, hash := range hashes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (code,used,user_recoverycodes) VALUES ($1,false,$2)`, hash, expected.ID); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET use2fa=true,totp_secret_confirmed=true,modified=clock_timestamp() WHERE uid=$1`, expected.ID)
		return err
	})
}

// Disable2FA removes the secret and its codes together, and retires sessions in
// the same transaction. Deletion receipts prevent old session writers returning.
func (m *Model) Disable2FA(ctx context.Context, expected *ent.User) error {
	return m.changeMFAState(ctx, expected, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_recoverycodes=$1`, expected.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET use2fa=false,totp_secret='',totp_secret_confirmed=false,modified=clock_timestamp() WHERE uid=$1`, expected.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_sessions=$1`, expected.ID)
		return err
	})
}

// Configuration, account and code/session rows use the same lock order as other
// credential mutations. The supplied snapshot must include stored ciphertext.
func (m *Model) changeMFAState(parent context.Context, expected *ent.User, change func(context.Context, *sql.Tx) error) error {
	if m.DB == nil || expected == nil || expected.ID == "" {
		return ErrMFAState
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	settings, err := lockAuthenticationSettings(ctx, tx)
	if errors.Is(err, ErrLocalSignIn) {
		return ErrMFAState
	}
	if err != nil {
		return err
	}
	var current ent.User
	err = tx.QueryRowContext(ctx, `SELECT coalesce(passwd,false),coalesce(openid,false),coalesce(hash,''),coalesce(register,''),coalesce(use2fa,false),coalesce(totp_secret_confirmed,false),coalesce(totp_secret,'') FROM users WHERE uid=$1 FOR UPDATE`, expected.ID).Scan(&current.Passwd, &current.Openid, &current.Hash, &current.Register, &current.Use2fa, &current.TotpSecretConfirmed, &current.TotpSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMFAState
	}
	if err != nil {
		return err
	}
	if current.Passwd != expected.Passwd || current.Openid != expected.Openid || current.Hash != expected.Hash || current.Use2fa != expected.Use2fa || current.TotpSecretConfirmed != expected.TotpSecretConfirmed || current.TotpSecret != expected.TotpSecret {
		return ErrMFAState
	}
	switch {
	case current.Passwd:
		if !settings.passwords || current.Openid || current.Hash == "" {
			return ErrMFAState
		}
	case current.Openid:
		if !settings.openid {
			return ErrMFAState
		}
	default:
		if !settings.certificates {
			return ErrMFAState
		}
	}
	if current.Register != nats.REGISTER_COMPLETE && current.Register != nats.REGISTER_APPROVED && !(!current.Passwd && !current.Openid && current.Register == nats.REGISTER_CERTIFICATE_SENT) {
		return ErrMFAState
	}
	if err = change(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}
