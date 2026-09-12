package models

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

var ErrMFAState = errors.New("MFA enrollment or account authorization changed")

// LocalMFAAuthorization retains the server-side first-factor proof and, for
// certificate sign-in, its original TLS certificate. Never build it from forms.
type LocalMFAAuthorization struct {
	Proof       string
	Certificate *x509.Certificate
}

// SaveTOTPSecretKey stages an unconfirmed secret against the account snapshot
// whose authorization was checked. Confirmed enrollment must be disabled first.
// OpenID callers must use StageOIDCTOTPSecret with their server-side identity.
func (m *Model) SaveTOTPSecretKey(ctx context.Context, expected *ent.User, secret string) error {
	return m.stageMFASecret(ctx, expected, secret, nil, nil)
}

func (m *Model) StagePrimaryTOTPSecret(ctx context.Context, expected *ent.User, secret string, primary LocalMFAAuthorization) error {
	return m.stageMFASecret(ctx, expected, secret, &primary, nil)
}

func (m *Model) stageMFASecret(ctx context.Context, expected *ent.User, secret string, primary *LocalMFAAuthorization, identity *oidcaccounts.MFAAuthorization) error {
	if expected == nil || expected.TotpSecretConfirmed || secret == "" || len(secret) > 4096 {
		return ErrMFAState
	}
	return m.changeMFAState(ctx, expected, primary, identity, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret=$2,modified=clock_timestamp() WHERE uid=$1`, expected.ID, secret)
		return err
	})
}

// SaveRecoveryCodes confirms the exact staged secret and replaces the full code
// set in one transaction. Hashing finishes before any database locks are held.
// OpenID callers must use ConfirmOIDCMFA with their server-side identity.
func (m *Model) SaveRecoveryCodes(parent context.Context, expected *ent.User, codes []string) error {
	return m.confirmMFA(parent, expected, codes, nil, nil)
}

func (m *Model) ConfirmPrimaryMFA(ctx context.Context, expected *ent.User, codes []string, primary LocalMFAAuthorization) error {
	return m.confirmMFA(ctx, expected, codes, &primary, nil)
}

func (m *Model) confirmMFA(parent context.Context, expected *ent.User, codes []string, primary *LocalMFAAuthorization, identity *oidcaccounts.MFAAuthorization) error {
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
	return m.changeMFAState(ctx, expected, primary, identity, func(ctx context.Context, tx *sql.Tx) error {
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
	return m.disableMFA(ctx, expected, nil)
}

func (m *Model) StageOIDCTOTPSecret(ctx context.Context, expected *ent.User, secret string, identity oidcaccounts.MFAAuthorization) error {
	return m.stageMFASecret(ctx, expected, secret, nil, &identity)
}

func (m *Model) ConfirmOIDCMFA(ctx context.Context, expected *ent.User, codes []string, identity oidcaccounts.MFAAuthorization) error {
	return m.confirmMFA(ctx, expected, codes, nil, &identity)
}

func (m *Model) DisableOIDCMFA(ctx context.Context, expected *ent.User, identity oidcaccounts.MFAAuthorization) error {
	return m.disableMFA(ctx, expected, &identity)
}

func (m *Model) disableMFA(ctx context.Context, expected *ent.User, identity *oidcaccounts.MFAAuthorization) error {
	return m.changeMFAState(ctx, expected, nil, identity, func(ctx context.Context, tx *sql.Tx) error {
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
func (m *Model) changeMFAState(parent context.Context, expected *ent.User, primary *LocalMFAAuthorization, identity *oidcaccounts.MFAAuthorization, change func(context.Context, *sql.Tx) error) error {
	if m.DB == nil || expected == nil || expected.ID == "" || expected.Openid && identity == nil || primary != nil && identity != nil {
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
	if identity != nil {
		if err = identity.Lock(ctx, tx, expected); err != nil {
			if errors.Is(err, oidcaccounts.ErrIdentity) || errors.Is(err, oidcaccounts.ErrConflict) {
				return ErrMFAState
			}
			return err
		}
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
	if primary != nil {
		proof, err := loginproof.Read(primary.Proof, expected.ID, time.Now())
		if err != nil || !current.Use2fa || current.Openid {
			return ErrLocalSignIn
		}
		switch proof.Method {
		case loginproof.Password:
			if !current.Passwd || primary.Certificate != nil || proof.Credential != loginproof.Digest(current.Hash) {
				return ErrLocalSignIn
			}
		case loginproof.Certificate:
			if current.Passwd {
				return ErrLocalSignIn
			}
			if err = lockUserCertificate(ctx, tx, expected.ID, primary.Certificate); err != nil {
				return err
			}
			if proof.Credential != loginproof.Digest(string(primary.Certificate.Raw)) {
				return ErrLocalSignIn
			}
		default:
			return ErrLocalSignIn
		}
		if err = checkPrimaryGeneration(ctx, tx, expected.ID, proof.Method, primary.Certificate, proof.Generation); err != nil {
			return err
		}
	}
	if err = change(ctx, tx); err != nil {
		return err
	}
	if primary != nil && primary.Certificate != nil && !primary.Certificate.NotAfter.After(time.Now()) {
		return ErrLocalSignIn
	}
	if identity != nil {
		if err = identity.Validate(expected, time.Now()); err != nil {
			return ErrMFAState
		}
	}
	return tx.Commit()
}
