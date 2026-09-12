package models

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
)

var ErrLocalSignIn = errors.New("local sign-in policy or credentials changed")

type LocalSignInStage int

const (
	LocalSignInCheck LocalSignInStage = iota
	LocalSignInPendingMFA
	LocalSignInComplete
	LocalSignInPasswordReplacement
	LocalSignInCurrentSession
)

// AdmitLocalSignIn binds admission to the account snapshot whose first factor
// was checked. Configuration is locked before the account, so confirmation cannot
// undo revocation or silently accept a changed password, mode or MFA requirement.
func (m *Model) AdmitLocalSignIn(parent context.Context, expected *ent.User, method string, stage LocalSignInStage) error {
	return m.admitLocalSignIn(parent, expected, method, stage, nil)
}

func (m *Model) CompleteMFASignIn(parent context.Context, expected *ent.User, method string, evidence *mfaadmission.Evidence) error {
	if evidence == nil {
		return mfaadmission.ErrRejected
	}
	return m.admitLocalSignIn(parent, expected, method, LocalSignInComplete, evidence)
}

func (m *Model) admitLocalSignIn(parent context.Context, expected *ent.User, method string, stage LocalSignInStage, evidence *mfaadmission.Evidence) error {
	if m.DB == nil || expected == nil || expected.ID == "" || (method != loginproof.Password && method != loginproof.Certificate) || stage < LocalSignInCheck || stage > LocalSignInCurrentSession {
		return ErrLocalSignIn
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	passwords, certificates, err := lockLocalAuthenticationSettings(ctx, tx)
	if err != nil {
		return err
	}
	var passwd, openid, mfa, confirmed bool
	var hash, register, secret string
	lock := "FOR UPDATE"
	if stage == LocalSignInCurrentSession {
		lock = "FOR SHARE"
	}
	err = tx.QueryRowContext(ctx, `SELECT coalesce(passwd,false),coalesce(openid,false),coalesce(hash,''),coalesce(register,''),coalesce(use2fa,false),coalesce(totp_secret_confirmed,false),coalesce(totp_secret,'') FROM users WHERE uid=$1 `+lock, expected.ID).Scan(&passwd, &openid, &hash, &register, &mfa, &confirmed, &secret)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLocalSignIn
	}
	if err != nil {
		return err
	}
	if openid || expected.Openid || mfa != expected.Use2fa {
		return ErrLocalSignIn
	}
	switch method {
	case loginproof.Password:
		if !passwords || !passwd || !expected.Passwd || hash == "" || hash != expected.Hash {
			return ErrLocalSignIn
		}
	case loginproof.Certificate:
		if !certificates || passwd || expected.Passwd {
			return ErrLocalSignIn
		}
	}
	if stage == LocalSignInPasswordReplacement {
		if method != loginproof.Password || register != nats.REGISTER_FORCE_PASSWORD_CHANGE {
			return ErrLocalSignIn
		}
	} else if register != nats.REGISTER_COMPLETE && register != nats.REGISTER_APPROVED && !(stage != LocalSignInCurrentSession && method == loginproof.Certificate && register == nats.REGISTER_CERTIFICATE_SENT) {
		return ErrLocalSignIn
	}
	if stage == LocalSignInCurrentSession && (confirmed != expected.TotpSecretConfirmed || secret != expected.TotpSecret) {
		return ErrLocalSignIn
	}
	if stage == LocalSignInPendingMFA && !mfa {
		return ErrLocalSignIn
	}
	if stage == LocalSignInComplete {
		// TOTP and backup-code verification must still refer to the same
		// enrollment when admission commits. Handlers retain stored ciphertext.
		if mfa && (!confirmed || secret != expected.TotpSecret) {
			return ErrLocalSignIn
		}
		if mfa {
			credential := ""
			if method == loginproof.Password {
				credential = loginproof.Digest(hash)
			}
			if err = mfaadmission.Consume(ctx, tx, expected.ID, method, credential, evidence); err != nil {
				return err
			}
		} else if evidence != nil {
			return mfaadmission.ErrRejected
		}
		if _, err = tx.ExecContext(ctx, `UPDATE users SET register=$2,cert_clear_password='',modified=clock_timestamp() WHERE uid=$1`, expected.ID, nats.REGISTER_COMPLETE); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// All credential mutations lock configuration before users to share one lock order.
func lockLocalAuthenticationSettings(ctx context.Context, tx *sql.Tx) (bool, bool, error) {
	settings, err := lockAuthenticationSettings(ctx, tx)
	return settings.passwords, settings.certificates, err
}

type lockedAuthenticationSettings struct{ passwords, certificates, openid bool }

func lockAuthenticationSettings(ctx context.Context, tx *sql.Tx) (lockedAuthenticationSettings, error) {
	var settings lockedAuthenticationSettings
	rows, err := tx.QueryContext(ctx, `SELECT coalesce(use_passwd,false),coalesce(use_certificates,false),coalesce(use_oidc,false) FROM authentications ORDER BY id LIMIT 2 FOR SHARE`)
	if err != nil {
		return settings, err
	}
	count := 0
	for rows.Next() {
		if err = rows.Scan(&settings.passwords, &settings.certificates, &settings.openid); err != nil {
			rows.Close()
			return settings, err
		}
		count++
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return settings, err
	}
	if count != 1 {
		return settings, ErrLocalSignIn
	}
	return settings, nil
}
