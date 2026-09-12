package models

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/open-uem/ent"
	openuem "github.com/open-uem/nats"
)

const (
	PasswordReplacementInitial    = "initial_password"
	PasswordReplacementRecovery   = "recovery_code"
	PasswordReplacementInvitation = "invitation"
	passwordReplacementAccount    = "authenticated_account"
)

var ErrPasswordReplacement = errors.New("password replacement authorization is missing, expired or no longer current")
var ErrPasswordUnchanged = errors.New("choose a password different from the current password")

// PasswordReplacementProof is held only in the server session after verifying
// an initial password, recovery code or invitation. HTTP form fields never set it.
type PasswordReplacementProof struct {
	Kind           string
	PasswordDigest string
	SourceDigest   string
	ExpiresAt      time.Time
}

func PasswordReplacementDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// ChangePasswordWithProof serializes replacement against the exact credentials
// which authorized the session. Only one concurrent replacement can succeed.
func (m *Model) ChangePasswordWithProof(ctx context.Context, userID, password string, proof PasswordReplacementProof) error {
	err := m.changePasswordWithProof(ctx, userID, password, proof, nil)
	if err != nil && !errors.Is(err, ErrPasswordUnchanged) {
		return ErrPasswordReplacement
	}
	return err
}

// ChangeAccountPassword binds a just-verified current password and completed
// account authentication to the exact credential and MFA snapshot used by the
// protected account-settings handler. This proof never enters a browser session.
func (m *Model) ChangeAccountPassword(ctx context.Context, expected *ent.User, password string) error {
	if expected == nil || expected.ID == "" || !expected.Passwd || expected.Openid || expected.Hash == "" {
		return ErrPasswordReplacement
	}
	proof := PasswordReplacementProof{Kind: passwordReplacementAccount, PasswordDigest: PasswordReplacementDigest(expected.Hash), ExpiresAt: time.Now().Add(time.Minute)}
	return m.changePasswordWithProof(ctx, expected.ID, password, proof, expected)
}

func (m *Model) changePasswordWithProof(ctx context.Context, userID, password string, proof PasswordReplacementProof, expected *ent.User) error {
	if m.DB == nil || userID == "" || len(password) == 0 || len(password) > 1024 || len(proof.PasswordDigest) != 64 || !proof.ExpiresAt.After(time.Now()) {
		return ErrPasswordReplacement
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	passwords, _, err := lockLocalAuthenticationSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !passwords {
		return ErrPasswordReplacement
	}
	var passwd, openid, mfa, confirmed bool
	var secret string
	var currentHash, register, code, invitation sql.NullString
	var codeExpiry sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT hash,register,forgot_password_code,forgot_password_code_expires_at,new_user_token,coalesce(passwd,false),coalesce(openid,false),coalesce(use2fa,false),coalesce(totp_secret_confirmed,false),coalesce(totp_secret,'') FROM users WHERE uid=$1 FOR UPDATE`, userID).Scan(&currentHash, &register, &code, &codeExpiry, &invitation, &passwd, &openid, &mfa, &confirmed, &secret); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPasswordReplacement
		}
		return err
	}
	if !passwd || openid {
		return ErrPasswordReplacement
	}
	switch register.String {
	case openuem.REGISTER_COMPLETE, openuem.REGISTER_APPROVED, openuem.REGISTER_PASSWORD_LINK_SENT, openuem.REGISTER_FORCE_PASSWORD_CHANGE:
	default:
		return ErrPasswordReplacement
	}
	if PasswordReplacementDigest(currentHash.String) != proof.PasswordDigest {
		return ErrPasswordReplacement
	}
	switch proof.Kind {
	case passwordReplacementAccount:
		if expected == nil || proof.SourceDigest != "" || (register.String != openuem.REGISTER_COMPLETE && register.String != openuem.REGISTER_APPROVED) || mfa != expected.Use2fa || confirmed != expected.TotpSecretConfirmed || secret != expected.TotpSecret || mfa && !confirmed {
			return ErrPasswordReplacement
		}
	case PasswordReplacementInitial:
		if currentHash.String == "" || register.String != openuem.REGISTER_FORCE_PASSWORD_CHANGE || proof.SourceDigest != "" {
			return ErrPasswordReplacement
		}
	case PasswordReplacementRecovery:
		if code.String == "" || !codeExpiry.Valid || !codeExpiry.Time.After(time.Now()) || PasswordReplacementDigest(code.String) != proof.SourceDigest {
			return ErrPasswordReplacement
		}
	case PasswordReplacementInvitation:
		if invitation.String == "" || PasswordReplacementDigest(invitation.String) != proof.SourceDigest {
			return ErrPasswordReplacement
		}
	default:
		return ErrPasswordReplacement
	}
	if currentHash.String != "" {
		if same, compareErr := argon2id.ComparePasswordAndHash(password, currentHash.String); compareErr == nil && same {
			return ErrPasswordUnchanged
		}
	}
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return err
	}
	if !proof.ExpiresAt.After(time.Now()) || proof.Kind == PasswordReplacementRecovery && !codeExpiry.Time.After(time.Now()) {
		return ErrPasswordReplacement
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET hash=$2,register='users.completed',modified=clock_timestamp(),forgot_password_code='',forgot_password_code_expires_at=clock_timestamp(),new_user_token='' WHERE uid=$1`, userID, hash); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_sessions=$1`, userID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}
