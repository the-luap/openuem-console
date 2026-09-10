package models

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/alexedwards/argon2id"
	openuem "github.com/open-uem/nats"
)

const (
	PasswordReplacementInitial    = "initial_password"
	PasswordReplacementRecovery   = "recovery_code"
	PasswordReplacementInvitation = "invitation"
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
	if m.DB == nil || userID == "" || len(password) == 0 || len(password) > 1024 || len(proof.PasswordDigest) != 64 || !proof.ExpiresAt.After(time.Now()) {
		return ErrPasswordReplacement
	}
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrPasswordReplacement
	}
	defer tx.Rollback()
	var currentHash, register, code, invitation sql.NullString
	var codeExpiry sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT hash,register,forgot_password_code,forgot_password_code_expires_at,new_user_token FROM users WHERE uid=$1 FOR UPDATE`, userID).Scan(&currentHash, &register, &code, &codeExpiry, &invitation); err != nil {
		return ErrPasswordReplacement
	}
	if PasswordReplacementDigest(currentHash.String) != proof.PasswordDigest {
		return ErrPasswordReplacement
	}
	switch proof.Kind {
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
	if err != nil || !proof.ExpiresAt.After(time.Now()) || proof.Kind == PasswordReplacementRecovery && !codeExpiry.Time.After(time.Now()) {
		return ErrPasswordReplacement
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET hash=$2,register='users.completed',modified=clock_timestamp(),forgot_password_code='',forgot_password_code_expires_at=clock_timestamp(),new_user_token='' WHERE uid=$1`, userID, hash); err != nil {
		return ErrPasswordReplacement
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_sessions=$1`, userID); err != nil {
		return ErrPasswordReplacement
	}
	if err = tx.Commit(); err != nil {
		return ErrPasswordReplacement
	}
	return nil
}
