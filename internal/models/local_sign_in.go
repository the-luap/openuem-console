package models

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
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
	return m.admitLocalSignIn(parent, expected, method, stage, nil, nil, "", nil, "")
}

func (m *Model) CompleteMFASignIn(parent context.Context, expected *ent.User, method string, evidence *mfaadmission.Evidence) error {
	if evidence == nil {
		return mfaadmission.ErrRejected
	}
	return m.admitLocalSignIn(parent, expected, method, LocalSignInComplete, evidence, nil, "", nil, "")
}

// CompleteLocalSession returns generation metadata only after final admission
// commits. The session publisher must save it before issuing the new cookie.
func (m *Model) CompleteLocalSession(ctx context.Context, expected *ent.User, method string, cert *x509.Certificate, evidence *mfaadmission.Evidence) (string, error) {
	var issued string
	err := m.admitLocalSignIn(ctx, expected, method, LocalSignInComplete, evidence, cert, "", &issued, "")
	return issued, err
}

func (m *Model) CheckLocalSession(ctx context.Context, expected *ent.User, method, generation string) error {
	return m.admitLocalSignIn(ctx, expected, method, LocalSignInCurrentSession, nil, nil, generation, nil, "")
}

func (m *Model) BeginLocalMFA(ctx context.Context, expected *ent.User, method string, cert *x509.Certificate) (string, error) {
	var issued string
	err := m.admitLocalSignIn(ctx, expected, method, LocalSignInPendingMFA, nil, cert, "", &issued, "")
	return issued, err
}

func (m *Model) CheckLocalPrimary(ctx context.Context, expected *ent.User, method string, cert *x509.Certificate, generation string) error {
	if generation == "" {
		return ErrLocalSignIn
	}
	return m.admitLocalSignIn(ctx, expected, method, LocalSignInPendingMFA, nil, cert, generation, nil, "")
}

func (m *Model) admitLocalSignIn(parent context.Context, expected *ent.User, method string, stage LocalSignInStage, evidence *mfaadmission.Evidence, cert *x509.Certificate, generation string, issued *string, issuer string) error {
	if m.DB == nil || expected == nil || expected.ID == "" || (method != loginproof.Password && method != loginproof.Certificate) || stage < LocalSignInCheck || stage > LocalSignInCurrentSession {
		return ErrLocalSignIn
	}
	if method == loginproof.Certificate && (stage == LocalSignInComplete && evidence == nil || stage == LocalSignInPendingMFA && generation == "") && issuer == "" {
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
		if stage == LocalSignInPendingMFA || stage == LocalSignInComplete || stage == LocalSignInCurrentSession {
			if err = lockUserCertificate(ctx, tx, expected.ID, cert); err != nil {
				return err
			}
			if issuer == "" {
				issuer, err = sessiongeneration.CurrentIssuer(ctx, tx)
				if err != nil {
					return err
				}
			}
		}
	}
	if method == loginproof.Certificate && issuer != "" {
		if _, err = lockConsoleCertificateIssuer(ctx, tx, cert, issuer); err != nil {
			return err
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
	if stage == LocalSignInCurrentSession {
		previous, err := sessiongeneration.Read(generation, expected.ID, method)
		if err != nil {
			return ErrLocalSignIn
		}
		current, err := sessiongeneration.Current(ctx, tx, expected.ID, method)
		if err != nil {
			return err
		}
		if previous.Account != current.Account || previous.Policy != current.Policy {
			return ErrLocalSignIn
		}
		if method == loginproof.Certificate {
			certificate, err := sessiongeneration.CurrentCertificate(ctx, tx, cert.SerialNumber.Int64())
			if err != nil {
				return err
			}
			issuer, err := sessiongeneration.CurrentIssuer(ctx, tx)
			if err != nil {
				return err
			}
			if previous.Certificate != certificate || previous.Issuer != issuer {
				return ErrLocalSignIn
			}
		}
	}
	if stage == LocalSignInPendingMFA && !mfa {
		return ErrLocalSignIn
	}
	if stage == LocalSignInPendingMFA && generation != "" {
		if err = checkPrimaryGeneration(ctx, tx, expected.ID, method, cert, generation); err != nil {
			return err
		}
	}
	if stage == LocalSignInComplete {
		// TOTP and backup-code verification must still refer to the same
		// enrollment when admission commits. Handlers retain stored ciphertext.
		if mfa && (!confirmed || secret != expected.TotpSecret) {
			return ErrLocalSignIn
		}
		if mfa {
			primary, err := evidence.PrimaryGeneration(expected.ID, method, time.Now())
			if err != nil {
				return err
			}
			if err = checkPrimaryGeneration(ctx, tx, expected.ID, method, cert, primary); err != nil {
				return err
			}
			credential := ""
			if method == loginproof.Password {
				credential = loginproof.Digest(hash)
			} else {
				credential = loginproof.Digest(string(cert.Raw))
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
	var stamp sessiongeneration.Stamp
	if issued != nil {
		if stage == LocalSignInPendingMFA {
			stamp, err = sessiongeneration.CurrentPrimary(ctx, tx, expected.ID, method)
		} else {
			stamp, err = sessiongeneration.Current(ctx, tx, expected.ID, method)
		}
		if err != nil {
			return err
		}
		if method == loginproof.Certificate {
			stamp.Certificate, err = sessiongeneration.CurrentCertificate(ctx, tx, cert.SerialNumber.Int64())
			if err != nil {
				return err
			}
			stamp.Issuer, err = sessiongeneration.CurrentIssuer(ctx, tx)
			if err != nil {
				return err
			}
		}
	}
	if cert != nil {
		if _, err = lockConsoleCertificateIssuer(ctx, tx, cert, issuer); err != nil {
			return err
		}
	}
	if cert != nil && !cert.NotAfter.After(time.Now()) {
		return ErrLocalSignIn
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if issued != nil {
		*issued = stamp.Encode()
	}
	return nil
}

func checkPrimaryGeneration(ctx context.Context, tx *sql.Tx, uid, method string, cert *x509.Certificate, generation string) error {
	previous, err := sessiongeneration.Read(generation, uid, method)
	if err != nil {
		return ErrLocalSignIn
	}
	current, err := sessiongeneration.CurrentPrimary(ctx, tx, uid, method)
	if err != nil {
		return err
	}
	if previous.Account != current.Account || previous.Policy != current.Policy {
		return ErrLocalSignIn
	}
	if method == loginproof.Certificate {
		if cert == nil || cert.SerialNumber == nil {
			return ErrLocalSignIn
		}
		certificate, err := sessiongeneration.CurrentCertificate(ctx, tx, cert.SerialNumber.Int64())
		if err != nil {
			return err
		}
		issuer, err := sessiongeneration.CurrentIssuer(ctx, tx)
		if err != nil {
			return err
		}
		if previous.Certificate != certificate || previous.Issuer != issuer {
			return ErrLocalSignIn
		}
	}
	return nil
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
