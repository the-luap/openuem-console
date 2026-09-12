package models

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
)

// AdmitCertificateSignIn checks the TLS-verified certificate against current
// registry ownership, purpose, lifetime and revocation in the admission transaction.
func (m *Model) AdmitCertificateSignIn(ctx context.Context, expected *ent.User, cert *x509.Certificate, stage LocalSignInStage, evidence *mfaadmission.Evidence, issuer string) error {
	if expected == nil || !clientidentity.CurrentUserCertificate(cert, expected.ID, time.Now()) || (stage != LocalSignInPendingMFA && stage != LocalSignInComplete) {
		return ErrLocalSignIn
	}
	return m.admitLocalSignIn(ctx, expected, loginproof.Certificate, stage, evidence, cert, "", nil, issuer)
}

// CheckCertificateSession rechecks the original TLS certificate and current
// generation under the same source locks used by final certificate admission.
func (m *Model) CheckCertificateSession(ctx context.Context, expected *ent.User, cert *x509.Certificate, generation string) error {
	return m.admitLocalSignIn(ctx, expected, loginproof.Certificate, LocalSignInCurrentSession, nil, cert, generation, nil, "")
}

func lockUserCertificate(ctx context.Context, tx *sql.Tx, uid string, cert *x509.Certificate) error {
	if !clientidentity.CurrentUserCertificate(cert, uid, time.Now()) {
		return ErrLocalSignIn
	}
	if _, err := lockConsoleCertificateIssuer(ctx, tx, cert, ""); err != nil {
		return err
	}
	// The legacy revocation table has no parent-row lock or common advisory-lock
	// protocol. A short shared table lock also serializes absent-record checks
	// against existing writers, including insertion of a new revocation.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE revocations IN SHARE MODE`); err != nil {
		return err
	}
	var owner, purpose sql.NullString
	var expiry sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT uid,type,expiry FROM certificates WHERE serial=$1 FOR SHARE`, cert.SerialNumber.Int64()).Scan(&owner, &purpose, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLocalSignIn
	}
	if err != nil {
		return err
	}
	if owner.String != uid || purpose.String != "user" || !expiry.Valid || !expiry.Time.Equal(cert.NotAfter) || !expiry.Time.After(time.Now()) {
		return ErrLocalSignIn
	}
	var revoked bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM revocations WHERE serial=$1)`, cert.SerialNumber.Int64()).Scan(&revoked); err != nil {
		return err
	}
	if revoked {
		return ErrLocalSignIn
	}
	return nil
}

// BeginCertificateMFA binds a verified TLS first factor to the issuer generation
// captured before its external revocation check.
func (m *Model) BeginCertificateMFA(ctx context.Context, expected *ent.User, cert *x509.Certificate, issuer string) (string, error) {
	var issued string
	err := m.admitLocalSignIn(ctx, expected, loginproof.Certificate, LocalSignInPendingMFA, nil, cert, "", &issued, issuer)
	return issued, err
}

// CompleteCertificateSession preserves the original issuer generation through
// initial certificate admission. MFA completion uses its retained primary stamp.
func (m *Model) CompleteCertificateSession(ctx context.Context, expected *ent.User, cert *x509.Certificate, issuer string) (string, error) {
	var issued string
	err := m.admitLocalSignIn(ctx, expected, loginproof.Certificate, LocalSignInComplete, nil, cert, "", &issued, issuer)
	return issued, err
}

func lockConsoleCertificateIssuer(ctx context.Context, tx *sql.Tx, cert *x509.Certificate, expected string) (string, error) {
	generation, err := sessiongeneration.LockIssuer(ctx, tx, cert, expected)
	if errors.Is(err, sessiongeneration.ErrChanged) {
		return "", ErrLocalSignIn
	}
	return generation, err
}
