package sessiongeneration

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"time"
)

var ErrIssuerUnavailable = errors.New("console certificate issuer is unavailable")

// ConfigureIssuer publishes the public CA from trusted server configuration.
// Call during startup before accepting console traffic, never from login input.
// Repeated publication of identical DER preserves all existing generations.
func ConfigureIssuer(parent context.Context, db *sql.DB, issuer *x509.Certificate) (string, error) {
	if issuer == nil {
		return "", ErrIssuerUnavailable
	}
	parsed, err := parseConsoleIssuer(issuer.Raw)
	if err != nil || !validIssuerTime(parsed, time.Now()) {
		return "", ErrIssuerUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var generation string
	err = tx.QueryRowContext(ctx, `UPDATE uem_console_certificate_issuer SET certificate=$1 WHERE singleton RETURNING generation::text`, parsed.Raw).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrIssuerUnavailable
	}
	if err != nil {
		return "", err
	}
	if !validIssuerTime(parsed, time.Now()) {
		return "", ErrIssuerUnavailable
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return generation, nil
}

// CaptureIssuer verifies a presented certificate against the configured issuer
// and captures its generation before external checks such as OCSP. Admission
// must compare this original generation again while holding the issuer lock.
func CaptureIssuer(parent context.Context, db *sql.DB, leaf *x509.Certificate) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	generation, err := LockIssuer(ctx, tx, leaf, "")
	if err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return generation, nil
}

// LockIssuer holds current trust through the caller's transaction and verifies
// the leaf's client-auth chain at the current time. Callers passing an empty
// expected value must compare retained evidence under this lock separately.
func LockIssuer(ctx context.Context, tx *sql.Tx, leaf *x509.Certificate, expected string) (string, error) {
	var generation string
	var der []byte
	err := tx.QueryRowContext(ctx, `SELECT generation::text,CASE WHEN octet_length(certificate)<=16384 THEN certificate ELSE NULL END FROM uem_console_certificate_issuer WHERE singleton FOR SHARE`).Scan(&generation, &der)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrIssuerUnavailable
	}
	if err != nil {
		return "", err
	}
	issuer, err := parseConsoleIssuer(der)
	if err != nil {
		return "", err
	}
	if expected != "" && expected != generation {
		return "", ErrChanged
	}
	if leaf == nil || len(leaf.Raw) == 0 || len(leaf.Raw) > 16<<10 {
		return "", ErrChanged
	}
	// Parse public DER again: caller-mutated x509 fields are not signed evidence.
	certificate, err := x509.ParseCertificate(leaf.Raw)
	if err != nil || certificate.IsCA {
		return "", ErrChanged
	}
	if leaf.SerialNumber == nil || leaf.SerialNumber.Cmp(certificate.SerialNumber) != 0 || leaf.Subject.CommonName != certificate.Subject.CommonName || !leaf.NotBefore.Equal(certificate.NotBefore) || !leaf.NotAfter.Equal(certificate.NotAfter) {
		return "", ErrChanged
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	chains, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 || len(chains[0]) < 2 {
		return "", ErrChanged
	}
	return generation, nil
}

// CurrentIssuer is metadata only. Admission must already hold LockIssuer's
// shared row lock and verify the original certificate before using this UUID.
func CurrentIssuer(ctx context.Context, q Queryer) (string, error) {
	var generation string
	err := q.QueryRowContext(ctx, `SELECT generation::text FROM uem_console_certificate_issuer WHERE singleton AND certificate IS NOT NULL`).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrIssuerUnavailable
	}
	return generation, err
}

func parseConsoleIssuer(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > 16<<10 {
		return nil, ErrIssuerUnavailable
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil || !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrIssuerUnavailable
	}
	return issuer, nil
}

func validIssuerTime(issuer *x509.Certificate, now time.Time) bool {
	return issuer != nil && !now.Before(issuer.NotBefore) && now.Before(issuer.NotAfter)
}
