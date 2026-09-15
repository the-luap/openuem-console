package sessions_test

import (
	"crypto/x509"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
	"github.com/stretchr/testify/require"
)

func TestCompletedCertificateSessionRejectsExpiredIssuer(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			// The leaf remains valid after its issuing CA expires. Initial mutual TLS
			// and OCSP admission occur while both certificates are still valid.
			expires := time.Now().Add(6 * time.Second).Truncate(time.Second)
			f, ctx, leaf := completedOwnedCertificateSession(t, encrypted, "none", time.Now().Add(time.Hour), expires)
			if !time.Now().Before(expires) {
				t.Fatal("owned issuer expired before the initial admission could be tested")
			}
			if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
				t.Fatal("valid issuer denied a fresh session", err)
			}
			select {
			case <-time.After(time.Until(expires) + 20*time.Millisecond):
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
			if !time.Now().Before(leaf.NotAfter) {
				t.Fatal("owned leaf expired with its issuer")
			}
			admitted, err := localSessionRequest(f, ctx)
			var denied *echo.HTTPError
			if admitted || !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized {
				t.Fatal("expired issuer retained completed certificate access", admitted, err)
			}
			if f.manager.GetString(ctx, "uid") != "" {
				t.Fatal("expired issuer retained authenticated session state")
			}
		})
	}
}

func TestConsoleIssuerGenerationRetainsTrustChangesAcrossRestoration(t *testing.T) {
	f, _ := prepareLocalSession(t, false, true, false)
	ctx := t.Context()
	first, leaf := ownedConsoleCertificate(t, f.user.ID)
	second, other := ownedConsoleCertificate(t, f.user.ID)
	_, err := sessiongeneration.CaptureIssuer(ctx, f.model.DB, leaf.Leaf)
	require.ErrorIs(t, err, sessiongeneration.ErrIssuerUnavailable)
	initial, err := sessiongeneration.ConfigureIssuer(ctx, f.model.DB, first)
	require.NoError(t, err)
	same, err := sessiongeneration.ConfigureIssuer(ctx, f.model.DB, first)
	require.NoError(t, err)
	require.Equal(t, initial, same)
	captured, err := sessiongeneration.CaptureIssuer(ctx, f.model.DB, leaf.Leaf)
	require.NoError(t, err)
	require.Equal(t, initial, captured)
	mutated := *leaf.Leaf
	mutated.Subject.CommonName = "other-owned-user"
	_, err = sessiongeneration.CaptureIssuer(ctx, f.model.DB, &mutated)
	require.ErrorIs(t, err, sessiongeneration.ErrChanged)
	_, err = sessiongeneration.CaptureIssuer(ctx, f.model.DB, other.Leaf)
	require.ErrorIs(t, err, sessiongeneration.ErrChanged)
	changed, err := sessiongeneration.ConfigureIssuer(ctx, f.model.DB, second)
	require.NoError(t, err)
	require.NotEqual(t, initial, changed)
	_, err = sessiongeneration.CaptureIssuer(ctx, f.model.DB, leaf.Leaf)
	require.ErrorIs(t, err, sessiongeneration.ErrChanged)
	restored, err := sessiongeneration.ConfigureIssuer(ctx, f.model.DB, first)
	require.NoError(t, err)
	require.NotEqual(t, initial, restored)
	require.NotEqual(t, changed, restored)
	require.NoError(t, f.store.Migrate(ctx))
	current, err := sessiongeneration.CurrentIssuer(ctx, f.model.DB)
	require.NoError(t, err)
	require.Equal(t, restored, current)
	tx, err := f.model.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = sessiongeneration.LockIssuer(ctx, tx, leaf.Leaf, initial)
	require.ErrorIs(t, err, sessiongeneration.ErrChanged)
	_, err = sessiongeneration.LockIssuer(ctx, tx, leaf.Leaf, restored)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback())
	for _, query := range []string{
		`UPDATE uem_console_certificate_issuer SET generation=pg_catalog.gen_random_uuid()`,
		`DELETE FROM uem_console_certificate_issuer`,
		`TRUNCATE uem_console_certificate_issuer`,
	} {
		_, err = f.model.DB.ExecContext(ctx, query)
		require.Error(t, err)
	}
	tx, err = f.model.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `UPDATE uem_console_certificate_issuer SET certificate=$1`, second.Raw)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback())
	current, err = sessiongeneration.CurrentIssuer(ctx, f.model.DB)
	require.NoError(t, err)
	require.Equal(t, restored, current)
}

func TestCertificateSessionCannotReviveAfterIssuerReplacement(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, factor := range []string{"none", "TOTP", "backup"} {
			for _, restored := range []bool{false, true} {
				t.Run(sessionMode(encrypted)+"/"+factor+"/"+map[bool]string{false: "replacement", true: "restoration"}[restored], func(t *testing.T) {
					f, ctx, leaf := completedOwnedCertificateSession(t, encrypted, factor)
					var originalDER []byte
					require.NoError(t, f.model.DB.QueryRowContext(t.Context(), `SELECT certificate FROM uem_console_certificate_issuer WHERE singleton`).Scan(&originalDER))
					original, err := x509.ParseCertificate(originalDER)
					require.NoError(t, err)
					replacement, _ := ownedConsoleCertificate(t, f.user.ID)
					_, err = sessiongeneration.ConfigureIssuer(t.Context(), f.model.DB, replacement)
					require.NoError(t, err)
					if restored {
						_, err = sessiongeneration.ConfigureIssuer(t.Context(), f.model.DB, original)
						require.NoError(t, err)
					}
					admitted, err := localSessionRequest(f, ctx)
					var denied *echo.HTTPError
					require.False(t, admitted)
					require.ErrorAs(t, err, &denied)
					require.Equal(t, http.StatusUnauthorized, denied.Code)
					require.Empty(t, f.manager.GetString(ctx, "uid"))
					if restored && factor == "none" {
						issuer, err := sessiongeneration.CaptureIssuer(t.Context(), f.model.DB, leaf)
						require.NoError(t, err)
						current, err := f.model.CompleteCertificateSession(t.Context(), f.user, leaf, issuer)
						require.NoError(t, err)
						require.NoError(t, f.model.CheckCertificateSession(t.Context(), f.user, leaf, current))
					}
				})
			}
		}
	}
}

func TestCertificateInitialAndPendingEvidenceKeepsOriginalIssuer(t *testing.T) {
	f, _ := prepareLocalSession(t, false, true, true)
	ca, leaf := ownedConsoleCertificate(t, f.user.ID)
	registerOwnedConsoleCertificate(t, f.sessionFixture, leaf.Leaf, ca)
	original, err := sessiongeneration.CaptureIssuer(t.Context(), f.model.DB, leaf.Leaf)
	require.NoError(t, err)
	primary, err := f.model.BeginCertificateMFA(t.Context(), f.user, leaf.Leaf, original)
	require.NoError(t, err)
	replacement, _ := ownedConsoleCertificate(t, f.user.ID)
	_, err = sessiongeneration.ConfigureIssuer(t.Context(), f.model.DB, replacement)
	require.NoError(t, err)
	_, err = sessiongeneration.ConfigureIssuer(t.Context(), f.model.DB, ca)
	require.NoError(t, err)
	_, err = f.model.BeginCertificateMFA(t.Context(), f.user, leaf.Leaf, original)
	require.ErrorIs(t, err, models.ErrLocalSignIn)
	require.ErrorIs(t, f.model.CheckLocalPrimary(t.Context(), f.user, loginproof.Certificate, leaf.Leaf, primary), models.ErrLocalSignIn)
	_, err = f.model.BeginLocalMFA(t.Context(), f.user, loginproof.Certificate, leaf.Leaf)
	require.ErrorIs(t, err, models.ErrLocalSignIn)
	fresh, err := sessiongeneration.CaptureIssuer(t.Context(), f.model.DB, leaf.Leaf)
	require.NoError(t, err)
	next, err := f.model.BeginCertificateMFA(t.Context(), f.user, leaf.Leaf, fresh)
	require.NoError(t, err)
	require.NoError(t, f.model.CheckLocalPrimary(t.Context(), f.user, loginproof.Certificate, leaf.Leaf, next))
	// No-factor final admission also keeps the generation captured before OCSP.
	f.user, err = f.user.Update().SetUse2fa(false).SetTotpSecretConfirmed(false).Save(t.Context())
	require.NoError(t, err)
	_, err = f.model.CompleteCertificateSession(t.Context(), f.user, leaf.Leaf, original)
	require.ErrorIs(t, err, models.ErrLocalSignIn)
	_, err = f.model.CompleteLocalSession(t.Context(), f.user, loginproof.Certificate, leaf.Leaf, nil)
	require.ErrorIs(t, err, models.ErrLocalSignIn)
	current, err := f.model.CompleteCertificateSession(t.Context(), f.user, leaf.Leaf, fresh)
	require.NoError(t, err)
	require.NoError(t, f.model.CheckCertificateSession(t.Context(), f.user, leaf.Leaf, current))
}
