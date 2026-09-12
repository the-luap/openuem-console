package sessions_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"

	"github.com/labstack/echo/v4"
	auth "github.com/open-uem/openuem-console/internal/controllers/authserver/handlers"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func holdOwnedIssuerAdmission(t *testing.T, f accountPasswordFixture) func() {
	t.Helper()
	const gate = 673810059
	conn, err := f.model.DB.Conn(t.Context())
	require.NoError(t, err)
	_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, gate)
		_ = conn.Close()
	})
	_, err = f.model.DB.ExecContext(t.Context(), `CREATE SEQUENCE owned_issuer_admission_entered; CREATE FUNCTION hold_owned_issuer_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('owned_issuer_admission_entered'); PERFORM pg_advisory_xact_lock(673810059); RETURN NEW; END $$; CREATE TRIGGER hold_owned_issuer_admission AFTER UPDATE OF modified ON users FOR EACH ROW EXECUTE FUNCTION hold_owned_issuer_admission()`)
	require.NoError(t, err)
	return func() {
		_, err := conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, gate)
		require.NoError(t, err)
	}
}

func waitOwnedIssuerAdmission(t *testing.T, f accountPasswordFixture) {
	t.Helper()
	require.Eventually(t, func() bool {
		var entered bool
		err := f.model.DB.QueryRowContext(t.Context(), `SELECT is_called FROM owned_issuer_admission_entered`).Scan(&entered)
		return err == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
}

func TestCertificateAdmissionHoldsIssuerTrustUntilCommit(t *testing.T) {
	f, _ := prepareLocalSession(t, false, false, false)
	ca, leaf := ownedConsoleCertificate(t, f.user.ID)
	registerOwnedConsoleCertificate(t, f.sessionFixture, leaf.Leaf, ca)
	issuer := ownedCertificateIssuer(t, f.model, leaf.Leaf)
	replacement, _ := ownedConsoleCertificate(t, f.user.ID)
	release := holdOwnedIssuerAdmission(t, f)
	done := make(chan error, 1)
	go func() {
		_, err := f.model.CompleteCertificateSession(t.Context(), f.user, leaf.Leaf, issuer)
		done <- err
	}()
	waitOwnedIssuerAdmission(t, f)
	bounded, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	_, err := sessiongeneration.ConfigureIssuer(bounded, f.model.DB, replacement)
	cancel()
	require.Error(t, err)
	current, err := sessiongeneration.CurrentIssuer(t.Context(), f.model.DB)
	require.NoError(t, err)
	require.Equal(t, issuer, current)
	release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("admission did not resume after release")
	}
	_, err = sessiongeneration.ConfigureIssuer(t.Context(), f.model.DB, replacement)
	require.NoError(t, err)
}

func TestCertificateFinalAdmissionRechecksIssuerExpiryAndRollsBackMFA(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "MFA"}[mfa], func(t *testing.T) {
			f, _ := prepareLocalSession(t, false, false, mfa)
			expires := time.Now().Add(5 * time.Second).Truncate(time.Second)
			ca, leaf := ownedConsoleCertificate(t, f.user.ID, time.Now().Add(time.Hour), expires)
			registerOwnedConsoleCertificate(t, f.sessionFixture, leaf.Leaf, ca)
			issuer := ownedCertificateIssuer(t, f.model, leaf.Leaf)
			var evidence *mfaadmission.Evidence
			if mfa {
				generation, err := f.model.BeginCertificateMFA(t.Context(), f.user, leaf.Leaf, issuer)
				require.NoError(t, err)
				primary := loginproof.NewLocal(f.user.ID, loginproof.Certificate, string(leaf.Leaf.Raw), generation, time.Now())
				code, err := totp.GenerateCode(f.user.TotpSecret, time.Now())
				require.NoError(t, err)
				evidence, err = mfaadmission.TOTP(primary, f.user.ID, f.user.TotpSecret, code, time.Now())
				require.NoError(t, err)
			}
			release := holdOwnedIssuerAdmission(t, f)
			// Start within the transaction's five-second limit while leaving time to
			// observe the final write before the already verified CA expires.
			if delay := time.Until(expires.Add(-time.Second)); delay > 0 {
				select {
				case <-time.After(delay):
				case <-t.Context().Done():
					t.Fatal(t.Context().Err())
				}
			}
			type result struct {
				stamp string
				err   error
			}
			done := make(chan result, 1)
			go func() {
				var r result
				if mfa {
					r.stamp, r.err = f.model.CompleteLocalSession(t.Context(), f.user, loginproof.Certificate, leaf.Leaf, evidence)
				} else {
					r.stamp, r.err = f.model.CompleteCertificateSession(t.Context(), f.user, leaf.Leaf, issuer)
				}
				done <- r
			}()
			waitOwnedIssuerAdmission(t, f)
			select {
			case <-time.After(time.Until(expires) + 20*time.Millisecond):
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
			release()
			select {
			case r := <-done:
				require.ErrorIs(t, r.err, models.ErrLocalSignIn)
				require.Empty(t, r.stamp)
			case <-time.After(3 * time.Second):
				t.Fatal("expired issuer admission did not resume")
			}
			var consumed int
			require.NoError(t, f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_primary_consumptions`).Scan(&consumed))
			require.Zero(t, consumed)
			var counters int
			require.NoError(t, f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_totp_counters`).Scan(&counters))
			require.Zero(t, counters)
		})
	}
}

func TestCertificateMFAAdmissionRejectsIssuerRestoredDuringConfirmation(t *testing.T) {
	f, _ := prepareLocalSession(t, false, false, true)
	ca, leaf := ownedConsoleCertificate(t, f.user.ID)
	registerOwnedConsoleCertificate(t, f.sessionFixture, leaf.Leaf, ca)
	issuer := ownedCertificateIssuer(t, f.model, leaf.Leaf)
	generation, err := f.model.BeginCertificateMFA(t.Context(), f.user, leaf.Leaf, issuer)
	require.NoError(t, err)
	primary := loginproof.NewLocal(f.user.ID, loginproof.Certificate, string(leaf.Leaf.Raw), generation, time.Now())
	code, err := totp.GenerateCode(f.user.TotpSecret, time.Now())
	require.NoError(t, err)
	evidence, err := mfaadmission.TOTP(primary, f.user.ID, f.user.TotpSecret, code, time.Now())
	require.NoError(t, err)
	replacement, _ := ownedConsoleCertificate(t, f.user.ID)
	mutation := `UPDATE uem_console_certificate_issuer SET certificate=decode('` + hex.EncodeToString(replacement.Raw) + `','hex'); UPDATE uem_console_certificate_issuer SET certificate=decode('` + hex.EncodeToString(ca.Raw) + `','hex');`
	_, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION restore_owned_issuer_at_confirmation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+mutation+` RETURN NEW; END $$; CREATE TRIGGER restore_owned_issuer_at_confirmation AFTER UPDATE OF modified ON users FOR EACH ROW EXECUTE FUNCTION restore_owned_issuer_at_confirmation()`)
	require.NoError(t, err)
	stamp, err := f.model.CompleteLocalSession(t.Context(), f.user, loginproof.Certificate, leaf.Leaf, evidence)
	require.ErrorIs(t, err, models.ErrLocalSignIn)
	require.Empty(t, stamp)
	var consumed, counters int
	require.NoError(t, f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_primary_consumptions`).Scan(&consumed))
	require.NoError(t, f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_totp_counters`).Scan(&counters))
	require.Zero(t, consumed)
	require.Zero(t, counters)
	current, err := sessiongeneration.CurrentIssuer(t.Context(), f.model.DB)
	require.NoError(t, err)
	require.Equal(t, issuer, current)
}

func TestCertificateTLSAdmissionRejectsIssuerRestoredAfterEarlierVerification(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, pending := range []bool{false, true} {
			t.Run(sessionMode(encrypted)+"/"+map[bool]string{false: "complete", true: "pending MFA"}[pending], func(t *testing.T) {
				f, _ := prepareLocalSession(t, false, encrypted, pending)
				require.NoError(t, f.model.CreateDefaultTenantAndSite())
				ca, credential := ownedConsoleCertificate(t, f.user.ID)
				registerOwnedConsoleCertificate(t, f.sessionFixture, credential.Leaf, ca)
				replacement, _ := ownedConsoleCertificate(t, f.user.ID)
				// Both policy writes occur after the handler has verified TLS and OCSP,
				// inside owner association, before final pending/completed admission.
				mutation := `UPDATE uem_console_certificate_issuer SET certificate=decode('` + hex.EncodeToString(replacement.Raw) + `','hex'); UPDATE uem_console_certificate_issuer SET certificate=decode('` + hex.EncodeToString(ca.Raw) + `','hex');`
				_, err := f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION restore_owned_issuer_during_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+mutation+` RETURN NEW; END $$; CREATE TRIGGER restore_owned_issuer_during_admission AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION restore_owned_issuer_during_admission()`)
				require.NoError(t, err)
				h := &auth.Handler{Model: f.model, SessionManager: f.handler.SessionManager, EncryptionMasterKey: f.key, CACert: ca, PublicOrigin: "https://console.test"}
				server := httptest.NewUnstartedServer(f.manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c := echo.New().NewContext(r, w)
					if err := h.Auth(c); err != nil {
						c.Error(err)
					}
				})))
				roots := x509.NewCertPool()
				roots.AddCert(ca)
				server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
				server.StartTLS()
				t.Cleanup(server.Close)
				client := server.Client()
				client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{credential}
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/auth", nil)
				require.NoError(t, err)
				response, err := client.Do(request)
				require.NoError(t, err)
				response.Body.Close()
				require.Equal(t, http.StatusUnauthorized, response.StatusCode)
				for _, cookie := range response.Cookies() {
					if cookie.Name == f.manager.Cookie.Name && cookie.Value != "" {
						ctx, err := f.manager.Load(t.Context(), cookie.Value)
						require.NoError(t, err)
						require.Empty(t, f.manager.GetString(ctx, "uid"))
					}
				}
			})
		}
	}
}

func TestCertificateIssuerUnavailableTrustPreservesOnlyValidRetries(t *testing.T) {
	for _, condition := range []string{"locked", "unconfigured", "malformed"} {
		t.Run(condition, func(t *testing.T) {
			f, ctx, leaf := completedOwnedCertificateSession(t, true, "none")
			var originalDER []byte
			require.NoError(t, f.model.DB.QueryRowContext(ctx, `SELECT certificate FROM uem_console_certificate_issuer WHERE singleton`).Scan(&originalDER))
			issuer, err := x509.ParseCertificate(originalDER)
			require.NoError(t, err)
			var rollback func() error
			if condition == "locked" {
				tx, err := f.model.DB.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tx.Rollback() })
				_, err = tx.ExecContext(ctx, `UPDATE uem_console_certificate_issuer SET certificate=NULL`)
				require.NoError(t, err)
				rollback = tx.Rollback
			} else {
				query := `UPDATE uem_console_certificate_issuer SET certificate=NULL`
				if condition == "malformed" {
					query = `UPDATE uem_console_certificate_issuer SET certificate='\x01'::bytea`
				}
				_, err = f.model.DB.ExecContext(ctx, query)
				require.NoError(t, err)
			}
			bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			admitted, err := localSessionRequest(f, bounded)
			cancel()
			var unavailable *echo.HTTPError
			require.False(t, admitted)
			require.ErrorAs(t, err, &unavailable)
			require.Equal(t, http.StatusServiceUnavailable, unavailable.Code)
			require.Equal(t, f.user.ID, f.manager.GetString(ctx, "uid"))
			if rollback != nil {
				require.NoError(t, rollback())
				admitted, err = localSessionRequest(f, ctx)
				require.NoError(t, err)
				require.True(t, admitted)
			} else {
				// A committed trust edit has a new generation even after its repair.
				_, err = sessiongeneration.ConfigureIssuer(ctx, f.model.DB, issuer)
				require.NoError(t, err)
				admitted, err = localSessionRequest(f, ctx)
				var denied *echo.HTTPError
				require.False(t, admitted)
				require.ErrorAs(t, err, &denied)
				require.Equal(t, http.StatusUnauthorized, denied.Code)
				fresh := ownedCertificateIssuer(t, f.model, leaf)
				_, err = f.model.CompleteCertificateSession(ctx, f.user, leaf, fresh)
				require.NoError(t, err)
			}
		})
	}
}

func TestConsoleIssuerMigrationRequiresGuardsAndPinsTheirNamespace(t *testing.T) {
	f, _ := prepareLocalSession(t, false, false, false)
	ctx := t.Context()
	ca, _ := ownedConsoleCertificate(t, f.user.ID)
	original, err := sessiongeneration.ConfigureIssuer(ctx, f.model.DB, ca)
	require.NoError(t, err)
	for _, trigger := range []string{"uem_console_issuer_generation", "uem_console_issuer_truncation"} {
		_, err = f.model.DB.ExecContext(ctx, `ALTER TABLE uem_console_certificate_issuer DISABLE TRIGGER `+trigger)
		require.NoError(t, err)
		failure := f.store.Migrate(ctx)
		_, restoreErr := f.model.DB.ExecContext(ctx, `ALTER TABLE uem_console_certificate_issuer ENABLE TRIGGER `+trigger)
		require.NoError(t, restoreErr)
		require.Error(t, failure)
		require.NoError(t, f.store.Migrate(ctx))
	}
	var namespace string
	require.NoError(t, f.model.DB.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&namespace))
	replacement, _ := ownedConsoleCertificate(t, f.user.ID)
	tx, err := f.model.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `SET LOCAL search_path=pg_catalog`)
	require.NoError(t, err)
	for _, der := range [][]byte{replacement.Raw, ca.Raw} {
		_, err = tx.ExecContext(ctx, `UPDATE "`+namespace+`".uem_console_certificate_issuer SET certificate=$1`, der)
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit())
	current, err := sessiongeneration.CurrentIssuer(ctx, f.model.DB)
	require.NoError(t, err)
	require.NotEqual(t, original, current)
	// An installed marker cannot silently recreate lost trust state.
	_, err = f.model.DB.ExecContext(ctx, `ALTER TABLE uem_console_certificate_issuer DISABLE TRIGGER uem_console_issuer_generation`)
	require.NoError(t, err)
	_, err = f.model.DB.ExecContext(ctx, `DELETE FROM uem_console_certificate_issuer`)
	require.NoError(t, err)
	_, err = f.model.DB.ExecContext(ctx, `ALTER TABLE uem_console_certificate_issuer ENABLE TRIGGER uem_console_issuer_generation`)
	require.NoError(t, err)
	failure := f.store.Migrate(ctx)
	_, restoreErr := f.model.DB.ExecContext(ctx, `INSERT INTO uem_console_certificate_issuer(singleton,certificate) VALUES(true,$1)`, ca.Raw)
	require.NoError(t, restoreErr)
	require.Error(t, failure)
	require.NoError(t, f.store.Migrate(ctx))
}
