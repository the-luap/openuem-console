package sessions_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/labstack/echo/v4"
	auth "github.com/open-uem/openuem-console/internal/controllers/authserver/handlers"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/pquerna/otp/totp"
)

// Complete real mutual TLS and signed OCSP admission, then the selected factor.
// Protected requests below reload only the published database-backed session.
func completedOwnedCertificateSession(t *testing.T, encrypted bool, factor string, expires ...time.Time) (accountPasswordFixture, context.Context, *x509.Certificate) {
	t.Helper()
	f, _ := prepareLocalSession(t, false, encrypted, factor != "none")
	if factor == "enrollment" {
		var err error
		f.user, err = f.user.Update().SetTotpSecretConfirmed(false).Save(t.Context())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.model.CreateDefaultTenantAndSite(); err != nil {
		t.Fatal(err)
	}
	ca, credential := ownedConsoleCertificate(t, f.user.ID, expires...)
	registerOwnedConsoleCertificate(t, f.sessionFixture, credential.Leaf)
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
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatal("owned TLS certificate admission failed", response.StatusCode)
	}
	token := ""
	for _, cookie := range response.Cookies() {
		if cookie.Name == f.manager.Cookie.Name && cookie.Value != "" {
			token = cookie.Value
		}
	}
	if token == "" {
		t.Fatal("owned TLS admission did not publish its session")
	}
	ctx, err := f.manager.Load(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	if factor != "none" && factor != "pending" {
		secret := f.user.TotpSecret
		if factor == "enrollment" {
			req := httptest.NewRequest(http.MethodPost, "https://console.test/login/totpregister", nil).WithContext(ctx)
			if err = f.handler.Register2FA(echo.New().NewContext(req, httptest.NewRecorder())); err != nil {
				t.Fatal("certificate authenticator setup failed", err)
			}
			staged, err := f.model.Client.User.Get(t.Context(), f.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			secret, _, err = sessiontokens.Decode(staged.TotpSecret, f.key)
			if err != nil {
				t.Fatal(err)
			}
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"confirm-code": {code}}
		if factor == "backup" {
			const backup = "OWNED-COMPLETED-CERTIFICATE-BACKUP"
			hash, err := argon2id.CreateHash(backup, argon2id.DefaultParams)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.model.Client.RecoveryCode.Create().SetUserID(f.user.ID).SetCode(hash).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			form.Set("recovery-code", backup)
		}
		req := httptest.NewRequest(http.MethodPost, "https://console.test/login/mfa", strings.NewReader(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		c := echo.New().NewContext(req, recorder)
		if factor == "backup" {
			err = f.handler.LoginTOTPBackupCheck(c)
		} else if factor == "enrollment" {
			err = f.handler.LoginTOTPConfirm(c)
		} else {
			err = f.handler.LoginTOTPValidate(c)
		}
		if err != nil {
			t.Fatal("owned certificate MFA failed", err)
		}
		token = ""
		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == f.manager.Cookie.Name && cookie.Value != "" {
				token = cookie.Value
			}
		}
		if token == "" {
			t.Fatal("owned certificate MFA did not publish its session")
		}
		ctx, err = f.manager.Load(t.Context(), token)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.token = token
	if factor == "pending" {
		return f, ctx, credential.Leaf
	}
	if f.manager.GetString(ctx, clientidentity.SessionCertificateKey) != clientidentity.EncodeSessionCertificate(credential.Leaf) || f.manager.Exists(ctx, loginproof.SessionKey) {
		t.Fatal("completed certificate session did not retain only its original certificate evidence")
	}
	if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
		t.Fatal("valid completed certificate session was denied", err)
	}
	return f, ctx, credential.Leaf
}

func TestCompletedCertificateSessionRejectsChangedRegistry(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, factor := range []string{"none", "TOTP", "backup"} {
			for _, mutation := range []string{"owner", "purpose", "removed", "revoked"} {
				t.Run(sessionMode(encrypted)+"/"+factor+"/"+mutation, func(t *testing.T) {
					f, ctx, cert := completedOwnedCertificateSession(t, encrypted, factor)
					query := map[string]string{
						"owner":   `UPDATE certificates SET uid='other-owned-user' WHERE serial=$1`,
						"purpose": `UPDATE certificates SET type='agent' WHERE serial=$1`,
						"removed": `DELETE FROM certificates WHERE serial=$1`,
						"revoked": `INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=$1`,
					}[mutation]
					if _, err := f.model.DB.ExecContext(t.Context(), query, cert.SerialNumber.Int64()); err != nil {
						t.Fatal(err)
					}
					admitted, err := localSessionRequest(f, ctx)
					var denied *echo.HTTPError
					if admitted || !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized {
						t.Fatal("completed certificate session ignored changed registry", admitted, err)
					}
					if f.manager.GetString(ctx, "uid") != "" {
						t.Fatal("changed certificate retained session authority")
					}
					if err = f.store.CommitCtx(t.Context(), f.token, []byte("owned stale certificate session"), time.Now().Add(time.Hour)); !errors.Is(err, sessions.ErrRevoked) {
						t.Fatal("changed certificate session could return", err)
					}
				})
			}
		}
	}
}

func TestCompletedCertificateSessionRejectsExpiredOriginal(t *testing.T) {
	f, ctx, cert := completedOwnedCertificateSession(t, true, "TOTP", time.Now().Add(10*time.Second))
	timer := time.NewTimer(time.Until(cert.NotAfter))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	admitted, err := localSessionRequest(f, ctx)
	var denied *echo.HTTPError
	if admitted || !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized || f.manager.GetString(ctx, "uid") != "" {
		t.Fatal("completed certificate session outlived the original TLS certificate", admitted, err)
	}
}

func TestCompletedCertificateSessionCannotReviveAfterRegistryRestoration(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, factor := range []string{"none", "TOTP", "backup"} {
			for _, mutation := range []string{"owner", "purpose", "revocation", "recreation", "serial", "expiry"} {
				t.Run(sessionMode(encrypted)+"/"+factor+"/"+mutation, func(t *testing.T) {
					f, ctx, cert := completedOwnedCertificateSession(t, encrypted, factor)
					tx, err := f.model.DB.BeginTx(t.Context(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					var statements []string
					switch mutation {
					case "owner":
						statements = []string{`UPDATE certificates SET uid='other-owned-user' WHERE serial=$1`, `UPDATE certificates SET uid='owner' WHERE serial=$1`}
					case "purpose":
						statements = []string{`UPDATE certificates SET type='agent' WHERE serial=$1`, `UPDATE certificates SET type='user' WHERE serial=$1`}
					case "revocation":
						statements = []string{`INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=$1`, `DELETE FROM revocations WHERE serial=$1`}
					case "recreation":
						statements = []string{`CREATE TEMP TABLE owned_original_certificate ON COMMIT DROP AS SELECT * FROM certificates WHERE serial=$1`, `DELETE FROM certificates WHERE serial=$1`, `INSERT INTO certificates SELECT * FROM owned_original_certificate WHERE serial=$1`}
					case "serial":
						statements = []string{`UPDATE certificates SET serial=$1+1 WHERE serial=$1`, `UPDATE certificates SET serial=$1 WHERE serial=$1+1`}
					case "expiry":
						statements = []string{`UPDATE certificates SET expiry=expiry+interval '1 minute' WHERE serial=$1`, `UPDATE certificates SET expiry=expiry-interval '1 minute' WHERE serial=$1`}
					}
					for _, statement := range statements {
						if _, err = tx.ExecContext(t.Context(), statement, cert.SerialNumber.Int64()); err != nil {
							t.Fatal(err)
						}
					}
					if err = tx.Commit(); err != nil {
						t.Fatal(err)
					}
					admitted, err := localSessionRequest(f, ctx)
					var denied *echo.HTTPError
					if admitted || !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized || f.manager.GetString(ctx, "uid") != "" {
						t.Fatal("restored certificate registry revived an earlier session", admitted, err)
					}
					if factor == "none" {
						stamp, err := f.model.CompleteLocalSession(t.Context(), f.user, loginproof.Certificate, cert, nil)
						if err != nil {
							t.Fatal("restored valid certificate could not establish a new session", err)
						}
						if err = f.model.CheckCertificateSession(t.Context(), f.user, cert, stamp); err != nil {
							t.Fatal("new certificate generation was not authorized", err)
						}
					}
				})
			}
		}
	}
}

func TestCompletedCertificateSessionRegistryWaits(t *testing.T) {
	for _, source := range []string{"owner", "revocation"} {
		for _, outcome := range []string{"commit", "rollback", "cancel"} {
			t.Run(source+"/"+outcome, func(t *testing.T) {
				f, ctx, cert := completedOwnedCertificateSession(t, true, "none")
				tx, err := f.model.DB.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				query := `UPDATE certificates SET uid='other-owned-user' WHERE serial=$1`
				waitingQuery := "SELECT uid,type,expiry FROM certificates%FOR SHARE"
				if source == "revocation" {
					query = `INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=$1`
					waitingQuery = "LOCK TABLE revocations IN SHARE MODE"
				}
				if _, err = tx.ExecContext(t.Context(), query, cert.SerialNumber.Int64()); err != nil {
					t.Fatal(err)
				}
				request, cancel := context.WithCancel(ctx)
				defer cancel()
				type result struct {
					admitted bool
					err      error
				}
				done := make(chan result, 1)
				go func() { admitted, err := localSessionRequest(f, request); done <- result{admitted, err} }()
				deadline := time.Now().Add(3 * time.Second)
				for {
					var waiting bool
					if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1)`, waitingQuery).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("completed certificate check did not reach the held registry")
					}
					time.Sleep(time.Millisecond)
				}
				if outcome == "cancel" {
					cancel()
					r := <-done
					var unavailable *echo.HTTPError
					if r.admitted || !errors.As(r.err, &unavailable) || unavailable.Code != http.StatusServiceUnavailable || f.manager.GetString(ctx, "uid") != f.user.ID {
						t.Fatal("canceled registry check admitted access or destroyed valid session", r.err)
					}
				}
				if outcome == "commit" {
					err = tx.Commit()
				} else {
					err = tx.Rollback()
				}
				if err != nil {
					t.Fatal(err)
				}
				var r result
				if outcome == "cancel" {
					r.admitted, r.err = localSessionRequest(f, ctx)
				} else {
					r = <-done
				}
				if outcome == "commit" {
					var denied *echo.HTTPError
					if r.admitted || !errors.As(r.err, &denied) || denied.Code != http.StatusUnauthorized {
						t.Fatal("committed certificate change retained access", r.err)
					}
				} else if !r.admitted || r.err != nil {
					t.Fatal("rolled back certificate change prevented valid retry", r.err)
				}
			})
		}
	}
}

func TestCompletedCertificateSessionRequiresStoredEvidence(t *testing.T) {
	for _, invalid := range []string{"missing", "malformed", "other account"} {
		t.Run(invalid, func(t *testing.T) {
			f, ctx, _ := completedOwnedCertificateSession(t, true, "backup")
			raw := ""
			if invalid == "malformed" {
				raw = "owned malformed certificate"
			}
			if invalid == "other account" {
				_, other := ownedConsoleCertificate(t, "other-owned-user")
				raw = clientidentity.EncodeSessionCertificate(other.Leaf)
			}
			f.manager.Put(ctx, clientidentity.SessionCertificateKey, raw)
			admitted, err := localSessionRequest(f, ctx)
			var denied *echo.HTTPError
			if admitted || !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized || f.manager.GetString(ctx, "uid") != "" {
				t.Fatal("completed certificate session accepted invalid evidence", err)
			}
		})
	}
}

func TestCompletedCertificateSessionStorageRetryAndFreshProcess(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f, ctx, cert := completedOwnedCertificateSession(t, encrypted, "none")
			stamp := f.manager.GetString(ctx, sessiongeneration.SessionKey)
			if err := f.model.CheckLocalSession(t.Context(), f.user, loginproof.Certificate, stamp); !errors.Is(err, models.ErrLocalSignIn) {
				t.Fatal("generic check accepted a completed certificate session without a certificate", err)
			}
			if _, err := f.model.DB.ExecContext(t.Context(), `ALTER TABLE certificates RENAME TO owned_unavailable_certificates`); err != nil {
				t.Fatal(err)
			}
			admitted, err := localSessionRequest(f, ctx)
			var unavailable *echo.HTTPError
			if admitted || !errors.As(err, &unavailable) || unavailable.Code != http.StatusServiceUnavailable || f.manager.GetString(ctx, "uid") != f.user.ID {
				t.Fatal("unavailable registry admitted access or destroyed valid evidence", err)
			}
			if _, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE owned_unavailable_certificates RENAME TO certificates`); err != nil {
				t.Fatal(err)
			}
			if admitted, err = localSessionRequest(f, ctx); !admitted || err != nil {
				t.Fatal("valid certificate session could not retry", err)
			}
			child := func(denied bool) {
				t.Helper()
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				command := exec.CommandContext(t.Context(), executable, "-test.run=^TestCompletedCertificateSessionRestartChild$")
				command.Env = append(os.Environ(), "OPENUEM_CERTIFICATE_RESTART_CHECK=1", "OPENUEM_CERTIFICATE_RESTART_DSN="+f.pool.Config().ConnString(), "OPENUEM_CERTIFICATE_RESTART_UID="+f.user.ID, "OPENUEM_CERTIFICATE_RESTART_STAMP="+stamp, "OPENUEM_CERTIFICATE_RESTART_DER="+clientidentity.EncodeSessionCertificate(cert))
				if denied {
					command.Env = append(command.Env, "OPENUEM_CERTIFICATE_RESTART_DENIED=1")
				}
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatal("fresh-process certificate verification failed", err, string(output))
				}
			}
			child(false)
			if _, err = f.model.DB.ExecContext(t.Context(), `INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=$1`, cert.SerialNumber.Int64()); err != nil {
				t.Fatal(err)
			}
			if _, err = f.model.DB.ExecContext(t.Context(), `DELETE FROM revocations WHERE serial=$1`, cert.SerialNumber.Int64()); err != nil {
				t.Fatal(err)
			}
			child(true)
		})
	}
}

func TestCompletedCertificateSessionRestartChild(t *testing.T) {
	if os.Getenv("OPENUEM_CERTIFICATE_RESTART_CHECK") != "1" {
		t.Skip("owned restart subprocess only")
	}
	m, err := models.New(os.Getenv("OPENUEM_CERTIFICATE_RESTART_DSN"), "pgx", "example.test")
	if err != nil {
		t.Fatal("restart database unavailable")
	}
	defer m.Close()
	u, err := m.Client.User.Get(t.Context(), os.Getenv("OPENUEM_CERTIFICATE_RESTART_UID"))
	if err != nil {
		t.Fatal("restart account unavailable")
	}
	cert, err := clientidentity.DecodeSessionCertificate(os.Getenv("OPENUEM_CERTIFICATE_RESTART_DER"), u.ID, time.Now())
	if err != nil {
		t.Fatal("restart certificate evidence unavailable")
	}
	err = m.CheckCertificateSession(t.Context(), u, cert, os.Getenv("OPENUEM_CERTIFICATE_RESTART_STAMP"))
	if os.Getenv("OPENUEM_CERTIFICATE_RESTART_DENIED") == "1" {
		if !errors.Is(err, models.ErrLocalSignIn) {
			t.Fatal("restart admitted changed certificate")
		}
	} else if err != nil {
		t.Fatal("restart denied valid certificate")
	}
}
