package sessions_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/certificate"
	"github.com/open-uem/nats"
	auth "github.com/open-uem/openuem-console/internal/controllers/authserver/handlers"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/pquerna/otp/totp"
)

func registerOwnedConsoleCertificate(t *testing.T, f sessionFixture, cert *x509.Certificate) {
	t.Helper()
	if err := f.model.Client.Certificate.Create().SetID(cert.SerialNumber.Int64()).SetType(certificate.TypeUser).SetUID(cert.Subject.CommonName).SetExpiry(cert.NotAfter).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateMFARechecksRegistryAfterFactorVerification(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, factor := range []string{"TOTP", "backup"} {
			for _, mutation := range []string{"owner", "revocation"} {
				t.Run(sessionMode(encrypted)+"/"+factor+"/"+mutation, func(t *testing.T) {
					f, ctx := prepareLocalSession(t, false, encrypted, true)
					_, credential := ownedConsoleCertificate(t, f.user.ID)
					registerOwnedConsoleCertificate(t, f.sessionFixture, credential.Leaf)
					f.manager.Put(ctx, "twofa", false)
					f.manager.Put(ctx, "authentication-pending", true)
					f.manager.Put(ctx, loginproof.SessionKey, loginproof.New(f.user.ID, loginproof.Certificate, string(credential.Leaf.Raw), time.Now()))
					f.manager.Put(ctx, clientidentity.SessionCertificateKey, clientidentity.EncodeSessionCertificate(credential.Leaf))
					if _, _, err := f.manager.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					code, err := totp.GenerateCode(f.user.TotpSecret, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					const backup = "OWNED-CERTIFICATE-BACKUP"
					if factor == "backup" {
						hash, err := argon2id.CreateHash(backup, argon2id.DefaultParams)
						if err != nil {
							t.Fatal(err)
						}
						if err = f.model.Client.RecoveryCode.Create().SetUserID(f.user.ID).SetCode(hash).Exec(t.Context()); err != nil {
							t.Fatal(err)
						}
					}
					change := `UPDATE certificates SET uid='other-owned-user' WHERE serial=2;`
					if mutation == "revocation" {
						change = `INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=2;`
					}
					if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION change_mfa_certificate_registry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+change+` RETURN NEW; END $$; CREATE TRIGGER change_mfa_registry AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION change_mfa_certificate_registry()`); err != nil {
						t.Fatal(err)
					}
					form := url.Values{"confirm-code": {code}, "recovery-code": {backup}}
					req := httptest.NewRequest(http.MethodPost, "https://console.test/login/mfa", strings.NewReader(form.Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					c := echo.New().NewContext(req, httptest.NewRecorder())
					if factor == "backup" {
						err = f.handler.LoginTOTPBackupCheck(c)
					} else {
						err = f.handler.LoginTOTPValidate(c)
					}
					var denied *echo.HTTPError
					if !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized || f.manager.GetString(ctx, "uid") != "" {
						t.Fatal("superseded certificate finished MFA", err)
					}
					var consumed int
					if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_primary_consumptions`).Scan(&consumed); err != nil || consumed != 0 {
						t.Fatal("failed certificate admission partially consumed primary evidence", consumed, err)
					}
				})
			}
		}
	}
}

func TestCertificateAdmissionRechecksRegistryWaits(t *testing.T) {
	for _, source := range []string{"owner", "revocation"} {
		for _, outcome := range []string{"commit", "rollback", "cancel"} {
			t.Run(source+"/"+outcome, func(t *testing.T) {
				f, _ := prepareLocalSession(t, false, true, false)
				_, credential := ownedConsoleCertificate(t, f.user.ID)
				registerOwnedConsoleCertificate(t, f.sessionFixture, credential.Leaf)
				if err := f.model.AdmitLocalSignIn(t.Context(), f.user, loginproof.Certificate, models.LocalSignInComplete); !errors.Is(err, models.ErrLocalSignIn) {
					t.Fatal("certificate confirmation succeeded without its verified certificate", err)
				}
				tx, err := f.model.DB.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if source == "owner" {
					_, err = tx.ExecContext(t.Context(), `UPDATE certificates SET uid='other-owned-user' WHERE serial=2`)
				} else {
					_, err = tx.ExecContext(t.Context(), `INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=2`)
				}
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- f.model.AdmitCertificateSignIn(ctx, f.user, credential.Leaf, models.LocalSignInComplete, nil)
				}()
				query := "SELECT uid,type,expiry FROM certificates%FOR SHARE"
				if source == "revocation" {
					query = "LOCK TABLE revocations IN SHARE MODE"
				}
				deadline := time.Now().Add(3 * time.Second)
				for {
					var waiting bool
					if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1)`, query).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("certificate admission did not wait for registry change")
					}
					time.Sleep(time.Millisecond)
				}
				if outcome == "cancel" {
					cancel()
					if err = <-done; err == nil {
						t.Fatal("canceled registry wait completed admission")
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
				if outcome == "cancel" {
					err = f.model.AdmitCertificateSignIn(t.Context(), f.user, credential.Leaf, models.LocalSignInComplete, nil)
				} else {
					err = <-done
				}
				if outcome == "commit" && !errors.Is(err, models.ErrLocalSignIn) || outcome != "commit" && err != nil {
					t.Fatal("certificate admission ignored the registry transaction outcome", err)
				}
			})
		}
	}
}

func TestCertificatePendingSessionRechecksRegistry(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked certificate", true: "unavailable registry"}[unavailable], func(t *testing.T) {
			f, ctx := prepareLocalSession(t, false, true, true)
			_, credential := ownedConsoleCertificate(t, f.user.ID)
			registerOwnedConsoleCertificate(t, f.sessionFixture, credential.Leaf)
			f.manager.Put(ctx, "twofa", false)
			f.manager.Put(ctx, "authentication-pending", true)
			f.manager.Put(ctx, loginproof.SessionKey, loginproof.New(f.user.ID, loginproof.Certificate, string(credential.Leaf.Raw), time.Now()))
			f.manager.Put(ctx, clientidentity.SessionCertificateKey, clientidentity.EncodeSessionCertificate(credential.Leaf))
			var err error
			if unavailable {
				_, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE certificates RENAME TO owned_unavailable_certificates`)
			} else {
				_, err = f.model.DB.ExecContext(t.Context(), `INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=2`)
			}
			if err != nil {
				t.Fatal(err)
			}
			admitted, err := localSessionRequest(f, ctx)
			var denied *echo.HTTPError
			want := http.StatusUnauthorized
			if unavailable {
				want = http.StatusServiceUnavailable
			}
			if admitted || !errors.As(err, &denied) || denied.Code != want {
				t.Fatal("pending certificate ignored registry verification failure", err)
			}
			if unavailable {
				if f.manager.GetString(ctx, "uid") != f.user.ID {
					t.Fatal("temporary registry failure destroyed pending authentication")
				}
				if _, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE owned_unavailable_certificates RENAME TO certificates`); err != nil {
					t.Fatal(err)
				}
				if admitted, err = localSessionRequest(f, ctx); admitted || err != nil {
					t.Fatal("pending certificate could not retry its challenge", err)
				}
			} else if f.manager.GetString(ctx, "uid") != "" {
				t.Fatal("revoked pending certificate retained authority")
			}
		})
	}
}

func TestCertificateSignInRequiresCurrentUserCertificateRegistry(t *testing.T) {
	for _, invalid := range []string{"missing record", "different owner", "agent certificate", "different expiry", "revoked record", "removed during admission", "revoked during admission", "type changed during admission"} {
		t.Run(invalid, func(t *testing.T) {
			f := newSessionFixture(t, true)
			if err := f.model.CreateInitialSettings(); err != nil {
				t.Fatal(err)
			}
			if err := f.model.CreateDefaultTenantAndSite(); err != nil {
				t.Fatal(err)
			}
			settings, err := f.model.GetAuthenticationSettings()
			if err != nil {
				t.Fatal(err)
			}
			if err = settings.Update().SetUseCertificates(true).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			const uid = "certificate-user"
			if err = f.model.Client.User.Create().SetID(uid).SetName("Owned certificate user").SetRegister(nats.REGISTER_COMPLETE).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			ca, credential := ownedConsoleCertificate(t, uid)
			if invalid != "missing record" {
				record := f.model.Client.Certificate.Create().SetID(credential.Leaf.SerialNumber.Int64()).SetType(certificate.TypeUser).SetUID(uid).SetExpiry(credential.Leaf.NotAfter)
				switch invalid {
				case "different owner":
					record.SetUID("another-owned-account")
				case "agent certificate":
					record.SetType(certificate.TypeAgent)
				case "different expiry":
					record.SetExpiry(credential.Leaf.NotBefore)
				}
				if err = record.Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if invalid == "revoked record" {
				if _, err = f.model.DB.ExecContext(t.Context(), `INSERT INTO revocations(serial,revoked,expiry) VALUES($1,clock_timestamp(),$2)`, credential.Leaf.SerialNumber.Int64(), credential.Leaf.NotAfter); err != nil {
					t.Fatal(err)
				}
			}
			mutation := ""
			switch invalid {
			case "removed during admission":
				mutation = `DELETE FROM certificates WHERE serial=2;`
			case "revoked during admission":
				mutation = `INSERT INTO revocations(serial,revoked,expiry) SELECT serial,clock_timestamp(),expiry FROM certificates WHERE serial=2;`
			case "type changed during admission":
				mutation = `UPDATE certificates SET type='agent' WHERE serial=2;`
			}
			if mutation != "" {
				if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION change_certificate_registry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+mutation+` RETURN NEW; END $$; CREATE TRIGGER change_owned_registry AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION change_certificate_registry()`); err != nil {
					t.Fatal(err)
				}
			}
			sm := scs.New()
			sm.Store = f.store
			h := &auth.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, CACert: ca, PublicOrigin: "https://console.test"}
			server := httptest.NewUnstartedServer(sm.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c := echo.New().NewContext(r, w)
				if err := h.Auth(c); err != nil {
					c.Error(err)
				}
			})))
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
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
			if response.StatusCode != http.StatusUnauthorized {
				t.Error("certificate sign-in ignored its current registry", response.StatusCode)
			}
			for _, cookie := range response.Cookies() {
				if cookie.Name != sm.Cookie.Name || cookie.Value == "" {
					continue
				}
				ctx, err := sm.Load(t.Context(), cookie.Value)
				if err != nil {
					t.Fatal(err)
				}
				if sm.GetString(ctx, "uid") != "" {
					t.Error("invalid certificate registry issued an authenticated session")
				}
			}
		})
	}
}
