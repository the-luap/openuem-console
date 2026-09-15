package sessions_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/pquerna/otp/totp"
)

func pendingOwnedLocalSession(t *testing.T, encrypted bool, method string) (accountPasswordFixture, context.Context) {
	t.Helper()
	if method == loginproof.Certificate {
		f, ctx, _ := completedOwnedCertificateSession(t, encrypted, "pending")
		return f, ctx
	}
	f, ctx := prepareLocalSession(t, true, encrypted, true)
	if err := f.model.CreateDefaultTenantAndSite(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://console.test/login", strings.NewReader(url.Values{"username": {f.user.ID}, "password": {accountOldPassword}}.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := f.handler.LoginPasswordAuth(echo.New().NewContext(req, httptest.NewRecorder())); err != nil {
		t.Fatal("owned password first factor failed", err)
	}
	return f, ctx
}

func TestPrimaryGenerationAllowsCertificateMFAEnrollment(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f, ctx, _ := completedOwnedCertificateSession(t, encrypted, "enrollment")
			if !f.manager.GetBool(ctx, "twofa") {
				t.Fatal("certificate MFA enrollment did not complete")
			}
			if count, err := f.model.Client.RecoveryCode.Query().Count(t.Context()); err != nil || count != 10 {
				t.Fatal("certificate MFA enrollment did not persist its recovery codes", err)
			}
		})
	}
}

func TestPendingLocalMFARejectsRestoredAuthenticationState(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, method := range []string{loginproof.Password, loginproof.Certificate} {
			for _, mutation := range []string{"method policy", "revocation", "credential", "MFA requirement", "MFA secret", "account creation"} {
				t.Run(sessionMode(encrypted)+"/"+method+"/"+mutation, func(t *testing.T) {
					f, ctx := pendingOwnedLocalSession(t, encrypted, method)
					if _, err := loginproof.Read(f.manager.GetString(ctx, loginproof.SessionKey), f.user.ID, time.Now()); err != nil || f.manager.GetBool(ctx, "twofa") {
						t.Fatal("fixture did not establish pending primary evidence", err)
					}
					tx, err := f.model.DB.BeginTx(t.Context(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					var statements []string
					switch mutation {
					case "method policy":
						column := "use_passwd"
						if method == loginproof.Certificate {
							column = "use_certificates"
						}
						statements = []string{`UPDATE authentications SET ` + column + `=false`, `UPDATE authentications SET ` + column + `=true`}
					case "revocation":
						statements = []string{`UPDATE users SET register='users.revoked' WHERE uid='owner'`, `UPDATE users SET register='users.completed' WHERE uid='owner'`}
					case "credential":
						if method == loginproof.Certificate {
							statements = []string{`UPDATE certificates SET uid='other-owned-user' WHERE serial=2`, `UPDATE certificates SET uid='owner' WHERE serial=2`}
						} else {
							statements = []string{`CREATE TEMP TABLE owned_primary_before ON COMMIT DROP AS SELECT hash FROM users WHERE uid='owner'`, `UPDATE users SET hash='owned intervening credential' WHERE uid='owner'`, `UPDATE users SET hash=(SELECT hash FROM owned_primary_before) WHERE uid='owner'`}
						}
					case "MFA requirement":
						statements = []string{`UPDATE users SET use2fa=false WHERE uid='owner'`, `UPDATE users SET use2fa=true WHERE uid='owner'`}
					case "MFA secret":
						statements = []string{`CREATE TEMP TABLE owned_primary_before ON COMMIT DROP AS SELECT totp_secret FROM users WHERE uid='owner'`, `UPDATE users SET totp_secret='owned intervening factor' WHERE uid='owner'`, `UPDATE users SET totp_secret=(SELECT totp_secret FROM owned_primary_before) WHERE uid='owner'`}
					case "account creation":
						statements = []string{`CREATE TEMP TABLE owned_primary_before ON COMMIT DROP AS SELECT created FROM users WHERE uid='owner'`, `UPDATE users SET created=clock_timestamp() WHERE uid='owner'`, `UPDATE users SET created=(SELECT created FROM owned_primary_before) WHERE uid='owner'`}
					}
					for _, statement := range statements {
						if _, err = tx.ExecContext(t.Context(), statement); err != nil {
							t.Fatal(err)
						}
					}
					if err = tx.Commit(); err != nil {
						t.Fatal(err)
					}
					code, err := totp.GenerateCode(f.user.TotpSecret, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest(http.MethodPost, "https://console.test/login/totp", strings.NewReader(url.Values{"confirm-code": {code}}.Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					err = f.handler.LoginTOTPValidate(echo.New().NewContext(req, httptest.NewRecorder()))
					var denied *echo.HTTPError
					if !errors.As(err, &denied) || (denied.Code != http.StatusForbidden && denied.Code != http.StatusUnauthorized) || f.manager.GetBool(ctx, "twofa") {
						t.Fatal("restored authentication state completed an older primary flow", err)
					}
				})
			}
		}
	}
}

func TestPendingLocalMFARechecksGenerationsAfterFactorVerification(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, method := range []string{loginproof.Password, loginproof.Certificate} {
			for _, factor := range []string{"TOTP", "backup"} {
				for _, mutation := range []string{"policy", "credential"} {
					t.Run(sessionMode(encrypted)+"/"+method+"/"+factor+"/"+mutation, func(t *testing.T) {
						f, ctx := pendingOwnedLocalSession(t, encrypted, method)
						code, err := totp.GenerateCode(f.user.TotpSecret, time.Now())
						if err != nil {
							t.Fatal(err)
						}
						const backup = "OWNED-PRIMARY-GENERATION-BACKUP"
						if factor == "backup" {
							hash, err := argon2id.CreateHash(backup, argon2id.DefaultParams)
							if err != nil {
								t.Fatal(err)
							}
							if err = f.model.Client.RecoveryCode.Create().SetUserID(f.user.ID).SetCode(hash).Exec(t.Context()); err != nil {
								t.Fatal(err)
							}
						}
						change := `UPDATE users SET hash=hash||'x' WHERE uid='owner'; UPDATE users SET hash=left(hash,length(hash)-1) WHERE uid='owner';`
						if method == loginproof.Certificate {
							change = `UPDATE certificates SET uid='other-owned-user' WHERE serial=2; UPDATE certificates SET uid='owner' WHERE serial=2;`
						}
						if mutation == "policy" {
							column := "use_passwd"
							if method == loginproof.Certificate {
								column = "use_certificates"
							}
							change = `UPDATE authentications SET ` + column + `=false; UPDATE authentications SET ` + column + `=true;`
						}
						if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION change_owned_primary_generation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+change+` RETURN NEW; END $$; CREATE TRIGGER change_owned_primary_generation AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION change_owned_primary_generation()`); err != nil {
							t.Fatal(err)
						}
						req := httptest.NewRequest(http.MethodPost, "https://console.test/login/mfa", strings.NewReader(url.Values{"confirm-code": {code}, "recovery-code": {backup}}.Encode())).WithContext(ctx)
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						recorder := httptest.NewRecorder()
						c := echo.New().NewContext(req, recorder)
						if factor == "backup" {
							err = f.handler.LoginTOTPBackupCheck(c)
						} else {
							err = f.handler.LoginTOTPValidate(c)
						}
						var denied *echo.HTTPError
						if !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized || f.manager.GetString(ctx, "uid") != "" {
							t.Fatal("generation change after factor verification established a session", err)
						}
						for _, cookie := range recorder.Result().Cookies() {
							if cookie.Name == f.manager.Cookie.Name && cookie.Value != "" {
								t.Fatal("generation change published a session cookie")
							}
						}
						var consumed int
						if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_mfa_primary_consumptions`).Scan(&consumed); err != nil || consumed != 0 {
							t.Fatal("generation rejection partially consumed the primary flow", err)
						}
					})
				}
			}
		}
	}
}

func TestPendingLocalMFARetriesTransientGenerationFailure(t *testing.T) {
	for _, failure := range []string{"unavailable column", "canceled policy wait"} {
		t.Run(failure, func(t *testing.T) {
			f, ctx := pendingOwnedLocalSession(t, true, loginproof.Password)
			original := f.manager.GetString(ctx, loginproof.SessionKey)
			code, err := totp.GenerateCode(f.user.TotpSecret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			request := func(parent context.Context) error {
				req := httptest.NewRequest(http.MethodPost, "https://console.test/login/mfa", strings.NewReader(url.Values{"confirm-code": {code}}.Encode())).WithContext(parent)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return f.handler.LoginTOTPValidate(echo.New().NewContext(req, httptest.NewRecorder()))
			}
			if failure == "unavailable column" {
				if _, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE uem_session_account_generations RENAME COLUMN primary_generation TO owned_unavailable_primary`); err != nil {
					t.Fatal(err)
				}
				err = request(ctx)
				if _, restoreErr := f.model.DB.ExecContext(t.Context(), `ALTER TABLE uem_session_account_generations RENAME COLUMN owned_unavailable_primary TO primary_generation`); restoreErr != nil {
					t.Fatal(restoreErr)
				}
			} else {
				tx, beginErr := f.model.DB.BeginTx(t.Context(), nil)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				defer tx.Rollback()
				if _, err = tx.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=false`); err != nil {
					t.Fatal(err)
				}
				bounded, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
				err = request(bounded)
				cancel()
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					t.Fatal(rollbackErr)
				}
			}
			var unavailable *echo.HTTPError
			if !errors.As(err, &unavailable) || unavailable.Code != http.StatusServiceUnavailable || f.manager.GetBool(ctx, "twofa") || f.manager.GetString(ctx, loginproof.SessionKey) != original {
				t.Fatal("transient failure admitted or discarded primary authority", err)
			}
			if err = request(ctx); err != nil || !f.manager.GetBool(ctx, "twofa") {
				t.Fatal("valid primary could not retry after storage recovery", err)
			}
		})
	}
}
