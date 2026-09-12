package sessions_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
	"github.com/pquerna/otp/totp"
)

func TestCompletedPasswordSessionCannotOutliveAuthenticationGeneration(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, changed := range []string{"password", "MFA secret", "account generation", "revocation restored", "method restored", "MFA restored"} {
			t.Run(sessionMode(encrypted)+"/"+changed, func(t *testing.T) {
				f, ctx := prepareLocalSession(t, true, encrypted, true)
				if err := f.model.CreateDefaultTenantAndSite(); err != nil {
					t.Fatal(err)
				}
				form := func(values url.Values) echo.Context {
					req := httptest.NewRequest(http.MethodPost, "https://console.test/login", strings.NewReader(values.Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					c := echo.New().NewContext(req, httptest.NewRecorder())
					c.Set("csrf", "owned form token")
					return c
				}
				if err := f.handler.LoginPasswordAuth(form(url.Values{"username": {f.user.ID}, "password": {accountOldPassword}})); err != nil {
					t.Fatal("owned password primary failed", err)
				}
				code, err := totp.GenerateCode(f.user.TotpSecret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if err = f.handler.LoginTOTPValidate(form(url.Values{"confirm-code": {code}})); err != nil {
					t.Fatal("owned password MFA failed", err)
				}
				if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
					t.Fatal("new completed password session was not usable", err)
				}
				switch changed {
				case "password":
					_, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET hash='owned different credential hash' WHERE uid=$1`, f.user.ID)
				case "MFA secret":
					_, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET totp_secret='KRSXG5DSNFXGOIDT' WHERE uid=$1`, f.user.ID)
				case "account generation":
					_, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET created=coalesce(created,clock_timestamp())+interval '1 minute' WHERE uid=$1`, f.user.ID)
				case "revocation restored":
					_, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET register='users.certificate_revoked' WHERE uid=$1`, f.user.ID)
					if err == nil {
						_, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET register='users.completed' WHERE uid=$1`, f.user.ID)
					}
				case "method restored":
					_, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=false`)
					if err == nil {
						_, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=true`)
					}
				case "MFA restored":
					_, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET use2fa=false WHERE uid=$1`, f.user.ID)
					if err == nil {
						_, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET use2fa=true WHERE uid=$1`, f.user.ID)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				admitted, err := localSessionRequest(f, ctx)
				var denied *echo.HTTPError
				if admitted || !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized {
					t.Error("completed session retained an earlier authentication generation", admitted, err)
				}
				if f.manager.GetString(ctx, "uid") != "" {
					t.Error("obsolete authentication retained session authority")
				}
			})
		}
	}
}

func TestSessionGenerationPreservesNonsecurityChangesAndStartup(t *testing.T) {
	f, ctx := prepareLocalSession(t, true, true, false)
	original := f.manager.GetString(ctx, sessiongeneration.SessionKey)
	if _, err := f.model.DB.ExecContext(t.Context(), `UPDATE users SET name='Owned updated display name',email='updated@example.test',totp_secret='owned staged secret',modified=clock_timestamp() WHERE uid=$1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := sessiongeneration.Current(t.Context(), f.model.DB, f.user.ID, loginproof.Password)
	if err != nil || current.Encode() != original {
		t.Fatal("profile edits, unconfirmed staging or repeated startup changed the generation", err)
	}
	if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
		t.Fatal("nonsecurity change revoked the session", err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_certificates=false`); err != nil {
		t.Fatal(err)
	}
	if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
		t.Fatal("certificate policy revoked a password session", err)
	}
}

func TestSessionGenerationRollbackAndCallerSchema(t *testing.T) {
	for _, failure := range []string{"rollback", "trigger failure", "different caller schema"} {
		t.Run(failure, func(t *testing.T) {
			f, ctx := prepareLocalSession(t, true, true, false)
			original := f.manager.GetString(ctx, sessiongeneration.SessionKey)
			if failure == "trigger failure" {
				if _, err := f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION fail_owned_generation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned generation failure'; END $$; CREATE TRIGGER fail_owned_generation BEFORE UPDATE ON uem_session_account_generations FOR EACH ROW EXECUTE FUNCTION fail_owned_generation()`); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			relation := "users"
			if failure == "different caller schema" {
				relation = pgx.Identifier{f.pool.Config().ConnConfig.RuntimeParams["search_path"], "users"}.Sanitize()
				if _, err = tx.ExecContext(t.Context(), `SET LOCAL search_path=pg_catalog`); err != nil {
					t.Fatal(err)
				}
			}
			_, err = tx.ExecContext(t.Context(), `UPDATE `+relation+` SET hash='owned replacement hash' WHERE uid=$1`, f.user.ID)
			if failure == "trigger failure" && err == nil || failure != "trigger failure" && err != nil {
				t.Fatal("unexpected credential update result", err)
			}
			if failure == "different caller schema" {
				err = tx.Commit()
			} else {
				err = tx.Rollback()
			}
			if err != nil {
				t.Fatal(err)
			}
			current, err := sessiongeneration.Current(t.Context(), f.model.DB, f.user.ID, loginproof.Password)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "different caller schema" {
				if current.Encode() == original {
					t.Fatal("caller search path redirected generation update")
				}
			} else {
				if current.Encode() != original {
					t.Fatal("failed credential change advanced generation")
				}
				if admitted, err := localSessionRequest(f, ctx); !admitted || err != nil {
					t.Fatal("failed credential change revoked the valid session", err)
				}
			}
		})
	}
}

func TestSessionGenerationRejectsRecreatedAccount(t *testing.T) {
	f := newAccountPasswordFixture(t, true)
	previous, err := sessiongeneration.Current(t.Context(), f.model.DB, f.user.ID, loginproof.Password)
	if err != nil {
		t.Fatal(err)
	}
	original := previous.Encode()
	if err := f.model.Client.User.DeleteOneID(f.user.ID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	recreated, err := f.model.Client.User.Create().SetID(f.user.ID).SetName(f.user.Name).SetPasswd(true).SetHash(f.user.Hash).SetRegister(f.user.Register).SetCreated(f.user.Created).SetUse2fa(f.user.Use2fa).SetTotpSecretConfirmed(f.user.TotpSecretConfirmed).SetTotpSecret(f.user.TotpSecret).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.CheckLocalSession(t.Context(), recreated, loginproof.Password, original); !errors.Is(err, models.ErrLocalSignIn) {
		t.Fatal("recreated account inherited an earlier session", err)
	}
	current, err := sessiongeneration.Current(t.Context(), f.model.DB, recreated.ID, loginproof.Password)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.CheckLocalSession(t.Context(), recreated, loginproof.Password, current.Encode()); err != nil {
		t.Fatal("new account generation could not be authenticated", err)
	}
}

func TestSessionGenerationSurvivesNewProcess(t *testing.T) {
	f := newAccountPasswordFixture(t, true)
	stamp, err := sessiongeneration.Current(t.Context(), f.model.DB, f.user.ID, loginproof.Password)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	check := func(denied string) {
		t.Helper()
		child := exec.CommandContext(t.Context(), binary, "-test.run=^TestSessionGenerationRestartChild$", "-test.count=1")
		child.Env = append(os.Environ(), "OPENUEM_GENERATION_RESTART_CHECK=1", "OPENUEM_GENERATION_RESTART_DATABASE_URL="+f.pool.Config().ConnString(), "OPENUEM_GENERATION_RESTART_STAMP="+stamp.Encode(), "OPENUEM_GENERATION_RESTART_DENIED="+denied)
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatal("owned generation restart check failed", err, string(output))
		}
	}
	check("false")
	if _, err = f.model.DB.ExecContext(t.Context(), `UPDATE users SET totp_secret='KRSXG5DSNFXGOIDT' WHERE uid=$1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	check("true")
}

func TestSessionGenerationRestartChild(t *testing.T) {
	if os.Getenv("OPENUEM_GENERATION_RESTART_CHECK") != "1" {
		t.Skip("owned restart subprocess only")
	}
	m, err := models.New(os.Getenv("OPENUEM_GENERATION_RESTART_DATABASE_URL"), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = sessiongeneration.Migrate(t.Context(), m.DB); err != nil {
		t.Fatal(err)
	}
	u, err := m.Client.User.Get(t.Context(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	err = m.CheckLocalSession(t.Context(), u, loginproof.Password, os.Getenv("OPENUEM_GENERATION_RESTART_STAMP"))
	if os.Getenv("OPENUEM_GENERATION_RESTART_DENIED") == "true" {
		if !errors.Is(err, models.ErrLocalSignIn) {
			t.Fatal("old generation survived process restart", err)
		}
	} else if err != nil {
		t.Fatal("unchanged generation did not survive restart", err)
	}
}

func TestSessionGenerationPublicationFailureDoesNotIssueAuthority(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f, _ := prepareLocalSession(t, true, encrypted, false)
			if err := f.model.CreateDefaultTenantAndSite(); err != nil {
				t.Fatal(err)
			}
			if _, err := f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION fail_generation_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.user_sessions IS NOT NULL THEN RAISE EXCEPTION 'owned generation persistence failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_generation_publication BEFORE UPDATE OF data ON sessions FOR EACH ROW EXECUTE FUNCTION fail_generation_publication()`); err != nil {
				t.Fatal(err)
			}
			request := func() (context.Context, *httptest.ResponseRecorder, error) {
				ctx, err := f.manager.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				form := url.Values{"username": {f.user.ID}, "password": {accountOldPassword}}
				req := httptest.NewRequest(http.MethodPost, "https://console.test/login/userpass", strings.NewReader(form.Encode())).WithContext(ctx)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()
				c := echo.New().NewContext(req, rec)
				c.Set("csrf", "owned form token")
				return ctx, rec, f.handler.LoginPasswordAuth(c)
			}
			ctx, rec, err := request()
			if err == nil || f.manager.GetString(ctx, "uid") != "" {
				t.Fatal("failed generation persistence issued session authority", err)
			}
			for _, cookie := range rec.Result().Cookies() {
				if cookie.Name == f.manager.Cookie.Name && cookie.Value != "" {
					t.Fatal("failed generation persistence published a cookie")
				}
			}
			if _, err = f.model.DB.ExecContext(t.Context(), `DROP TRIGGER fail_generation_publication ON sessions`); err != nil {
				t.Fatal(err)
			}
			ctx, _, err = request()
			if err != nil || f.manager.GetString(ctx, "uid") != f.user.ID || f.manager.GetString(ctx, sessiongeneration.SessionKey) == "" {
				t.Fatal("valid retry did not publish its generation", err)
			}
			loaded, err := f.manager.Load(t.Context(), f.manager.Token(ctx))
			if err != nil || f.manager.GetString(loaded, sessiongeneration.SessionKey) != f.manager.GetString(ctx, sessiongeneration.SessionKey) {
				t.Fatal("published generation was not stored", err)
			}
		})
	}
}

func TestSessionGenerationStartupRejectsDisabledTriggers(t *testing.T) {
	f := newSessionFixture(t, false)
	if _, err := f.model.DB.ExecContext(t.Context(), `ALTER TABLE users DISABLE TRIGGER uem_account_generation`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Migrate(t.Context()); err == nil {
		t.Fatal("startup accepted an inactive credential-generation trigger")
	}
	if _, err := f.model.DB.ExecContext(t.Context(), `ALTER TABLE users ENABLE TRIGGER uem_account_generation`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal("valid generation triggers could not restart", err)
	}
}

// The generation check must observe credentials and policy under the same locks
// used by final admission, including a restored value after an earlier event.
func TestSessionGenerationCheckWaitsForCredentialTransaction(t *testing.T) {
	f, ctx := prepareLocalSession(t, true, true, false)
	tx, err := f.model.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(t.Context(), `UPDATE users SET hash='owned temporary hash' WHERE uid=$1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(t.Context(), `UPDATE users SET hash=$2 WHERE uid=$1`, f.user.ID, f.user.Hash); err != nil {
		t.Fatal(err)
	}
	limited, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if admitted, err := localSessionRequest(f, limited); admitted || err == nil {
		t.Fatal("generation check ignored the credential transaction", err)
	}
	if f.manager.GetString(ctx, "uid") != f.user.ID {
		t.Fatal("canceled check destroyed a not-yet-invalid session")
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if admitted, err := localSessionRequest(f, ctx); admitted || err == nil {
		t.Fatal("restored password revived the earlier authentication generation", err)
	}
}
