package sessions_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/router"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	console "github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/open-uem/utils"
	"github.com/pquerna/otp/totp"
)

func TestMFAAccountEnrollmentThroughProtectedRoutes(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f, ctx := prepareLocalSession(t, true, encrypted, false)
			if _, _, err := f.manager.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			e := router.New(f.handler.SessionManager, "console.test", "443", "1M")
			f.handler.Register(e, 3)
			e.GET("/fixture/csrf", func(c echo.Context) error { return c.String(http.StatusOK, c.Get("csrf").(string)) })
			e.GET("/fixture/authority", func(c echo.Context) error { return c.String(http.StatusOK, "owned protected response") }, f.handler.IsAuthenticated)
			cookies := map[string]*http.Cookie{f.manager.Cookie.Name: {Name: f.manager.Cookie.Name, Value: f.token}}
			request := func(method, path string, form url.Values) *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(method, "https://console.test"+path, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", "https://console.test")
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, req)
				for _, cookie := range rec.Result().Cookies() {
					if cookie.MaxAge < 0 {
						delete(cookies, cookie.Name)
					} else {
						cookies[cookie.Name] = cookie
					}
				}
				return rec
			}
			csrf := request(http.MethodGet, "/fixture/csrf", nil)
			if csrf.Code != http.StatusOK || csrf.Body.Len() == 0 {
				t.Fatal("MFA route fixture did not issue CSRF evidence")
			}
			if rec := request(http.MethodPost, "/myaccount/enable2fa", url.Values{"current-password": {accountOldPassword}}); rec.Code != http.StatusForbidden {
				t.Fatal("MFA enrollment accepted a missing CSRF token", rec.Code)
			}
			unchanged, err := f.model.Client.User.Get(t.Context(), f.user.ID)
			if err != nil || unchanged.TotpSecret != f.user.TotpSecret || unchanged.Use2fa {
				t.Fatal("rejected enrollment changed MFA", err)
			}
			rec := request(http.MethodPost, "/myaccount/enable2fa", url.Values{"csrf": {csrf.Body.String()}, "current-password": {accountOldPassword}})
			if rec.Code != http.StatusOK || rec.Result().Header.Get("Cache-Control") != "no-store" {
				t.Fatal("protected authenticator setup failed or permits storage", rec.Code)
			}
			staged, err := f.model.Client.User.Get(t.Context(), f.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			secret, wasEncrypted, err := sessiontokens.Decode(staged.TotpSecret, f.key)
			if err != nil || wasEncrypted != encrypted || !strings.Contains(rec.Body.String(), secret) {
				t.Fatal("protected setup did not show its persisted authenticator secret", err)
			}
			if rec = request(http.MethodGet, "/fixture/authority", nil); rec.Code != http.StatusOK {
				t.Fatal("staging an authenticator invalidated the existing session", rec.Code)
			}
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			rec = request(http.MethodPost, "/myaccount/register2fa", url.Values{"csrf": {csrf.Body.String()}, "confirm-code": {code}})
			if rec.Code != http.StatusOK || rec.Result().Header.Get("Cache-Control") != "no-store" {
				t.Fatal("protected MFA confirmation failed or permits storage", rec.Code)
			}
			shown := regexp.MustCompile(`[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}`).FindAllString(rec.Body.String(), -1)
			unique := map[string]bool{}
			for _, value := range shown {
				unique[value] = true
			}
			if len(unique) != 10 {
				t.Fatal("protected confirmation did not show ten recovery codes")
			}
			if rec = request(http.MethodGet, "/fixture/authority", nil); rec.Code != http.StatusUnauthorized || cookies[f.manager.Cookie.Name] != nil {
				t.Fatal("MFA activation did not retire the preceding single-factor session", rec.Code)
			}
		})
	}
}

func ownedRecoveryCodes() []string {
	codes := make([]string, 10)
	for i := range codes {
		codes[i] = fmt.Sprintf("OWNED-RECOVERY-%02d", i)
	}
	return codes
}

func TestMFAEnrollmentSerializesCompletionAndRetiresDisabledSessions(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, method := range []string{"password", "certificate", "OpenID"} {
			t.Run(sessionMode(encrypted)+"/"+method, func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
				if err := f.model.CreateInitialSettings(); err != nil {
					t.Fatal(err)
				}
				settings, err := f.model.GetAuthenticationSettings()
				if err != nil {
					t.Fatal(err)
				}
				if err = settings.Update().SetUsePasswd(true).SetUseCertificates(true).SetUseOIDC(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(method == "password").SetOpenid(method == "OpenID").SetHash("owned checked password hash").SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				stage, confirm, disable := f.model.SaveTOTPSecretKey, f.model.SaveRecoveryCodes, f.model.Disable2FA
				if method == "OpenID" {
					settings, err = settings.Update().SetOIDCIssuerURL("https://identity.example.test").SetOIDCClientID("owned-console").Save(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					permissions, err := access.NewStore(f.model.DB)
					if err != nil {
						t.Fatal(err)
					}
					if err = permissions.Migrate(t.Context()); err != nil {
						t.Fatal(err)
					}
					if err = permissions.Bootstrap(t.Context(), u.ID); err != nil {
						t.Fatal(err)
					}
					accounts, err := oidcaccounts.NewStore(f.model.DB, permissions)
					if err != nil {
						t.Fatal(err)
					}
					if err = accounts.Migrate(t.Context()); err != nil {
						t.Fatal(err)
					}
					if err = accounts.Change(t.Context(), u.ID, u.ID, settings.OIDCIssuerURL, settings.OIDCClientID, "owned-subject", "link", 0); err != nil {
						t.Fatal(err)
					}
					identity, err := accounts.SessionFor(t.Context(), oidcaccounts.PolicyFrom(settings), u.ID, "owned-subject")
					if err != nil {
						t.Fatal(err)
					}
					authorization := oidcaccounts.AccountMFA(*identity)
					stage = func(ctx context.Context, u *ent.User, secret string) error {
						return f.model.StageOIDCTOTPSecret(ctx, u, secret, authorization)
					}
					confirm = func(ctx context.Context, u *ent.User, codes []string) error {
						return f.model.ConfirmOIDCMFA(ctx, u, codes, authorization)
					}
					disable = func(ctx context.Context, u *ent.User) error { return f.model.DisableOIDCMFA(ctx, u, authorization) }
				}
				secret := "JBSWY3DPEHPK3PXP"
				if encrypted {
					secret, err = utils.EncryptSensitiveField(secret, f.key)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err = stage(t.Context(), u, secret); err != nil {
					t.Fatal("stage secret", err)
				}
				if err = stage(t.Context(), u, "stale replacement"); !errors.Is(err, models.ErrMFAState) {
					t.Fatal("stale secret staging succeeded", err)
				}
				u, err = f.model.Client.User.Get(t.Context(), u.ID)
				if err != nil {
					t.Fatal(err)
				}
				codes := [][]string{ownedRecoveryCodes(), ownedRecoveryCodes()}
				for i := range codes[1] {
					codes[1][i] = "SECOND-" + codes[1][i]
				}
				type result struct {
					index int
					err   error
				}
				done := make(chan result, 2)
				for i := range 2 {
					go func() { done <- result{i, confirm(t.Context(), u, codes[i])} }()
				}
				winner := -1
				for range 2 {
					r := <-done
					if r.err == nil {
						if winner >= 0 {
							t.Fatal("both enrollment generations completed")
						}
						winner = r.index
					} else if !errors.Is(r.err, models.ErrMFAState) {
						t.Fatal(r.err)
					}
				}
				if winner < 0 {
					t.Fatal("no enrollment completed")
				}
				current, err := f.model.Client.User.Get(t.Context(), u.ID)
				if err != nil {
					t.Fatal(err)
				}
				if !current.Use2fa || !current.TotpSecretConfirmed || current.TotpSecret != secret {
					t.Fatal("enrollment did not confirm the exact stored secret")
				}
				records, err := f.model.Client.RecoveryCode.Query().All(t.Context())
				if err != nil || len(records) != 10 {
					t.Fatal("enrollment retained an incomplete code set", len(records), err)
				}
				for _, code := range codes[winner] {
					matches := 0
					for _, record := range records {
						if yes, err := argon2id.ComparePasswordAndHash(code, record.Code); err != nil {
							t.Fatal(err)
						} else if yes {
							matches++
							break
						}
					}
					if matches != 1 {
						t.Fatal("published code set did not belong to the winner")
					}
				}
				if err = confirm(t.Context(), u, ownedRecoveryCodes()); !errors.Is(err, models.ErrMFAState) {
					t.Fatal("old enrollment replayed", err)
				}
				sm := scs.New()
				sm.Store = f.store
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				sm.Put(ctx, "uid", u.ID)
				token, _, err := sm.Commit(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.model.AddUserToSession(t.Context(), token, u.ID, f.key); err != nil {
					t.Fatal(err)
				}
				late, err := sm.Load(t.Context(), token)
				if err != nil {
					t.Fatal(err)
				}
				if err = disable(t.Context(), current); err != nil {
					t.Fatal("disable confirmed enrollment", err)
				}
				if _, _, err = sm.Commit(late); !errors.Is(err, sessions.ErrRevoked) {
					t.Fatal("disabled MFA retained an old session", err)
				}
				current, err = f.model.Client.User.Get(t.Context(), u.ID)
				if err != nil {
					t.Fatal(err)
				}
				if current.Use2fa || current.TotpSecretConfirmed || current.TotpSecret != "" {
					t.Fatal("disable retained MFA state")
				}
				if count, err := f.model.Client.RecoveryCode.Query().Count(t.Context()); err != nil || count != 0 {
					t.Fatal("disable retained recovery codes", count, err)
				}
			})
		}
	}
}

func TestMFAEnrollmentAccountHandlersPreserveEncryptedSnapshot(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f := newSessionFixture(t, encrypted)
			if err := f.model.CreateInitialSettings(); err != nil {
				t.Fatal(err)
			}
			settings, err := f.model.GetAuthenticationSettings()
			if err != nil {
				t.Fatal(err)
			}
			if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			const password = "Owned-MFA-Password-123!"
			hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
			if err != nil {
				t.Fatal(err)
			}
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash(hash).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			sm := scs.New()
			sm.Store = f.store
			ctx, err := sm.Load(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			sm.Put(ctx, "uid", u.ID)
			token, _, err := sm.Commit(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.model.AddUserToSession(t.Context(), token, u.ID, f.key); err != nil {
				t.Fatal(err)
			}
			h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
			newRequest := func(form url.Values) (echo.Context, *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodPost, "https://console.test/myaccount/mfa", strings.NewReader(form.Encode())).WithContext(ctx)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				recorder := httptest.NewRecorder()
				c := echo.New().NewContext(req, recorder)
				c.Set("csrf", "owned-form-token")
				return c, recorder
			}
			c, recorder := newRequest(url.Values{"current-password": {password}})
			if err = h.Enable2FA(c); err != nil {
				t.Fatal("account setup failed", err)
			}
			if recorder.Result().Header.Get("Cache-Control") != "no-store" {
				t.Error("account authenticator secret response permits storage")
			}
			staged, err := f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			secret, wasEncrypted, err := sessiontokens.Decode(staged.TotpSecret, f.key)
			if err != nil || wasEncrypted != encrypted || secret == "" || staged.TotpSecretConfirmed {
				t.Fatal("incorrectly staged secret", err)
			}
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			c, recorder = newRequest(url.Values{"confirm-code": {code}})
			if err = h.Enabled2FA(c); err != nil {
				t.Fatal("account confirmation failed", err)
			}
			if recorder.Result().Header.Get("Cache-Control") != "no-store" {
				t.Error("account recovery-code response permits storage")
			}
			shown := regexp.MustCompile(`[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}`).FindAllString(recorder.Body.String(), -1)
			unique := map[string]bool{}
			for _, code := range shown {
				unique[code] = true
			}
			if len(unique) != 10 {
				t.Fatal("confirmation did not show ten unique codes", len(unique))
			}
			current, err := f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !current.Use2fa || !current.TotpSecretConfirmed || current.TotpSecret != staged.TotpSecret {
				t.Fatal("confirmation replaced ciphertext or failed to activate MFA")
			}
			for _, action := range []func(echo.Context) error{h.Enable2FA, h.Enabled2FA} {
				c, _ = newRequest(url.Values{"current-password": {password}, "confirm-code": {code}})
				var response *echo.HTTPError
				if err = action(c); !errors.As(err, &response) || response.Code != http.StatusConflict {
					t.Fatal("confirmed account could restart enrollment", err)
				}
			}
			c, _ = newRequest(url.Values{"current-password": {"wrong owned password"}})
			_ = h.Disable2FA(c)
			current, err = f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil || !current.TotpSecretConfirmed {
				t.Fatal("wrong password disabled MFA", err)
			}
			c, _ = newRequest(url.Values{"current-password": {password}})
			if err = h.Disable2FA(c); err != nil {
				t.Fatal("account could not disable MFA", err)
			}
			if sm.GetString(ctx, "uid") != "" {
				t.Fatal("disable retained the browser session")
			}
			if _, found, err := f.store.FindCtx(t.Context(), token); err != nil || found {
				t.Fatal("disable retained the stored session", err)
			}
		})
	}
}

func TestMFAEnrollmentRejectsStaleAuthorizationAndCanceledMutation(t *testing.T) {
	for _, change := range []string{"password", "secret", "confirmed", "requirement", "mode", "revoked", "review", "disabled method", "canceled", "incomplete codes", "duplicate codes"} {
		t.Run(change, func(t *testing.T) {
			f := newSessionFixture(t, false)
			if err := f.model.CreateInitialSettings(); err != nil {
				t.Fatal(err)
			}
			settings, err := f.model.GetAuthenticationSettings()
			if err != nil {
				t.Fatal(err)
			}
			if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned checked password hash").SetRegister(nats.REGISTER_COMPLETE).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			codes := ownedRecoveryCodes()
			switch change {
			case "password":
				err = u.Update().SetHash("changed password").Exec(t.Context())
			case "secret":
				err = u.Update().SetTotpSecret("changed secret").Exec(t.Context())
			case "confirmed":
				err = u.Update().SetTotpSecretConfirmed(true).Exec(t.Context())
			case "requirement":
				err = u.Update().SetUse2fa(true).Exec(t.Context())
			case "mode":
				err = u.Update().SetOpenid(true).Exec(t.Context())
			case "revoked":
				err = u.Update().SetRegister(nats.REGISTER_REVOKED).Exec(t.Context())
			case "review":
				err = u.Update().SetRegister(nats.REGISTER_IN_REVIEW).Exec(t.Context())
			case "disabled method":
				err = settings.Update().SetUsePasswd(false).Exec(t.Context())
			case "incomplete codes":
				codes = codes[:9]
			case "duplicate codes":
				codes[9] = codes[0]
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if change == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Nanosecond)
				defer cancel()
				<-ctx.Done()
			}
			if err = f.model.SaveRecoveryCodes(ctx, u, codes); err == nil {
				t.Fatal("invalid authorization or codes confirmed enrollment")
			}
			if count, err := f.model.Client.RecoveryCode.Query().Count(t.Context()); err != nil || count != 0 {
				t.Fatal("denied enrollment wrote codes", count, err)
			}
		})
	}
}

func TestMFAEnrollmentFailurePreservesPreviousState(t *testing.T) {
	for _, failure := range []string{"third code", "confirmation", "disable", "session retirement"} {
		t.Run(failure, func(t *testing.T) {
			f := newSessionFixture(t, false)
			if err := f.model.CreateInitialSettings(); err != nil {
				t.Fatal(err)
			}
			settings, err := f.model.GetAuthenticationSettings()
			if err != nil {
				t.Fatal(err)
			}
			if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			disabling := failure == "disable" || failure == "session retirement"
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned checked password hash").SetRegister(nats.REGISTER_COMPLETE).SetUse2fa(disabling).SetTotpSecretConfirmed(disabling).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			old, err := f.model.Client.RecoveryCode.Create().SetUserID(u.ID).SetCode("owned previous hash").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			sm := scs.New()
			sm.Store = f.store
			ctx, err := sm.Load(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			sm.Put(ctx, "uid", u.ID)
			token, _, err := sm.Commit(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.model.AddUserToSession(t.Context(), token, u.ID, f.key); err != nil {
				t.Fatal(err)
			}
			fault := `CREATE FUNCTION fail_mfa_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned MFA update failure'; END $$; CREATE TRIGGER fail_mfa BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION fail_mfa_mutation()`
			if failure == "third code" {
				fault = `CREATE FUNCTION fail_mfa_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (SELECT count(*) FROM recovery_codes) >= 2 THEN RAISE EXCEPTION 'owned third recovery insert failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_mfa BEFORE INSERT ON recovery_codes FOR EACH ROW EXECUTE FUNCTION fail_mfa_mutation()`
			}
			if failure == "session retirement" {
				fault = `CREATE FUNCTION fail_mfa_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned session retirement failure'; END $$; CREATE TRIGGER fail_mfa BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION fail_mfa_mutation()`
			}
			if _, err = f.model.DB.ExecContext(t.Context(), fault); err != nil {
				t.Fatal(err)
			}
			if disabling {
				err = f.model.Disable2FA(t.Context(), u)
			} else {
				err = f.model.SaveRecoveryCodes(t.Context(), u, ownedRecoveryCodes())
			}
			if err == nil {
				t.Fatal("injected MFA write failure was ignored")
			}
			current, err := f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			codes, err := f.model.Client.RecoveryCode.Query().All(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if current.Use2fa != u.Use2fa || current.TotpSecretConfirmed != u.TotpSecretConfirmed || current.TotpSecret != u.TotpSecret || len(codes) != 1 || codes[0].ID != old.ID || codes[0].Code != old.Code {
				t.Fatal("failed MFA mutation lost or partially replaced previous state", len(codes))
			}
			if _, found, err := f.store.FindCtx(t.Context(), token); err != nil || !found {
				t.Fatal("failed mutation retired another session", err)
			}
		})
	}
}

func TestMFAEnrollmentCannotOverwriteConfirmedSecret(t *testing.T) {
	f := newSessionFixture(t, false)
	if err := f.model.CreateInitialSettings(); err != nil {
		t.Fatal(err)
	}
	settings, err := f.model.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned checked password hash").SetRegister(nats.REGISTER_COMPLETE).SetUse2fa(true).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = u.Update().SetTotpSecretConfirmed(true).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = f.model.SaveTOTPSecretKey(t.Context(), u, "KRSXG5DSNFXGOIDT"); err == nil {
		t.Error("stale enrollment overwrote the confirmed secret")
	}
	current, err := f.model.Client.User.Get(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.TotpSecret != u.TotpSecret || !current.TotpSecretConfirmed {
		t.Error("stale enrollment changed confirmed MFA state")
	}
}

func TestMFAEnrollmentRechecksConfirmationAfterRowWait(t *testing.T) {
	for _, outcome := range []string{"commit", "rollback", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			f := newSessionFixture(t, false)
			if err := f.model.CreateInitialSettings(); err != nil {
				t.Fatal(err)
			}
			settings, err := f.model.GetAuthenticationSettings()
			if err != nil {
				t.Fatal(err)
			}
			if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned checked password hash").SetRegister(nats.REGISTER_COMPLETE).SetUse2fa(true).SetTotpSecret("JBSWY3DPEHPK3PXP").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tx.Rollback() })
			if _, err = tx.ExecContext(t.Context(), `UPDATE users SET totp_secret_confirmed=true WHERE uid=$1`, u.ID); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- f.model.SaveTOTPSecretKey(ctx, u, "KRSXG5DSNFXGOIDT") }()
			deadline := time.Now().Add(4 * time.Second)
			for {
				var waiting bool
				if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT coalesce(passwd,false)%coalesce(totp_secret,%FOR UPDATE')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("secret update did not reach the held account")
				}
				time.Sleep(time.Millisecond)
			}
			if outcome == "cancel" {
				cancel()
				if err = <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("blocked MFA update ignored cancellation", err)
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
			if outcome != "cancel" {
				err = <-done
				if outcome == "commit" && !errors.Is(err, models.ErrMFAState) || outcome == "rollback" && err != nil {
					t.Fatal("MFA update missed current state", err)
				}
			}
			current, err := f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			wantSecret := u.TotpSecret
			if outcome == "rollback" {
				wantSecret = "KRSXG5DSNFXGOIDT"
			}
			if current.TotpSecret != wantSecret || current.TotpSecretConfirmed != (outcome == "commit") {
				t.Fatal("late MFA update changed another transaction's outcome")
			}
		})
	}
}
