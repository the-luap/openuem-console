package sessions_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
)

func TestAccountPasswordChangeRetiresSessionsAndRecoveryGrants(t *testing.T) {
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
			const oldPassword, newPassword = "Owned-Previous-Password-123!", "Owned-Replacement-Password-456!"
			hash, err := argon2id.CreateHash(oldPassword, argon2id.DefaultParams)
			if err != nil {
				t.Fatal(err)
			}
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned account user").SetPasswd(true).SetHash(hash).SetRegister(nats.REGISTER_COMPLETE).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret("JBSWY3DPEHPK3PXP").SetForgotPasswordCode("owned outstanding recovery hash").SetForgotPasswordCodeExpiresAt(time.Now().Add(time.Hour)).SetNewUserToken("owned outstanding invitation").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err = f.model.Client.User.Create().SetID("other").SetName("Other owned account").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			sm := scs.New()
			sm.Store = f.store
			tokens := make([]string, 3)
			for i, owner := range []string{u.ID, u.ID, "other"} {
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				sm.Put(ctx, "uid", owner)
				sm.Put(ctx, "twofa", true)
				tokens[i], _, err = sm.Commit(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.model.AddUserToSession(t.Context(), tokens[i], owner, f.key); err != nil {
					t.Fatal(err)
				}
			}
			ctx, err := sm.Load(t.Context(), tokens[0])
			if err != nil {
				t.Fatal(err)
			}
			late, err := sm.Load(t.Context(), tokens[1])
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "https://console.test/myaccount/password", strings.NewReader(url.Values{"current-password": {oldPassword}, "new-password": {newPassword}, "confirm-new-password": {newPassword}}.Encode())).WithContext(ctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			c := echo.New().NewContext(req, httptest.NewRecorder())
			c.Set("csrf", "owned form token")
			h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
			if err = h.MyAccountPassword(c); err != nil {
				t.Fatal("valid account password change failed", err)
			}
			if sm.GetString(ctx, "uid") != "" {
				t.Error("password change retained current session authority")
			}
			current, err := f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if match, err := argon2id.ComparePasswordAndHash(newPassword, current.Hash); err != nil || !match {
				t.Fatal("new password was not stored", err)
			}
			if current.ForgotPasswordCode != "" || current.NewUserToken != "" {
				t.Error("password change retained older recovery grants")
			}
			if !current.Use2fa || !current.TotpSecretConfirmed || current.TotpSecret != u.TotpSecret {
				t.Error("password change damaged MFA")
			}
			if _, _, err = sm.Commit(late); !errors.Is(err, sessions.ErrRevoked) {
				t.Error("password change allowed another preloaded session to return", err)
			}
			if _, found, err := f.store.FindCtx(t.Context(), tokens[2]); err != nil || !found {
				t.Error("password change retired another account's session", err)
			}
		})
	}
}

func TestAccountPasswordChangeCannotUndoConcurrentPolicy(t *testing.T) {
	for _, change := range []string{"revocation", "review", "password", "method", "MFA requirement", "MFA confirmation", "MFA secret", "disabled passwords"} {
		t.Run(change, func(t *testing.T) {
			f := newSessionFixture(t, true)
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
			const oldPassword, newPassword = "Owned-Previous-Password-123!", "Owned-Replacement-Password-456!"
			hash, err := argon2id.CreateHash(oldPassword, argon2id.DefaultParams)
			if err != nil {
				t.Fatal(err)
			}
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned account user").SetPasswd(true).SetHash(hash).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
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
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tx.Rollback() })
			wantHash, wantRegister := hash, nats.REGISTER_COMPLETE
			switch change {
			case "revocation":
				wantRegister = nats.REGISTER_REVOKED
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET register=$2 WHERE uid=$1`, u.ID, wantRegister)
			case "review":
				wantRegister = nats.REGISTER_IN_REVIEW
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET register=$2 WHERE uid=$1`, u.ID, wantRegister)
			case "password":
				wantHash = "owned intervening credential hash"
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET hash=$2 WHERE uid=$1`, u.ID, wantHash)
			case "method":
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET passwd=false,openid=true WHERE uid=$1`, u.ID)
			case "MFA requirement":
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET use2fa=true WHERE uid=$1`, u.ID)
			case "MFA confirmation":
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET totp_secret_confirmed=true WHERE uid=$1`, u.ID)
			case "MFA secret":
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET totp_secret='owned intervening secret' WHERE uid=$1`, u.ID)
			case "disabled passwords":
				_, err = tx.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=false`)
			}
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "https://console.test/myaccount/password", strings.NewReader(url.Values{"current-password": {oldPassword}, "new-password": {newPassword}, "confirm-new-password": {newPassword}}.Encode())).WithContext(ctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			c := echo.New().NewContext(req, httptest.NewRecorder())
			c.Set("csrf", "owned form token")
			h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
			done := make(chan error, 1)
			go func() { done <- h.MyAccountPassword(c) }()
			deadline := time.Now().Add(4 * time.Second)
			for {
				var waiting bool
				if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND (query LIKE 'SELECT coalesce(use_passwd,%FROM authentications%FOR SHARE' OR query LIKE 'SELECT hash,register,forgot_password_code%FOR UPDATE'))`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("password change did not reach the held account")
				}
				time.Sleep(time.Millisecond)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var denied *echo.HTTPError
			if err = <-done; !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized {
				t.Fatal("stale password change was not denied", err)
			}
			current, err := f.model.Client.User.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.Hash != wantHash || current.Register != wantRegister {
				t.Error("password change overrode newer authorization or credentials")
			}
		})
	}
}

func TestAccountPasswordChangeRegisteredRoute(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f := newAccountPasswordFixture(t, encrypted)
			permissions, err := access.NewStore(f.model.DB)
			if err != nil {
				t.Fatal(err)
			}
			if err = permissions.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = permissions.Bootstrap(t.Context(), f.user.ID); err != nil {
				t.Fatal(err)
			}
			f.handler.Access = permissions
			e := router.New(f.handler.SessionManager, "console.test", "443", "1M")
			f.handler.Register(e, 3)
			e.GET("/fixture/authority", func(c echo.Context) error {
				return c.String(http.StatusOK, f.manager.GetString(c.Request().Context(), "uid"))
			})
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
			if rec := request(http.MethodGet, "/fixture/authority", nil); rec.Code != http.StatusOK || rec.Body.String() != f.user.ID {
				t.Fatal("owned session did not load through the router", rec.Code)
			}
			csrf := cookies["__Host-openuem-csrf"]
			if csrf == nil {
				t.Fatal("router did not issue CSRF cookie")
			}
			form := url.Values{"current-password": {accountOldPassword}, "new-password": {accountNewPassword}, "confirm-new-password": {accountNewPassword}}
			if rec := request(http.MethodPost, "/myaccount/password", form); rec.Code != http.StatusForbidden {
				t.Fatal("password change accepted a missing CSRF token", rec.Code)
			}
			f.unchanged(t, f.user)
			form.Set("csrf", csrf.Value)
			if rec := request(http.MethodPost, "/myaccount/password", form); rec.Code != http.StatusOK || rec.Header().Get("HX-Retarget") != "body" {
				t.Fatal("registered password change did not return sign-in", rec.Code)
			}
			if rec := request(http.MethodGet, "/fixture/authority", nil); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
				t.Fatal("completed password change retained browser authority", rec.Code)
			}
			// Even a client ignoring the cookie deletion cannot reuse the old token.
			cookies[f.manager.Cookie.Name] = &http.Cookie{Name: f.manager.Cookie.Name, Value: f.token}
			if rec := request(http.MethodGet, "/fixture/authority", nil); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
				t.Fatal("retired session cookie restored authority", rec.Code)
			}
			current, err := f.model.Client.User.Get(t.Context(), f.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if match, err := argon2id.ComparePasswordAndHash(accountNewPassword, current.Hash); err != nil || !match {
				t.Fatal("registered password change failed to store the credential", err)
			}
		})
	}
}

const accountOldPassword = "Owned-Previous-Password-123!"
const accountNewPassword = "Owned-Replacement-Password-456!"

type accountPasswordFixture struct {
	sessionFixture
	user    *ent.User
	manager *scs.SessionManager
	token   string
	handler *console.Handler
}

func newAccountPasswordFixture(t *testing.T, encrypted bool) accountPasswordFixture {
	t.Helper()
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
	hash, err := argon2id.CreateHash(accountOldPassword, argon2id.DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned account user").SetPasswd(true).SetHash(hash).SetRegister(nats.REGISTER_COMPLETE).SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret("JBSWY3DPEHPK3PXP").SetForgotPasswordCode("owned outstanding recovery hash").SetForgotPasswordCodeExpiresAt(time.Now().Add(time.Hour)).SetNewUserToken("owned outstanding invitation").Save(t.Context())
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
	sm.Put(ctx, "twofa", true)
	sm.Put(ctx, "usepasswd", true)
	stamp, err := sessiongeneration.Current(t.Context(), f.model.DB, u.ID, loginproof.Password)
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, sessiongeneration.SessionKey, stamp.Encode())
	token, _, err := sm.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.model.AddUserToSession(t.Context(), token, u.ID, f.key); err != nil {
		t.Fatal(err)
	}
	h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
	return accountPasswordFixture{f, u, sm, token, h}
}

func (f accountPasswordFixture) request(t *testing.T, form url.Values, twofa bool) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	ctx, err := f.manager.Load(t.Context(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	f.manager.Put(ctx, "twofa", twofa)
	req := httptest.NewRequest(http.MethodPost, "https://console.test/myaccount/password", strings.NewReader(form.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r := httptest.NewRecorder()
	c := echo.New().NewContext(req, r)
	c.Set("csrf", "owned form token")
	return c, r
}

func (f accountPasswordFixture) unchanged(t *testing.T, expected *ent.User) {
	t.Helper()
	current, err := f.model.Client.User.Get(t.Context(), expected.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Hash != expected.Hash || current.Register != expected.Register || current.ForgotPasswordCode != expected.ForgotPasswordCode || !current.ForgotPasswordCodeExpiresAt.Equal(expected.ForgotPasswordCodeExpiresAt) || current.NewUserToken != expected.NewUserToken || current.Use2fa != expected.Use2fa || current.TotpSecretConfirmed != expected.TotpSecretConfirmed || current.TotpSecret != expected.TotpSecret {
		t.Fatal("denied password change altered credentials, grants or MFA")
	}
	if _, found, err := f.store.FindCtx(t.Context(), f.token); err != nil || !found {
		t.Fatal("denied password change removed the session", err)
	}
	var receipts int
	if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM sessions_revocations`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("denied password change left revocation receipts", receipts, err)
	}
}

func TestAccountPasswordChangeDeniesInvalidStateAndInput(t *testing.T) {
	for _, invalid := range []string{"revoked", "review", "forced password", "invitation", "certificate", "OpenID", "disabled password", "missing MFA", "unconfirmed MFA", "wrong password", "empty current", "empty new", "empty confirmation", "mismatch", "same password", "weak password"} {
		t.Run(invalid, func(t *testing.T) {
			f := newAccountPasswordFixture(t, true)
			form := url.Values{"current-password": {accountOldPassword}, "new-password": {accountNewPassword}, "confirm-new-password": {accountNewPassword}}
			twofa, status := true, http.StatusUnauthorized
			var err error
			switch invalid {
			case "revoked":
				err = f.user.Update().SetRegister(nats.REGISTER_REVOKED).Exec(t.Context())
			case "review":
				err = f.user.Update().SetRegister(nats.REGISTER_IN_REVIEW).Exec(t.Context())
			case "forced password":
				err = f.user.Update().SetRegister(nats.REGISTER_FORCE_PASSWORD_CHANGE).Exec(t.Context())
			case "invitation":
				err = f.user.Update().SetRegister(nats.REGISTER_PASSWORD_LINK_SENT).Exec(t.Context())
			case "certificate":
				err = f.user.Update().SetPasswd(false).Exec(t.Context())
				status = http.StatusForbidden
			case "OpenID":
				err = f.user.Update().SetOpenid(true).Exec(t.Context())
				status = http.StatusForbidden
			case "disabled password":
				_, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=false`)
			case "missing MFA":
				twofa = false
			case "unconfirmed MFA":
				err = f.user.Update().SetTotpSecretConfirmed(false).Exec(t.Context())
			case "same password":
				form.Set("new-password", accountOldPassword)
				form.Set("confirm-new-password", accountOldPassword)
				status = http.StatusBadRequest
			default:
				status = http.StatusOK // Existing form errors render an HTMX error fragment.
				switch invalid {
				case "wrong password":
					form.Set("current-password", "Owned-Wrong-Password-789!")
				case "empty current":
					form.Set("current-password", "")
				case "empty new":
					form.Set("new-password", "")
				case "empty confirmation":
					form.Set("confirm-new-password", "")
				case "mismatch":
					form.Set("confirm-new-password", "Owned-Mismatched-Password-789!")
				case "weak password":
					form.Set("new-password", "short")
					form.Set("confirm-new-password", "short")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			expected, err := f.model.Client.User.Get(t.Context(), f.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			c, recorder := f.request(t, form, twofa)
			err = f.handler.MyAccountPassword(c)
			if status == http.StatusOK {
				if err != nil || recorder.Header().Get("HX-Retarget") != "#error" {
					t.Fatal("invalid input did not render a form error", err)
				}
			} else {
				var denied *echo.HTTPError
				if !errors.As(err, &denied) || denied.Code != status {
					t.Fatal("invalid password change had the wrong status", err)
				}
			}
			f.unchanged(t, expected)
		})
	}
}

func TestAccountPasswordChangeHasOneWinnerAndRejectsSerializedAccountProof(t *testing.T) {
	f := newAccountPasswordFixture(t, true)
	proof := models.PasswordReplacementProof{Kind: "authenticated_account", PasswordDigest: models.PasswordReplacementDigest(f.user.Hash), ExpiresAt: time.Now().Add(time.Minute)}
	if err := f.model.ChangePasswordWithProof(t.Context(), f.user.ID, accountNewPassword, proof); !errors.Is(err, models.ErrPasswordReplacement) {
		t.Fatal("serialized recovery proof entered the account-settings path", err)
	}
	f.unchanged(t, f.user)
	done := make(chan error, 4)
	for range 4 {
		go func() { done <- f.model.ChangeAccountPassword(t.Context(), f.user, accountNewPassword) }()
	}
	winners := 0
	for range 4 {
		if err := <-done; err == nil {
			winners++
		} else if !errors.Is(err, models.ErrPasswordReplacement) {
			t.Fatal("unexpected competing password change failure", err)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent password changes did not have one winner", winners)
	}
}

func TestAccountPasswordChangeStorageFailureRollsBack(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f := newAccountPasswordFixture(t, encrypted)
			if _, err := f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION fail_account_session_retirement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned retirement diagnostic must remain private'; END $$; CREATE TRIGGER fail_account_retirement BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION fail_account_session_retirement()`); err != nil {
				t.Fatal(err)
			}
			form := url.Values{"current-password": {accountOldPassword}, "new-password": {accountNewPassword}, "confirm-new-password": {accountNewPassword}}
			c, _ := f.request(t, form, true)
			err := f.handler.MyAccountPassword(c)
			var unavailable *echo.HTTPError
			if !errors.As(err, &unavailable) || unavailable.Code != http.StatusServiceUnavailable || strings.Contains(err.Error(), "owned retirement") {
				t.Fatal("storage failure was not a generic unavailable response", err)
			}
			f.unchanged(t, f.user)
			if _, err = f.model.DB.ExecContext(t.Context(), `DROP TRIGGER fail_account_retirement ON sessions`); err != nil {
				t.Fatal(err)
			}
			c, _ = f.request(t, form, true)
			if err = f.handler.MyAccountPassword(c); err != nil {
				t.Fatal("failed transaction prevented a valid retry", err)
			}
		})
	}
}

func TestAccountPasswordChangeCanceledAndRolledBackLockWaits(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(map[bool]string{false: "rolled back revocation", true: "canceled request"}[cancelRequest], func(t *testing.T) {
			f := newAccountPasswordFixture(t, true)
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(t.Context(), `UPDATE users SET register=$2 WHERE uid=$1`, f.user.ID, nats.REGISTER_REVOKED); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- f.model.ChangeAccountPassword(ctx, f.user, accountNewPassword) }()
			deadline := time.Now().Add(3 * time.Second)
			for {
				var waiting bool
				if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT hash,register,forgot_password_code%FOR UPDATE')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("password change did not wait for the account row")
				}
				time.Sleep(time.Millisecond)
			}
			if cancelRequest {
				cancel()
				if err = <-done; err == nil {
					t.Fatal("canceled password change succeeded")
				}
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if cancelRequest {
				f.unchanged(t, f.user)
				if err = f.model.ChangeAccountPassword(t.Context(), f.user, accountNewPassword); err != nil {
					t.Fatal("canceled wait prevented retry", err)
				}
			} else if err = <-done; err != nil {
				t.Fatal("rolled-back revocation blocked the valid change", err)
			}
		})
	}
}
