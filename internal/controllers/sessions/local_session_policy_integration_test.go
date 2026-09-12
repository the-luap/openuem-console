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

	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/router"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

func TestLocalSessionRejectsChangedAccountAndMethodPolicy(t *testing.T) {
	for _, password := range []bool{false, true} {
		method := map[bool]string{false: "certificate", true: "password"}[password]
		for _, change := range []string{"revoked", "review", "forced password", "invitation", "issued certificate", "method switched", "OpenID mode", "method disabled", "missing method", "malformed method", "unconfirmed MFA", "removed MFA"} {
			t.Run(method+"/"+change, func(t *testing.T) {
				f := newAccountPasswordFixture(t, true)
				if err := f.user.Update().SetPasswd(password).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				if _, err := f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_certificates=true,use_passwd=true`); err != nil {
					t.Fatal(err)
				}
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
				ctx, err := f.manager.Load(t.Context(), f.token)
				if err != nil {
					t.Fatal(err)
				}
				f.manager.Put(ctx, "usepasswd", password)
				switch change {
				case "revoked":
					err = f.user.Update().SetRegister(nats.REGISTER_REVOKED).Exec(t.Context())
				case "review":
					err = f.user.Update().SetRegister(nats.REGISTER_IN_REVIEW).Exec(t.Context())
				case "forced password":
					err = f.user.Update().SetRegister(nats.REGISTER_FORCE_PASSWORD_CHANGE).Exec(t.Context())
				case "invitation":
					err = f.user.Update().SetRegister(nats.REGISTER_PASSWORD_LINK_SENT).Exec(t.Context())
				case "issued certificate":
					err = f.user.Update().SetRegister(nats.REGISTER_CERTIFICATE_SENT).Exec(t.Context())
				case "method switched":
					err = f.user.Update().SetPasswd(!password).Exec(t.Context())
				case "OpenID mode":
					err = f.user.Update().SetOpenid(true).Exec(t.Context())
				case "method disabled":
					if password {
						_, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=false`)
					} else {
						_, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_certificates=false`)
					}
				case "missing method":
					f.manager.Remove(ctx, "usepasswd")
				case "malformed method":
					f.manager.Put(ctx, "usepasswd", "false")
				case "unconfirmed MFA":
					err = f.user.Update().SetTotpSecretConfirmed(false).Exec(t.Context())
				case "removed MFA":
					err = f.user.Update().SetUse2fa(false).Exec(t.Context())
				}
				if err != nil {
					t.Fatal(err)
				}
				c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "https://console.test/myaccount", nil).WithContext(ctx), httptest.NewRecorder())
				c.SetPath("/myaccount")
				c.Set("csrf", "owned form token")
				admitted := false
				err = f.handler.IsAuthenticated(func(echo.Context) error { admitted = true; return nil })(c)
				var denied *echo.HTTPError
				if admitted || !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized {
					t.Errorf("existing %s session survived %s: admitted=%v, error=%v", method, change, admitted, err)
				}
				if f.manager.GetString(ctx, "uid") != "" {
					t.Error("denied session retained account authority")
				}
				if err = f.store.CommitCtx(t.Context(), f.token, []byte("owned stale writer"), time.Now().Add(time.Hour)); !errors.Is(err, sessions.ErrRevoked) {
					t.Error("denied session could be recreated by a stale writer", err)
				}
			})
		}
	}
}

func prepareLocalSession(t *testing.T, password, encrypted, mfa bool) (accountPasswordFixture, context.Context) {
	t.Helper()
	f := newAccountPasswordFixture(t, encrypted)
	var err error
	f.user, err = f.user.Update().SetPasswd(password).SetUse2fa(mfa).SetTotpSecretConfirmed(mfa).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `UPDATE authentications SET use_certificates=true,use_passwd=true`); err != nil {
		t.Fatal(err)
	}
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
	ctx, err := f.manager.Load(t.Context(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	f.manager.Put(ctx, "usepasswd", password)
	f.manager.Put(ctx, "twofa", mfa)
	return f, ctx
}

func localSessionRequest(f accountPasswordFixture, ctx context.Context) (bool, error) {
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "https://console.test/myaccount", nil).WithContext(ctx), httptest.NewRecorder())
	c.SetPath("/myaccount")
	c.Set("csrf", "owned form token")
	admitted := false
	err := f.handler.IsAuthenticated(func(echo.Context) error { admitted = true; return nil })(c)
	return admitted, err
}

func TestLocalSessionCurrentPolicyPreservesValidAndPendingFlows(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, password := range []bool{false, true} {
			for _, mfa := range []bool{false, true} {
				name := sessionMode(encrypted) + "/" + map[bool]string{false: "certificate", true: "password"}[password] + "/" + map[bool]string{false: "single factor", true: "MFA"}[mfa]
				t.Run(name, func(t *testing.T) {
					f, ctx := prepareLocalSession(t, password, encrypted, mfa)
					for range 2 {
						if admitted, err := localSessionRequest(f, ctx); err != nil || !admitted {
							t.Fatal("valid local session was denied", err)
						}
					}
					current, err := f.model.Client.User.Get(t.Context(), f.user.ID)
					if err != nil || current.Register != f.user.Register || !current.Modified.Equal(f.user.Modified) || current.Hash != f.user.Hash || current.TotpSecret != f.user.TotpSecret {
						t.Fatal("policy verification mutated the account", err)
					}
				})
			}
		}
	}
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "pending issued certificate", false: "unproven pending certificate"}[valid], func(t *testing.T) {
			f, ctx := prepareLocalSession(t, false, true, true)
			if err := f.user.Update().SetRegister(nats.REGISTER_CERTIFICATE_SENT).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			f.manager.Put(ctx, "twofa", false)
			f.manager.Put(ctx, "authentication-pending", true)
			if valid {
				_, credential := ownedConsoleCertificate(t, f.user.ID)
				registerOwnedConsoleCertificate(t, f.sessionFixture, credential.Leaf)
				f.manager.Put(ctx, clientidentity.SessionCertificateKey, clientidentity.EncodeSessionCertificate(credential.Leaf))
				f.manager.Put(ctx, loginproof.SessionKey, loginproof.New(f.user.ID, loginproof.Certificate, string(credential.Leaf.Raw), time.Now()))
			}
			admitted, err := localSessionRequest(f, ctx)
			if admitted {
				t.Fatal("pending certificate became a completed session")
			}
			if valid {
				if err != nil || f.manager.GetString(ctx, "uid") != f.user.ID || f.manager.GetBool(ctx, "twofa") {
					t.Fatal("valid pending certificate did not retain its MFA challenge", err)
				}
			} else {
				var denied *echo.HTTPError
				if !errors.As(err, &denied) || denied.Code != http.StatusUnauthorized || f.manager.GetString(ctx, "uid") != "" {
					t.Fatal("pending certificate without a primary proof was not retired", err)
				}
			}
		})
	}
}

func TestLocalSessionPolicyFailureRetainsValidSessionAndRetries(t *testing.T) {
	for _, operation := range []string{"account lookup", "configuration lock", "missing table"} {
		t.Run(operation, func(t *testing.T) {
			f, ctx := prepareLocalSession(t, true, true, false)
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			switch operation {
			case "account lookup":
				_, err = tx.ExecContext(t.Context(), `LOCK TABLE users IN ACCESS EXCLUSIVE MODE`)
			case "configuration lock":
				_, err = tx.ExecContext(t.Context(), `UPDATE authentications SET use_passwd=true`)
			case "missing table":
				_, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE authentications RENAME TO owned_unavailable_authentications`)
			}
			if err != nil {
				t.Fatal(err)
			}
			limited, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			defer cancel()
			admitted, err := localSessionRequest(f, limited)
			var unavailable *echo.HTTPError
			if admitted || !errors.As(err, &unavailable) || unavailable.Code != http.StatusServiceUnavailable {
				t.Fatal("unavailable policy did not return a service error", admitted, err)
			}
			if f.manager.GetString(ctx, "uid") != f.user.ID {
				t.Fatal("transient verification failure destroyed the valid session")
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if operation == "missing table" {
				if _, err = f.model.DB.ExecContext(t.Context(), `ALTER TABLE owned_unavailable_authentications RENAME TO authentications`); err != nil {
					t.Fatal(err)
				}
			}
			if admitted, err = localSessionRequest(f, ctx); err != nil || !admitted {
				t.Fatal("valid session could not retry after transient failure", err)
			}
		})
	}
}

func TestLocalSessionPolicyRechecksAfterConcurrentAccountWait(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed revocation", true: "rolled back revocation"}[rollback], func(t *testing.T) {
			f, ctx := prepareLocalSession(t, true, true, false)
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(t.Context(), `UPDATE users SET register=$2 WHERE uid=$1`, f.user.ID, nats.REGISTER_REVOKED); err != nil {
				t.Fatal(err)
			}
			type result struct {
				admitted bool
				err      error
			}
			done := make(chan result, 1)
			go func() {
				admitted, err := localSessionRequest(f, ctx)
				done <- result{admitted, err}
			}()
			deadline := time.Now().Add(3 * time.Second)
			for {
				var waiting bool
				if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT coalesce(passwd,false),coalesce(openid,false)%FROM users%FOR SHARE')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("policy check never reached the held account row")
				}
				time.Sleep(time.Millisecond)
			}
			if rollback {
				err = tx.Rollback()
			} else {
				err = tx.Commit()
			}
			if err != nil {
				t.Fatal(err)
			}
			r := <-done
			if rollback {
				if !r.admitted || r.err != nil {
					t.Fatal("rolled-back revocation denied the valid session", r.err)
				}
			} else {
				var denied *echo.HTTPError
				if r.admitted || !errors.As(r.err, &denied) || denied.Code != http.StatusUnauthorized || f.manager.GetString(ctx, "uid") != "" {
					t.Fatal("policy check did not observe committed revocation", r.err)
				}
			}
		})
	}
}

func TestLocalSessionPolicyRetirementThroughRegisteredRoute(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, password := range []bool{false, true} {
			t.Run(sessionMode(encrypted)+"/"+map[bool]string{false: "certificate", true: "password"}[password], func(t *testing.T) {
				f, ctx := prepareLocalSession(t, password, encrypted, true)
				if _, _, err := f.manager.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				e := router.New(f.handler.SessionManager, "console.test", "443", "1M")
				f.handler.Register(e, 3)
				e.GET("/fixture/csrf", func(c echo.Context) error { return c.String(http.StatusOK, c.Get("csrf").(string)) })
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://console.test/fixture/csrf", nil))
				if rec.Code != http.StatusOK {
					t.Fatal("CSRF fixture failed", rec.Code)
				}
				var csrf *http.Cookie
				for _, cookie := range rec.Result().Cookies() {
					if cookie.Name == "__Host-openuem-csrf" {
						csrf = cookie
					}
				}
				if csrf == nil {
					t.Fatal("router omitted CSRF cookie")
				}
				form := url.Values{"csrf": {rec.Body.String()}, "current-password": {accountOldPassword}, "new-password": {accountOldPassword}, "confirm-new-password": {accountOldPassword}}
				request := func() *httptest.ResponseRecorder {
					req := httptest.NewRequest(http.MethodPost, "https://console.test/myaccount/password", strings.NewReader(form.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("Origin", "https://console.test")
					req.AddCookie(csrf)
					req.AddCookie(&http.Cookie{Name: f.manager.Cookie.Name, Value: f.token})
					rec := httptest.NewRecorder()
					e.ServeHTTP(rec, req)
					return rec
				}
				want := http.StatusForbidden // Certificate accounts cannot change a local password.
				if password {
					want = http.StatusBadRequest // The same password is rejected without mutating state.
				}
				if rec = request(); rec.Code != want {
					t.Fatal("valid session did not reach registered account validation", rec.Code)
				}
				if err := f.user.Update().SetRegister(nats.REGISTER_REVOKED).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				if rec = request(); rec.Code != http.StatusUnauthorized {
					t.Fatal("revoked account reached the registered mutation", rec.Code)
				}
				deletedCookie := false
				for _, cookie := range rec.Result().Cookies() {
					if cookie.Name == f.manager.Cookie.Name && cookie.MaxAge < 0 {
						deletedCookie = true
					}
				}
				if !deletedCookie {
					t.Error("retirement did not remove the browser cookie")
				}
				if err := f.store.CommitCtx(t.Context(), f.token, []byte("owned stale writer"), time.Now().Add(time.Hour)); !errors.Is(err, sessions.ErrRevoked) {
					t.Fatal("retired cookie could be recreated", err)
				}
				if err := f.user.Update().SetRegister(nats.REGISTER_COMPLETE).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				if rec = request(); rec.Code != http.StatusOK || rec.Header().Get("HX-Retarget") != "body" {
					t.Fatal("restoring account policy did not require a fresh sign-in", rec.Code)
				}
			})
		}
	}
}
