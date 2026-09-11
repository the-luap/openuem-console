package sessions_test

import (
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	console "github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/pquerna/otp/totp"
)

func TestPasswordRecoveryCannotAuthorizeMFA(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, action := range []string{"register", "confirm", "validate", "recovery code"} {
			t.Run(sessionMode(encrypted)+"/"+action, func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
				if err := f.model.CreateInitialSettings(); err != nil {
					t.Fatal(err)
				}
				if err := f.model.CreateDefaultTenantAndSite(); err != nil {
					t.Fatal(err)
				}
				const secret = "JBSWY3DPEHPK3PXP"
				user, err := f.model.Client.User.Create().SetID("mfa-user").SetName("Owned MFA user").SetPasswd(true).SetUse2fa(true).SetTotpSecret(secret).SetTotpSecretConfirmed(action != "confirm").SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				const backup = "ABCDEFGHJKLMNPQR"
				hash, err := argon2id.CreateHash(backup, argon2id.DefaultParams)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.model.Client.RecoveryCode.Create().SetUserID(user.ID).SetCode(hash).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				sm := scs.New()
				sm.Store = f.store
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
				c := echo.New().NewContext(httptest.NewRequest("POST", "https://console.test/fixture/recovery", nil).WithContext(ctx), httptest.NewRecorder())
				if err = h.CreateForgotPasswordSession(c, user); err != nil {
					t.Fatal(err)
				}
				ctx, err = sm.Load(t.Context(), sm.Token(ctx))
				if err != nil {
					t.Fatal(err)
				}
				code, err := totp.GenerateCode(secret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				form := url.Values{"confirm-code": {code}, "recovery-code": {backup}}
				req := httptest.NewRequest("POST", "https://console.test/fixture/mfa", strings.NewReader(form.Encode())).WithContext(ctx)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				c = echo.New().NewContext(req, httptest.NewRecorder())
				switch action {
				case "register":
					err = h.Register2FA(c)
				case "confirm":
					err = h.LoginTOTPConfirm(c)
				case "validate":
					err = h.LoginTOTPValidate(c)
				case "recovery code":
					err = h.LoginTOTPBackupCheck(c)
				}
				if err == nil {
					t.Error("password recovery crossed into an MFA-authorized operation")
				}
				current, err := f.model.Client.User.Get(t.Context(), user.ID)
				if err != nil {
					t.Fatal(err)
				}
				if current.TotpSecret != secret || current.TotpSecretConfirmed != user.TotpSecretConfirmed {
					t.Error("unverified recovery changed MFA enrollment")
				}
				if sm.GetBool(ctx, "twofa") || !sm.GetBool(ctx, "forgot") {
					t.Error("unverified recovery became a completed login")
				}
				count, err := f.model.Client.RecoveryCode.Query().Count(t.Context())
				if err != nil || count != 1 {
					t.Error("unverified recovery changed backup codes", count, err)
				}
			})
		}
	}
}

func TestPasswordMFALifecycleRequiresFreshPrimaryAuthentication(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, step := range []string{"TOTP", "backup code", "enrollment"} {
			t.Run(sessionMode(encrypted)+"/"+step, func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
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
				if err = settings.Update().SetUsePasswd(true).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				const password = "owned-password-123!"
				hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
				if err != nil {
					t.Fatal(err)
				}
				user, err := f.model.Client.User.Create().SetID("mfa-user").SetName("Owned MFA user").SetHash(hash).SetPasswd(true).SetUse2fa(true).SetTotpSecret("JBSWY3DPEHPK3PXP").SetTotpSecretConfirmed(step != "enrollment").SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				const backup = "ABCDEFGHJKLMNPQR"
				if step == "backup code" {
					hash, err := argon2id.CreateHash(backup, argon2id.DefaultParams)
					if err != nil {
						t.Fatal(err)
					}
					if err = f.model.Client.RecoveryCode.Create().SetUserID(user.ID).SetCode(hash).Exec(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				sm := scs.New()
				sm.Store = f.store
				h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				newRequest := func(form url.Values) echo.Context {
					req := httptest.NewRequest("POST", "https://console.test/fixture/mfa", strings.NewReader(form.Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					return echo.New().NewContext(req, httptest.NewRecorder())
				}
				if err = h.LoginPasswordAuth(newRequest(url.Values{"username": {user.ID}, "password": {password}})); err != nil {
					t.Fatal("valid first factor failed", err)
				}
				if _, err = loginproof.Read(sm.GetString(ctx, loginproof.SessionKey), user.ID, time.Now()); err != nil || sm.GetBool(ctx, "twofa") {
					t.Fatal("password did not create a bounded MFA flow", err)
				}
				firstToken := sm.Token(ctx)
				ctx, err = sm.Load(t.Context(), firstToken)
				if err != nil {
					t.Fatal(err)
				}
				current, err := f.model.Client.User.Get(t.Context(), user.ID)
				if err != nil {
					t.Fatal(err)
				}
				secret, _, err := sessiontokens.Decode(current.TotpSecret, f.key)
				if err != nil {
					t.Fatal(err)
				}
				code, err := totp.GenerateCode(secret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				c := newRequest(url.Values{"confirm-code": {code}, "recovery-code": {backup}})
				switch step {
				case "TOTP":
					err = h.LoginTOTPValidate(c)
				case "backup code":
					err = h.LoginTOTPBackupCheck(c)
				case "enrollment":
					err = h.LoginTOTPConfirm(c)
				}
				if err != nil {
					t.Fatal("valid second factor failed", err)
				}
				if !sm.GetBool(ctx, "twofa") || sm.Exists(ctx, loginproof.SessionKey) || sm.Token(ctx) == firstToken {
					t.Fatal("MFA did not consume primary flow and renew session")
				}
				if err = h.LoginTOTPValidate(newRequest(url.Values{"confirm-code": {code}})); err == nil {
					t.Fatal("completed flow could be reused for another MFA admission")
				}
			})
		}
	}
}

func TestMFARejectsMissingExpiredOrChangedPrimaryProof(t *testing.T) {
	for _, change := range []string{"missing", "missing phase", "expired", "other account", "changed password", "changed mode", "disabled method", "revoked", "review", "disabled MFA"} {
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
			user, err := f.model.Client.User.Create().SetID("mfa-user").SetName("Owned MFA user").SetHash("owned-password-hash").SetPasswd(true).SetUse2fa(true).SetTotpSecret("JBSWY3DPEHPK3PXP").SetTotpSecretConfirmed(true).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			sm := scs.New()
			sm.Store = f.store
			ctx, err := sm.Load(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			sm.Put(ctx, "uid", user.ID)
			sm.Put(ctx, "authentication-pending", true)
			sm.Put(ctx, loginproof.SessionKey, loginproof.New(user.ID, loginproof.Password, user.Hash, time.Now()))
			switch change {
			case "missing":
				sm.Remove(ctx, loginproof.SessionKey)
			case "missing phase":
				sm.Remove(ctx, "authentication-pending")
			case "expired":
				sm.Put(ctx, loginproof.SessionKey, loginproof.New(user.ID, loginproof.Password, user.Hash, time.Now().Add(-loginproof.Lifetime)))
			case "other account":
				sm.Put(ctx, loginproof.SessionKey, loginproof.New("other-user", loginproof.Password, user.Hash, time.Now()))
			case "changed password":
				err = user.Update().SetHash("replacement-hash").Exec(t.Context())
			case "changed mode":
				err = user.Update().SetPasswd(false).Exec(t.Context())
			case "disabled method":
				err = settings.Update().SetUsePasswd(false).Exec(t.Context())
			case "revoked":
				err = user.Update().SetRegister(nats.REGISTER_REVOKED).Exec(t.Context())
			case "review":
				err = user.Update().SetRegister(nats.REGISTER_IN_REVIEW).Exec(t.Context())
			case "disabled MFA":
				err = user.Update().SetUse2fa(false).Exec(t.Context())
			}
			if err != nil {
				t.Fatal(err)
			}
			h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key}
			code, err := totp.GenerateCode(user.TotpSecret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "https://console.test/fixture/mfa", strings.NewReader(url.Values{"confirm-code": {code}}.Encode())).WithContext(ctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			c := echo.New().NewContext(req, httptest.NewRecorder())
			if err = h.LoginTOTPValidate(c); err == nil {
				t.Fatal("changed first factor authorized MFA")
			}
			if sm.GetBool(ctx, "twofa") {
				t.Fatal("changed first factor completed MFA")
			}
		})
	}
}
