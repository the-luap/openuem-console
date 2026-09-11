package sessions_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	certificate "github.com/open-uem/openuem-console/internal/controllers/authserver/handlers"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	console "github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

func TestPasswordSignInHonorsLocalAccountAndMethodPolicy(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, policy := range []string{"revoked", "review", "certificate account", "disabled passwords", "revoked during admission", "password changed during admission", "MFA enabled during admission"} {
			t.Run(sessionMode(encrypted)+"/"+policy, func(t *testing.T) {
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
				if err = settings.Update().SetUsePasswd(policy != "disabled passwords").Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				const password = "owned-password-123!"
				hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
				if err != nil {
					t.Fatal(err)
				}
				register := nats.REGISTER_COMPLETE
				if policy == "revoked" {
					register = nats.REGISTER_REVOKED
				}
				if policy == "review" {
					register = nats.REGISTER_IN_REVIEW
				}
				user, err := f.model.Client.User.Create().SetID("policy-user").SetName("Owned policy user").SetHash(hash).SetPasswd(policy != "certificate account").SetRegister(register).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(policy, "during admission") {
					change := `register='users.certificate_revoked'`
					if policy == "password changed during admission" {
						change = `hash='replacement-password-hash'`
					}
					if policy == "MFA enabled during admission" {
						change = `use2fa=true`
					}
					if _, err = f.model.DB.Exec(`CREATE FUNCTION change_owned_account() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE users SET ` + change + ` WHERE uid=NEW.user_sessions; RETURN NEW; END $$; CREATE TRIGGER change_owned_account AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION change_owned_account()`); err != nil {
						t.Fatal(err)
					}
				}
				sm := scs.New()
				sm.Store = f.store
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
				form := url.Values{"username": {user.ID}, "password": {password}}
				req := httptest.NewRequest("POST", "https://console.test/fixture/login", strings.NewReader(form.Encode())).WithContext(ctx)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				c := echo.New().NewContext(req, httptest.NewRecorder())
				_ = h.LoginPasswordAuth(c)
				if sm.GetString(ctx, "uid") != "" {
					t.Error("password sign-in ignored current account/method policy")
				}
				current, err := f.model.Client.User.Get(t.Context(), user.ID)
				if err != nil {
					t.Fatal(err)
				}
				if (policy == "revoked" || policy == "review") && current.Register != register {
					t.Error("password sign-in reactivated a denied account")
				}
				if policy == "revoked during admission" && current.Register != nats.REGISTER_REVOKED {
					t.Error("confirmation undid concurrent revocation")
				}
			})
		}
	}
}

func TestLocalConfirmationCancelsAndPreservesRegistration(t *testing.T) {
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
	user, err := f.model.Client.User.Create().SetID("new-password-user").SetName("Owned first login").SetHash("owned-verified-hash").SetPasswd(true).SetRegister(nats.REGISTER_APPROVED).SetCertClearPassword("owned-temporary-secret").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.model.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT uid FROM users WHERE uid=$1 FOR UPDATE`, user.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if err = f.model.AdmitLocalSignIn(ctx, user, loginproof.Password, models.LocalSignInComplete); err == nil {
		t.Fatal("confirmation ignored a canceled row-lock wait")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	current, err := f.model.Client.User.Get(t.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Register != nats.REGISTER_APPROVED || current.CertClearPassword != user.CertClearPassword {
		t.Fatal("canceled confirmation partially changed the account")
	}
	if err = f.model.AdmitLocalSignIn(t.Context(), user, loginproof.Password, models.LocalSignInComplete); err != nil {
		t.Fatal("valid first login did not confirm", err)
	}
	current, err = f.model.Client.User.Get(t.Context(), user.ID)
	if err != nil || current.Register != nats.REGISTER_COMPLETE || current.CertClearPassword != "" {
		t.Fatal("confirmation did not clear the temporary certificate password", err)
	}
	if err = current.Update().SetRegister(nats.REGISTER_FORCE_PASSWORD_CHANGE).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = f.model.AdmitLocalSignIn(t.Context(), current, loginproof.Password, models.LocalSignInComplete); err == nil {
		t.Fatal("forced password replacement became a completed login")
	}
	if err = f.model.AdmitLocalSignIn(t.Context(), current, loginproof.Password, models.LocalSignInPasswordReplacement); err != nil {
		t.Fatal("valid initial-password proof was rejected", err)
	}
	current, err = f.model.Client.User.Get(t.Context(), user.ID)
	if err != nil || current.Register != nats.REGISTER_FORCE_PASSWORD_CHANGE {
		t.Fatal("replacement admission prematurely completed registration", err)
	}
}

func TestCertificateSignInHonorsLocalAccountAndMethodPolicy(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, policy := range []string{"revoked", "review", "password account", "OpenID account", "disabled certificates", "revoked during admission", "MFA enabled during admission"} {
			t.Run(sessionMode(encrypted)+"/"+policy, func(t *testing.T) {
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
				if err = settings.Update().SetUseCertificates(policy != "disabled certificates").Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				register := nats.REGISTER_COMPLETE
				if policy == "revoked" {
					register = nats.REGISTER_REVOKED
				}
				if policy == "review" {
					register = nats.REGISTER_IN_REVIEW
				}
				if _, err = f.model.Client.User.Create().SetID("certificate-user").SetName("Owned certificate policy").SetPasswd(policy == "password account").SetOpenid(policy == "OpenID account").SetRegister(register).Save(t.Context()); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(policy, "during admission") {
					change := `register='users.certificate_revoked'`
					if policy == "MFA enabled during admission" {
						change = `use2fa=true`
					}
					if _, err = f.model.DB.Exec(`CREATE FUNCTION change_owned_account() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE users SET ` + change + ` WHERE uid=NEW.user_sessions; RETURN NEW; END $$; CREATE TRIGGER change_owned_account AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION change_owned_account()`); err != nil {
						t.Fatal(err)
					}
				}
				sm := scs.New()
				sm.Store = f.store
				ctx, err := sm.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				ca, credential := ownedConsoleCertificate(t, "certificate-user")
				h := &certificate.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, CACert: ca, PublicOrigin: "https://console.test"}
				req := httptest.NewRequest("GET", "https://console.test/fixture/certificate", nil).WithContext(ctx)
				req.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{credential.Leaf}}
				c := echo.New().NewContext(req, httptest.NewRecorder())
				if err = h.Auth(c); err == nil {
					t.Error("certificate sign-in ignored current account/method policy")
				}
				if sm.GetString(ctx, "uid") != "" {
					t.Error("denied certificate admission retained identity")
				}
				current, err := f.model.Client.User.Get(t.Context(), "certificate-user")
				if err != nil {
					t.Fatal(err)
				}
				if (policy == "revoked" || policy == "review") && current.Register != register {
					t.Error("certificate sign-in reactivated a denied account")
				}
				if policy == "revoked during admission" && current.Register != nats.REGISTER_REVOKED {
					t.Error("certificate confirmation undid concurrent revocation")
				}
			})
		}
	}
}

func TestPendingMFAIsNotPromotedByDisablingMFA(t *testing.T) {
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
	user, err := f.model.Client.User.Create().SetID("pending-user").SetName("Owned pending user").SetPasswd(true).SetHash("owned-verified-hash").SetUse2fa(true).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	sm.Store = f.store
	ctx, err := sm.Load(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key}
	c := echo.New().NewContext(httptest.NewRequest("POST", "https://console.test/fixture/login", nil).WithContext(ctx), httptest.NewRecorder())
	if err = h.NewSession(c, user); err != nil {
		t.Fatal(err)
	}
	if err = user.Update().SetUse2fa(false).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	c = echo.New().NewContext(httptest.NewRequest("GET", "https://console.test/myaccount", nil).WithContext(ctx), httptest.NewRecorder())
	c.SetPath("/myaccount")
	called := false
	_ = h.IsAuthenticated(func(echo.Context) error { called = true; return nil })(c)
	if called || sm.Exists(ctx, "uid") {
		t.Fatal("a pending first factor became a full session after MFA was disabled")
	}
}
