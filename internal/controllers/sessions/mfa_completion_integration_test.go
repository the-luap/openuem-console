package sessions_test

import (
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
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	console "github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/utils"
	"github.com/pquerna/otp/totp"
)

func TestMFACompletionRejectsSecretReplacementDuringAdmission(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, method := range []string{loginproof.Password, loginproof.Certificate} {
			for _, second := range []string{"TOTP", "backup"} {
				t.Run(sessionMode(encrypted)+"/"+method+"/"+second, func(t *testing.T) {
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
					if err = settings.Update().SetUsePasswd(true).SetUseCertificates(true).Exec(t.Context()); err != nil {
						t.Fatal(err)
					}
					const secret = "JBSWY3DPEHPK3PXP"
					stored, replacement := secret, "KRSXG5DSNFXGOIDT"
					if encrypted {
						stored, err = utils.EncryptSensitiveField(stored, f.key)
						if err != nil {
							t.Fatal(err)
						}
						replacement, err = utils.EncryptSensitiveField(replacement, f.key)
						if err != nil {
							t.Fatal(err)
						}
					}
					u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(method == loginproof.Password).SetHash("owned verified primary credential").SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret(stored).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					const backup = "OWNED-MFA-BACKUP"
					if second == "backup" {
						hash, err := argon2id.CreateHash(backup, argon2id.DefaultParams)
						if err != nil {
							t.Fatal(err)
						}
						if err = f.model.Client.RecoveryCode.Create().SetUserID(u.ID).SetCode(hash).Exec(t.Context()); err != nil {
							t.Fatal(err)
						}
					}
					sm := scs.New()
					sm.Store = f.store
					ctx, err := sm.Load(t.Context(), "")
					if err != nil {
						t.Fatal(err)
					}
					sm.Put(ctx, "uid", u.ID)
					sm.Put(ctx, "authentication-pending", true)
					primaryCredential := u.Hash
					if method == loginproof.Certificate {
						_, credential := ownedConsoleCertificate(t, u.ID)
						registerOwnedConsoleCertificate(t, f, credential.Leaf)
						primaryCredential = string(credential.Leaf.Raw)
						sm.Put(ctx, clientidentity.SessionCertificateKey, clientidentity.EncodeSessionCertificate(credential.Leaf))
					}
					sm.Put(ctx, loginproof.SessionKey, loginproof.New(u.ID, method, primaryCredential, time.Now()))
					token, _, err := sm.Commit(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err = f.model.AddUserToSession(t.Context(), token, u.ID, f.key); err != nil {
						t.Fatal(err)
					}
					ctx, err = sm.Load(t.Context(), token)
					if err != nil {
						t.Fatal(err)
					}
					// Ownership is written after second-factor verification but before
					// the final policy check and authenticated cookie publication.
					if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION replace_owned_mfa() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE users SET totp_secret='`+replacement+`' WHERE uid=NEW.user_sessions; RETURN NEW; END $$; CREATE TRIGGER replace_owned_mfa AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION replace_owned_mfa()`); err != nil {
						t.Fatal(err)
					}
					code, err := totp.GenerateCode(secret, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest(http.MethodPost, "https://console.test/login/mfa", strings.NewReader(url.Values{"confirm-code": {code}, "recovery-code": {backup}}.Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					recorder := httptest.NewRecorder()
					c := echo.New().NewContext(req, recorder)
					h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
					if second == "backup" {
						err = h.LoginTOTPBackupCheck(c)
					} else {
						err = h.LoginTOTPValidate(c)
					}
					if err == nil || sm.GetBool(ctx, "twofa") || sm.GetString(ctx, "uid") != "" || len(recorder.Result().Cookies()) != 0 {
						t.Error("a superseded second factor completed authentication", err)
					}
					current, err := f.model.Client.User.Get(t.Context(), u.ID)
					if err != nil {
						t.Fatal(err)
					}
					if current.TotpSecret != replacement {
						t.Fatal("admission undid the newer MFA enrollment")
					}
				})
			}
		}
	}
}
