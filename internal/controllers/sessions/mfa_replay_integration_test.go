package sessions_test

import (
	"context"
	"fmt"
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
	"github.com/pquerna/otp/totp"
)

func TestMFAPrimaryAndTOTPReplayHaveOneWinner(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, replay := range []string{"one primary with distinct backup codes", "one TOTP with distinct primary flows"} {
			t.Run(sessionMode(encrypted)+"/"+replay, func(t *testing.T) {
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
				const secret = "JBSWY3DPEHPK3PXP"
				u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned MFA user").SetPasswd(true).SetHash("owned verified primary credential").SetUse2fa(true).SetTotpSecretConfirmed(true).SetTotpSecret(secret).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				sm := scs.New()
				sm.Store = f.store
				h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
				newRequest := func(ctx context.Context, code string) (echo.Context, *httptest.ResponseRecorder) {
					req := httptest.NewRequest(http.MethodPost, "https://console.test/login/mfa", strings.NewReader(url.Values{"confirm-code": {code}, "recovery-code": {code}}.Encode())).WithContext(ctx)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					recorder := httptest.NewRecorder()
					return echo.New().NewContext(req, recorder), recorder
				}
				const contenders = 4
				contexts := make([]context.Context, contenders)
				codes := make([]string, contenders)
				token := ""
				sharedTOTP, err := totp.GenerateCode(secret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				for i := range contenders {
					if i == 0 || replay == "one TOTP with distinct primary flows" {
						ctx, err := sm.Load(t.Context(), "")
						if err != nil {
							t.Fatal(err)
						}
						c, _ := newRequest(ctx, "")
						if err = h.NewSession(c, u); err != nil {
							t.Fatal(err)
						}
						token = sm.Token(ctx)
					}
					contexts[i], err = sm.Load(t.Context(), token)
					if err != nil {
						t.Fatal(err)
					}
					if replay == "one primary with distinct backup codes" {
						codes[i] = fmt.Sprintf("OWNED-BACKUP-%02d", i)
						hash, err := argon2id.CreateHash(codes[i], argon2id.DefaultParams)
						if err != nil {
							t.Fatal(err)
						}
						if err = f.model.Client.RecoveryCode.Create().SetUserID(u.ID).SetCode(hash).Exec(t.Context()); err != nil {
							t.Fatal(err)
						}
					} else {
						codes[i] = sharedTOTP
					}
				}
				// All handlers finish verification and reach owner association before
				// any is allowed to enter its final admission transaction.
				if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION hold_mfa_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock_shared(712036482); RETURN NEW; END $$; CREATE TRIGGER hold_mfa_completion AFTER UPDATE OF user_sessions ON sessions FOR EACH ROW EXECUTE FUNCTION hold_mfa_completion()`); err != nil {
					t.Fatal(err)
				}
				tx, err := f.model.DB.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tx.Rollback() })
				if _, err = tx.ExecContext(t.Context(), `SELECT pg_advisory_xact_lock(712036482)`); err != nil {
					t.Fatal(err)
				}
				type result struct {
					admitted bool
					err      error
				}
				done := make(chan result, contenders)
				for i := range contenders {
					go func() {
						c, _ := newRequest(contexts[i], codes[i])
						var err error
						if replay == "one primary with distinct backup codes" {
							err = h.LoginTOTPBackupCheck(c)
						} else {
							err = h.LoginTOTPValidate(c)
						}
						done <- result{sm.GetBool(contexts[i], "twofa"), err}
					}()
				}
				deadline := time.Now().Add(4 * time.Second)
				for {
					var waiting int
					if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE "sessions" SET%'`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting == contenders {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("MFA contenders did not reach the admission barrier", waiting)
					}
					time.Sleep(time.Millisecond)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				winners := 0
				for range contenders {
					r := <-done
					if r.admitted {
						winners++
						if r.err != nil {
							t.Fatal("admitted response failed", r.err)
						}
					}
				}
				if winners != 1 {
					t.Fatal("replayed MFA evidence admitted multiple sessions", winners)
				}
			})
		}
	}
}
