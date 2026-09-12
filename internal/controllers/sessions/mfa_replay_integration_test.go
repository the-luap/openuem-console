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
	"sync"
	"sync/atomic"
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
				// Pause only after the first session write commits, before owner
				// association. A SQL trigger inside association retains a user
				// foreign-key lock and can block a later primary check itself.
				barrier := &mfaAdmissionBarrierStore{PostgresStore: f.store, reached: make(chan struct{}, contenders), release: make(chan struct{})}
				barrier.remaining.Store(contenders)
				sm.Store = barrier
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(barrier.release) }) }
				var handlers sync.WaitGroup
				t.Cleanup(func() { release(); handlers.Wait() })
				type result struct {
					admitted bool
					err      error
				}
				done := make(chan result, contenders)
				deadline, cancel := context.WithTimeout(t.Context(), 4*time.Second)
				defer cancel()
				awaitArrival := func() {
					t.Helper()
					select {
					case <-barrier.reached:
					case early := <-done:
						t.Fatal("MFA handler finished before admission barrier", early.err)
					case <-deadline.Done():
						t.Fatal("MFA handler did not reach admission barrier", deadline.Err())
					}
				}
				for i := range contenders {
					if i == contenders-1 {
						// Deliberately delay the last primary check until all
						// earlier handlers have reached the admission barrier.
						for range contenders - 1 {
							awaitArrival()
						}
					}
					handlers.Add(1)
					go func() {
						defer handlers.Done()
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
				awaitArrival()
				release()
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

// The adapter retains the actual PostgreSQL persistence and context methods.
// Its barrier holds no database transaction, row lock or authentication receipt.
type mfaAdmissionBarrierStore struct {
	*sessions.PostgresStore
	remaining atomic.Int32
	reached   chan struct{}
	release   chan struct{}
}

func (s *mfaAdmissionBarrierStore) CommitCtx(ctx context.Context, token string, data []byte, expiry time.Time) error {
	if err := s.PostgresStore.CommitCtx(ctx, token, data, expiry); err != nil {
		return err
	}
	if s.remaining.Add(-1) >= 0 {
		s.reached <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
