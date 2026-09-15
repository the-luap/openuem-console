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
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	console "github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
)

func TestRecoveryCodeConcurrentConsumptionHasOneWinner(t *testing.T) {
	f := newSessionFixture(t, false)
	u, err := f.model.Client.User.Create().SetID("recovery-user").SetName("Owned recovery user").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	const code = "ABCDEFGHJKLMNPQR"
	hash, err := argon2id.CreateHash(code, argon2id.DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.model.Client.RecoveryCode.Create().SetUserID(u.ID).SetCode(hash).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.model.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err = tx.ExecContext(t.Context(), `SELECT id FROM recovery_codes WHERE id=$1 FOR UPDATE`, record.ID); err != nil {
		t.Fatal(err)
	}
	const contenders = 4
	type result struct {
		accepted bool
		err      error
	}
	done := make(chan result, contenders)
	for range contenders {
		go func() {
			accepted, err := f.model.ConsumeRecoveryCode(t.Context(), u.ID, code)
			done <- result{accepted, err}
		}()
	}
	// All requests must validate the same unused snapshot before release.
	deadline := time.Now().Add(4 * time.Second)
	for {
		var waiting int
		if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE "recovery_codes" SET%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == contenders {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("contenders did not all reach the locked recovery code", waiting)
		}
		time.Sleep(time.Millisecond)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	winners := 0
	for range contenders {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.accepted {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("one recovery code admitted %d concurrent requests", winners)
	}
	if accepted, err := f.model.ConsumeRecoveryCode(t.Context(), u.ID, code); err != nil || accepted {
		t.Fatal("consumed recovery code was accepted again", err)
	}
}

func TestRecoveryCodeRechecksChangedRecordAfterLock(t *testing.T) {
	for _, change := range []string{"hash", "owner", "deleted", "rolled back"} {
		t.Run(change, func(t *testing.T) {
			f := newSessionFixture(t, false)
			for _, uid := range []string{"owner", "other"} {
				if err := f.model.Client.User.Create().SetID(uid).SetName("Owned recovery user").Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			const code = "ABCDEFGHJKLMNPQR"
			hash, err := argon2id.CreateHash(code, argon2id.DefaultParams)
			if err != nil {
				t.Fatal(err)
			}
			record, err := f.model.Client.RecoveryCode.Create().SetUserID("owner").SetCode(hash).Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err = f.model.Client.RecoveryCode.Create().SetUserID("other").SetCode(hash).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tx.Rollback() })
			switch change {
			case "hash", "rolled back":
				_, err = tx.ExecContext(t.Context(), `UPDATE recovery_codes SET code='owned replacement hash' WHERE id=$1`, record.ID)
			case "owner":
				_, err = tx.ExecContext(t.Context(), `UPDATE recovery_codes SET user_recoverycodes='other' WHERE id=$1`, record.ID)
			case "deleted":
				_, err = tx.ExecContext(t.Context(), `DELETE FROM recovery_codes WHERE id=$1`, record.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				accepted bool
				err      error
			}
			done := make(chan result, 1)
			go func() {
				accepted, err := f.model.ConsumeRecoveryCode(t.Context(), "owner", code)
				done <- result{accepted, err}
			}()
			deadline := time.Now().Add(4 * time.Second)
			for {
				var waiting bool
				if err = f.model.DB.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE "recovery_codes" SET%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("consumer did not reach the locked record")
				}
				time.Sleep(time.Millisecond)
			}
			// A different account's code can progress while this row is blocked.
			otherCtx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if accepted, err := f.model.ConsumeRecoveryCode(otherCtx, "other", code); err != nil || !accepted {
				t.Fatal("unrelated recovery code was blocked", err)
			}
			if change == "rolled back" {
				err = tx.Rollback()
			} else {
				err = tx.Commit()
			}
			if err != nil {
				t.Fatal(err)
			}
			r := <-done
			if r.err != nil || r.accepted != (change == "rolled back") {
				t.Fatal("consumer used stale recovery-code state", r.accepted, r.err)
			}
		})
	}
}

func TestRecoveryCodeCancellationAndFailurePreserveUnusedState(t *testing.T) {
	f := newSessionFixture(t, false)
	if err := f.model.Client.User.Create().SetID("owner").SetName("Owned recovery user").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	const code = "ABCDEFGHJKLMNPQR"
	hash, err := argon2id.CreateHash(code, argon2id.DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.model.Client.RecoveryCode.Create().SetUserID("owner").SetCode(hash).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []string{"", "WRONG-OWNED-CODE", string(make([]byte, 257))} {
		if accepted, err := f.model.ConsumeRecoveryCode(t.Context(), "owner", wrong); err != nil || accepted {
			t.Fatal("invalid input accepted", err)
		}
	}
	if accepted, err := f.model.ConsumeRecoveryCode(t.Context(), "missing", code); err != nil || accepted {
		t.Fatal("another account consumed the code", err)
	}
	tx, err := f.model.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err = tx.ExecContext(t.Context(), `SELECT id FROM recovery_codes WHERE id=$1 FOR UPDATE`, record.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if accepted, err := f.model.ConsumeRecoveryCode(ctx, "owner", code); accepted || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked consumption ignored cancellation", accepted, err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION reject_recovery_consumption() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned recovery write failure'; END $$; CREATE TRIGGER reject_recovery BEFORE UPDATE ON recovery_codes FOR EACH ROW EXECUTE FUNCTION reject_recovery_consumption()`); err != nil {
		t.Fatal(err)
	}
	if accepted, err := f.model.ConsumeRecoveryCode(t.Context(), "owner", code); accepted || err == nil {
		t.Fatal("failed write admitted a recovery code", accepted, err)
	}
	current, err := f.model.Client.RecoveryCode.Get(t.Context(), record.ID)
	if err != nil || current.Used {
		t.Fatal("failed or canceled write consumed the code", err)
	}
	if _, err = f.model.DB.ExecContext(t.Context(), `DROP TRIGGER reject_recovery ON recovery_codes`); err != nil {
		t.Fatal(err)
	}
	if accepted, err := f.model.ConsumeRecoveryCode(t.Context(), "owner", code); !accepted || err != nil {
		t.Fatal("valid retry failed", err)
	}
}

func TestRecoveryCodeHandlerConcurrentAdmissionAndWriteFailure(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
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
			u, err := f.model.Client.User.Create().SetID("owner").SetName("Owned recovery user").SetPasswd(true).SetHash("owned verified password hash").SetUse2fa(true).SetTotpSecretConfirmed(true).SetRegister(nats.REGISTER_COMPLETE).Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			const code = "ABCDEFGHJKLMNPQR"
			hash, err := argon2id.CreateHash(code, argon2id.DefaultParams)
			if err != nil {
				t.Fatal(err)
			}
			record, err := f.model.Client.RecoveryCode.Create().SetUserID(u.ID).SetCode(hash).Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			sm := scs.New()
			sm.Store = f.store
			h := &console.Handler{Model: f.model, SessionManager: &sessions.SessionManager{Manager: sm, Pool: f.pool}, EncryptionMasterKey: f.key, PublicOrigin: "https://console.test", AuthLogger: log.New(io.Discard, "", 0)}
			initial, err := sm.Load(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			newRequest := func(ctx context.Context) (echo.Context, *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodPost, "https://console.test/login/totp/backup", strings.NewReader(url.Values{"recovery-code": {code}}.Encode())).WithContext(ctx)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				recorder := httptest.NewRecorder()
				return echo.New().NewContext(req, recorder), recorder
			}
			c, _ := newRequest(initial)
			if err = h.NewSession(c, u); err != nil {
				t.Fatal(err)
			}
			token := sm.Token(initial)
			// A storage fault must return a generic retryable error without a
			// completed session, cookie or consumed code.
			if _, err = f.model.DB.ExecContext(t.Context(), `CREATE FUNCTION reject_recovery_consumption() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned recovery write failure'; END $$; CREATE TRIGGER reject_recovery BEFORE UPDATE ON recovery_codes FOR EACH ROW EXECUTE FUNCTION reject_recovery_consumption()`); err != nil {
				t.Fatal(err)
			}
			ctx, err := sm.Load(t.Context(), token)
			if err != nil {
				t.Fatal(err)
			}
			c, recorder := newRequest(ctx)
			err = h.LoginTOTPBackupCheck(c)
			var response *echo.HTTPError
			if !errors.As(err, &response) || response.Code != http.StatusServiceUnavailable || strings.Contains(err.Error(), code) || strings.Contains(err.Error(), "owned recovery write failure") {
				t.Fatal("storage failure did not return a generic retryable error", err)
			}
			if sm.GetBool(ctx, "twofa") || len(recorder.Result().Cookies()) != 0 {
				t.Fatal("failed write completed authentication")
			}
			if _, err = f.model.DB.ExecContext(t.Context(), `DROP TRIGGER reject_recovery ON recovery_codes`); err != nil {
				t.Fatal(err)
			}
			tx, err := f.model.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tx.Rollback() })
			if _, err = tx.ExecContext(t.Context(), `SELECT id FROM recovery_codes WHERE id=$1 FOR UPDATE`, record.ID); err != nil {
				t.Fatal(err)
			}
			type result struct {
				admitted bool
				cookies  int
				err      error
			}
			done := make(chan result, 4)
			for range 4 {
				ctx, err := sm.Load(t.Context(), token)
				if err != nil {
					t.Fatal(err)
				}
				go func() {
					c, recorder := newRequest(ctx)
					err := h.LoginTOTPBackupCheck(c)
					done <- result{sm.GetBool(ctx, "twofa"), len(recorder.Result().Cookies()), err}
				}()
			}
			deadline := time.Now().Add(4 * time.Second)
			for {
				var waiting int
				if err = f.model.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE "recovery_codes" SET%'`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting == 4 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("handler contenders did not reach the held code", waiting)
				}
				time.Sleep(time.Millisecond)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			winners := 0
			for range 4 {
				r := <-done
				if r.admitted {
					winners++
					if r.err != nil || r.cookies != 1 {
						t.Fatal("winner did not complete admission", r.err, r.cookies)
					}
				} else if r.cookies != 0 {
					t.Fatal("loser received an authenticated cookie")
				}
			}
			if winners != 1 {
				t.Fatal("backup handler admitted multiple consumers", winners)
			}
		})
	}
}
