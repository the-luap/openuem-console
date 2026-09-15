package sessions_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
)

// A completed deletion must win over a request which loaded its session earlier.
// Exercise the real SCS codec and manager, including independent server instances.
func TestSessionDeletionRejectsPreviouslyLoadedWrites(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, deletion := range []string{"logout", "administrator", "password reset", "truncate"} {
			t.Run(sessionMode(encrypted)+"/"+deletion, func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
				manager := scs.New()
				manager.Store = f.store
				ctx, err := manager.Load(t.Context(), "")
				if err != nil {
					t.Fatal(err)
				}
				manager.Put(ctx, "uid", "owned-user")
				token, _, err := manager.Commit(ctx)
				if err != nil {
					t.Fatal(err)
				}
				late, err := manager.Load(t.Context(), token)
				if err != nil {
					t.Fatal(err)
				}
				if manager.GetString(late, "uid") != "owned-user" {
					t.Fatal("fixture did not load the old account")
				}
				switch deletion {
				case "logout":
					if err = manager.Destroy(ctx); err != nil {
						t.Fatal(err)
					}
				case "administrator":
					var record string
					if err = f.model.DB.QueryRow(`SELECT token FROM sessions`).Scan(&record); err != nil {
						t.Fatal(err)
					}
					if err = f.model.DeleteSession(record); err != nil {
						t.Fatal(err)
					}
				case "password reset":
					if _, err = f.model.Client.Sessions.Delete().Exec(t.Context()); err != nil {
						t.Fatal(err)
					}
				case "truncate":
					if _, err = f.model.DB.Exec(`TRUNCATE sessions`); err != nil {
						t.Fatal(err)
					}
				}
				manager.Put(late, "preference", "saved after deletion")
				if _, _, err = manager.Commit(late); err == nil {
					t.Error("late request re-created a deleted session")
				}
				loaded, err := manager.Load(t.Context(), token)
				if err != nil {
					t.Fatal(err)
				}
				if manager.GetString(loaded, "uid") != "" {
					t.Error("deleted browser token authenticated again")
				}
				// A new server instance must honor the same durable deletion, while
				// a fresh login receives a different, usable token.
				restarted := sessions.NewWithConfig(f.pool, sessions.Config{EncryptionMasterKey: f.key})
				if err = restarted.Migrate(t.Context()); err != nil {
					t.Fatal(err)
				}
				manager.Store = restarted
				if _, _, err = manager.Commit(late); !errors.Is(err, sessions.ErrRevoked) {
					t.Fatal("restart forgot revocation", err)
				}
				manager.Put(loaded, "uid", "new-login")
				fresh, _, err := manager.Commit(loaded)
				if err != nil || fresh == token {
					t.Fatal("fresh sign-in could not create a new token", err)
				}
				if _, found, err := restarted.FindCtx(t.Context(), fresh); err != nil || !found {
					t.Fatal("fresh token unavailable", err)
				}
			})
		}
	}
}

func TestSessionCommitWaitsForDeletionOutcome(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, rollback := range []bool{false, true} {
			t.Run(sessionMode(encrypted)+"/rollback="+map[bool]string{false: "no", true: "yes"}[rollback], func(t *testing.T) {
				f := newSessionFixture(t, encrypted)
				token := strings.Repeat("r", 43)
				if err := f.store.CommitCtx(t.Context(), token, []byte("initial"), time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				tx, err := f.model.DB.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = tx.ExecContext(t.Context(), `DELETE FROM sessions WHERE token_lookup=$1`, sessiontokens.Lookup(token)); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- f.store.CommitCtx(ctx, token, []byte("late"), time.Now().Add(time.Hour)) }()
				waitForSessionRowLock(t, f)
				// A different token must make progress despite this token's lock.
				independent, stop := context.WithTimeout(t.Context(), time.Second)
				if err = f.store.CommitCtx(independent, "independent", []byte("separate"), time.Now().Add(time.Hour)); err != nil {
					t.Error("unrelated session write was serialized behind deletion", err)
				}
				stop()
				if rollback {
					err = tx.Rollback()
				} else {
					err = tx.Commit()
				}
				if err != nil {
					t.Fatal(err)
				}
				err = <-done
				if rollback && err != nil {
					t.Fatal("rolled-back deletion revoked the session", err)
				}
				if !rollback && !errors.Is(err, sessions.ErrRevoked) {
					t.Fatal("writer missed deletion after its row-lock wait", err)
				}
				data, found, err := f.store.FindCtx(t.Context(), token)
				if err != nil || found != rollback || (rollback && string(data) != "late") {
					t.Fatal("unexpected final session", found, err)
				}
			})
		}
	}
}

func waitForSessionRowLock(t *testing.T, f sessionFixture) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		err := f.model.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%FOR UPDATE%')`, f.pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("session writer never waited for the owned deletion transaction")
}

func TestSessionRevocationReceiptFailureRollsBackDeletion(t *testing.T) {
	f := newSessionFixture(t, true)
	token := strings.Repeat("q", 43)
	if err := f.store.CommitCtx(t.Context(), token, []byte("owned"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.model.DB.Exec(`CREATE FUNCTION reject_owned_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned receipt failure'; END $$; CREATE TRIGGER reject_owned_revocation BEFORE INSERT ON sessions_revocations FOR EACH ROW EXECUTE FUNCTION reject_owned_revocation()`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeleteCtx(t.Context(), token); err == nil {
		t.Fatal("logout reported success without a durable receipt")
	}
	if _, err := f.model.Client.Sessions.Delete().Exec(t.Context()); err == nil {
		t.Fatal("model deletion reported success without a durable receipt")
	}
	if _, found, err := f.store.FindCtx(t.Context(), token); err != nil || !found {
		t.Fatal("failed deletion partially committed", found, err)
	}
}

func TestSessionDeletionFencesFirstCommit(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f := newSessionFixture(t, encrypted)
			for range 2 {
				if err := f.store.DeleteCtx(t.Context(), "generated-before-first-commit"); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.store.CommitCtx(t.Context(), "generated-before-first-commit", []byte("late"), time.Now().AddDate(1, 0, 0)); !errors.Is(err, sessions.ErrRevoked) {
				t.Fatal("first commit ignored an earlier deletion", err)
			}
			var count int
			if err := f.model.DB.QueryRow(`SELECT count(*) FROM sessions_revocations`).Scan(&count); err != nil || count != 1 {
				t.Fatal("idempotent deletion accumulated receipts", count, err)
			}
		})
	}
}

func TestSessionExpiryCleanupRejectsLateIdleTimeoutWrite(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f := newSessionFixture(t, encrypted)
			manager := scs.New()
			manager.Store = f.store
			manager.IdleTimeout = time.Minute
			ctx, err := manager.Load(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			manager.Put(ctx, "uid", "owned-user")
			token, _, err := manager.Commit(ctx)
			if err != nil {
				t.Fatal(err)
			}
			late, err := manager.Load(t.Context(), token)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate expiry after loading without depending on a wall-clock race.
			if _, err = f.model.DB.Exec(`UPDATE sessions SET expiry=current_timestamp-interval '1 second'`); err != nil {
				t.Fatal(err)
			}
			cleaner := sessions.NewWithConfig(f.pool, sessions.Config{CleanUpInterval: time.Millisecond, EncryptionMasterKey: f.key})
			defer cleaner.StopCleanup()
			if err = cleaner.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				var count int
				if err = f.model.DB.QueryRow(`SELECT count(*) FROM sessions`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("expiry cleanup did not run")
				}
				time.Sleep(time.Millisecond)
			}
			if _, _, err = manager.Commit(late); !errors.Is(err, sessions.ErrRevoked) {
				t.Fatal("idle timeout refresh recreated an expired session", err)
			}
			// Empty anonymous destruction does not accumulate meaningless receipts.
			for range 5 {
				if err = cleaner.DeleteCtx(t.Context(), ""); err != nil {
					t.Fatal(err)
				}
			}
			var receipts int
			if err = f.model.DB.QueryRow(`SELECT count(*) FROM sessions_revocations`).Scan(&receipts); err != nil || receipts != 1 {
				t.Fatal("unexpected deletion receipts", receipts, err)
			}
		})
	}
}

func sessionMode(encrypted bool) string {
	if encrypted {
		return "encrypted"
	}
	return "plaintext"
}
