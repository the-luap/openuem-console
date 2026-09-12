package models

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
	"github.com/stretchr/testify/require"
)

func TestEmailConfirmationPostgresTransitionAndDeadline(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for account confirmation integration")
	}
	admin, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer admin.Close()
	schema := "confirmation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	require.NoError(t, err)
	defer admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	t.Setenv("ENV", "test")
	m, err := New(u.String(), "pgx", "example.test")
	require.NoError(t, err)
	defer m.Close()
	migrate := func() error {
		tx, err := m.DB.BeginTx(t.Context(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(t.Context(), sessiongeneration.Schema); err != nil {
			return err
		}
		return tx.Commit()
	}
	require.NoError(t, migrate())
	for _, outcome := range []string{"commit", "rollback", "deadline", "address", "resend"} {
		t.Run(outcome, func(t *testing.T) {
			uid := "confirmation-" + outcome
			require.NoError(t, m.Client.User.Create().SetID(uid).SetName(uid).SetEmail(uid+"@example.test").Exec(t.Context()))
			account, err := m.PendingEmailConfirmation(t.Context(), uid)
			require.NoError(t, err)
			require.NoError(t, m.StageEmailConfirmation(t.Context(), account, "owned-confirmation-token"))
			account, err = m.PendingEmailConfirmation(t.Context(), uid)
			require.NoError(t, err)
			tx, err := m.DB.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer tx.Rollback()
			var holder int
			require.NoError(t, tx.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&holder))
			if outcome == "address" {
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET email=$1 WHERE uid=$2`, "changed@example.test", uid)
			} else if outcome == "resend" {
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET new_user_token=$1 WHERE uid=$2`, "replacement-confirmation", uid)
			} else {
				_, err = tx.ExecContext(t.Context(), `UPDATE users SET register=$1 WHERE uid=$2`, openuem.REGISTER_REVOKED, uid)
			}
			require.NoError(t, err)
			wait := 10 * time.Second
			if outcome == "deadline" {
				wait = 3 * time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), wait)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- m.ConfirmEmail(ctx, account) }()
			// Observe the real row-lock wait before releasing or timing out the
			// request. The result must use the state committed by the blocker.
			var blocked int
			for blocked == 0 && ctx.Err() == nil {
				require.NoError(t, m.DB.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, holder).Scan(&blocked))
				if blocked == 0 {
					time.Sleep(5 * time.Millisecond)
				}
			}
			require.Positive(t, blocked, "confirmation did not reach the owned account lock")
			switch outcome {
			case "commit", "address", "resend":
				require.NoError(t, tx.Commit())
			case "rollback":
				require.NoError(t, tx.Rollback())
			}
			select {
			case err = <-result:
			case <-time.After(12 * time.Second):
				t.Fatal("confirmation did not release its database operation")
			}
			switch outcome {
			case "commit", "address", "resend":
				require.ErrorIs(t, err, ErrEmailConfirmationState)
			case "rollback":
				require.NoError(t, err)
			case "deadline":
				require.Error(t, err)
				require.True(t, errors.Is(ctx.Err(), context.DeadlineExceeded))
				require.NoError(t, tx.Rollback())
			}
			after, err := m.Client.User.Get(t.Context(), uid)
			require.NoError(t, err)
			require.Equal(t, outcome == "rollback", after.EmailVerified)
			if outcome == "commit" {
				require.Equal(t, openuem.REGISTER_REVOKED, after.Register)
			} else if outcome == "address" {
				require.Equal(t, "changed@example.test", after.Email)
				require.Equal(t, "users.pending_email_confirmation", after.Register)
				require.ErrorIs(t, m.ConfirmEmail(t.Context(), account), ErrEmailConfirmationState)
			} else if outcome == "resend" {
				require.Equal(t, "replacement-confirmation", after.NewUserToken)
				require.Equal(t, "users.pending_email_confirmation", after.Register)
				require.ErrorIs(t, m.StageEmailConfirmation(t.Context(), account, "stale-issuer-token"), ErrEmailConfirmationState)
			} else if outcome == "rollback" {
				require.Equal(t, openuem.REGISTER_SEND_CERTIFICATE, after.Register)
				require.ErrorIs(t, m.ConfirmEmail(t.Context(), account), ErrEmailConfirmationState)
			} else {
				require.Equal(t, "users.pending_email_confirmation", after.Register)
				require.NoError(t, m.ConfirmEmail(t.Context(), account), "cancelled statement must leave confirmation retryable")
			}
		})
	}
	for name, update := range map[string]string{
		"uid":           `uid=uid||'-renamed'`,
		"email":         `email='changed@example.test'`,
		"status":        `register='users.certificate_revoked'`,
		"verified":      `email_verified=true`,
		"password-mode": `passwd=true`,
		"openid-mode":   `openid=true`,
		"password":      `hash='changed-password'`,
		"created":       `created=created+interval '1 second'`,
	} {
		t.Run("restored-"+name, func(t *testing.T) {
			uid := "restored-" + name
			require.NoError(t, m.Client.User.Create().SetID(uid).SetName(uid).SetEmail("original@example.test").Exec(t.Context()))
			account, err := m.PendingEmailConfirmation(t.Context(), uid)
			require.NoError(t, err)
			require.NoError(t, m.StageEmailConfirmation(t.Context(), account, "owned-original-invitation"))
			account, err = m.PendingEmailConfirmation(t.Context(), uid)
			require.NoError(t, err)
			_, err = m.DB.ExecContext(t.Context(), `UPDATE users SET `+update+` WHERE uid=$1`, uid)
			require.NoError(t, err)
			currentID := uid
			if name == "uid" {
				currentID += "-renamed"
			}
			_, err = m.DB.ExecContext(t.Context(), `UPDATE users SET email=$2,register=$3,email_verified=false,passwd=false,openid=false,hash=$4,created=$5,uid=$6 WHERE uid=$1`, currentID, account.Email, account.Register, account.Hash, account.Created, uid)
			require.NoError(t, err)
			current, err := m.PendingEmailConfirmation(t.Context(), uid)
			require.NoError(t, err)
			require.Empty(t, current.NewUserToken, "restored account values revived its invitation")
			require.ErrorIs(t, m.ConfirmEmail(t.Context(), account), ErrEmailConfirmationState)
			require.ErrorIs(t, m.StageEmailConfirmation(t.Context(), account, "stale-issuer-token"), ErrEmailConfirmationState)
			require.NoError(t, m.StageEmailConfirmation(t.Context(), current, "fresh-invitation"))
		})
	}
	t.Run("migration-health", func(t *testing.T) {
		before, err := m.PendingEmailConfirmation(t.Context(), "restored-email")
		require.NoError(t, err)
		// Recreate the pre-v4 schema to cover upgrades with an existing invitation.
		_, err = m.DB.ExecContext(t.Context(), `DROP TRIGGER uem_account_invitation ON users; DROP FUNCTION uem_clear_account_invitation(); DELETE FROM uem_session_generation_migrations WHERE version=4`)
		require.NoError(t, err)
		require.NoError(t, migrate())
		require.NoError(t, migrate())
		_, err = m.DB.ExecContext(t.Context(), `UPDATE users SET name='Updated display name',phone='123',modified=now() WHERE uid=$1`, before.ID)
		require.NoError(t, err)
		after, err := m.PendingEmailConfirmation(t.Context(), before.ID)
		require.NoError(t, err)
		require.Equal(t, before.NewUserToken, after.NewUserToken, "migration or display metadata update revoked an unchanged invitation")
		_, err = m.DB.ExecContext(t.Context(), `ALTER TABLE users DISABLE TRIGGER uem_account_invitation`)
		require.NoError(t, err)
		require.Error(t, migrate(), "startup accepted disabled invitation revocation")
		_, err = m.DB.ExecContext(t.Context(), `ALTER TABLE users ENABLE TRIGGER uem_account_invitation`)
		require.NoError(t, err)
		require.NoError(t, migrate())
	})
}
