package inventory_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

func queueManual(t *testing.T, f *refreshFixture, store *inventory.ManualExecutionStore, actor string, taskID int) *inventory.ManualRequest {
	t.Helper()
	review, err := store.Review(t.Context(), actor, f.scope, f.id, "task", int64(taskID))
	require.NoError(t, err)
	request, err := store.Request(t.Context(), actor, f.scope, f.id, uuid.NewString(), "task", int64(taskID), review.Source.Revision)
	require.NoError(t, err)
	return request
}

func TestManualExecutionAuditFailureRestartAndRetentionNeverRepeatSend(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	_, taskID := manualTask(t, f, f.scope)
	calls := 0
	store := manualStore(t, f, func(ctx context.Context, _, id string, _ *taskexecution.Payload) error {
		calls++
		var attempts int
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_manual_execution_audit WHERE request_id=$1 AND action='inventory.execution.attempt'", id).Scan(&attempts))
		require.Equal(t, 1, attempts, "attempt must commit before publication")
		return nil
	})
	failure := func(action string) {
		t.Helper()
		_, err := f.db.ExecContext(ctx, "ALTER TABLE uem_manual_execution_audit ADD CONSTRAINT owned_manual_failure CHECK(action<>'inventory.execution."+action+"') NOT VALID")
		require.NoError(t, err)
	}
	recoverAudit := func() {
		t.Helper()
		_, err := f.db.ExecContext(ctx, "ALTER TABLE uem_manual_execution_audit DROP CONSTRAINT owned_manual_failure")
		require.NoError(t, err)
	}
	review, err := store.Review(ctx, "admin", f.scope, f.id, "task", int64(taskID))
	require.NoError(t, err)
	failure("request")
	_, err = store.Request(ctx, "admin", f.scope, f.id, uuid.NewString(), "task", int64(taskID), review.Source.Revision)
	require.Error(t, err)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_manual_execution").Scan(&count))
	require.Zero(t, count)
	require.Zero(t, calls)
	recoverAudit()
	request := queueManual(t, f, store, "admin", taskID)
	failure("attempt")
	_, err = store.DispatchOne(ctx)
	require.Error(t, err)
	require.Zero(t, calls)
	recoverAudit()
	failure("accepted")
	_, err = store.DispatchOne(ctx)
	require.Error(t, err)
	require.Equal(t, 1, calls)
	receipt, err := store.Read(ctx, "admin", f.scope, f.id, request.ID)
	require.NoError(t, err)
	require.Equal(t, "queued", receipt.Status)
	require.NotNil(t, receipt.AttemptedAt)
	recoverAudit()

	// Retention must preserve the only evidence preventing a duplicate command.
	_, err = f.db.ExecContext(ctx, "UPDATE uem_manual_execution_audit SET created_at=clock_timestamp()-interval '45 days' WHERE action='inventory.execution.attempt'")
	require.NoError(t, err)
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	preview, err := audits.PreviewRetention(ctx, "admin", org, 30)
	require.NoError(t, err)
	require.Zero(t, preview.Counts["manual-execution"])
	require.NoError(t, audits.ApplyRetention(ctx, "admin", org, preview.ID, preview.Token))
	require.NoError(t, audits.PruneRetention(ctx))
	receipt, err = store.Read(ctx, "admin", f.scope, f.id, request.ID)
	require.NoError(t, err)
	require.NotNil(t, receipt.AttemptedAt)

	restarted := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error {
		t.Fatal("restart repeated a command with durable attempt evidence")
		return nil
	})
	worked, err := restarted.DispatchOne(ctx)
	require.NoError(t, err)
	require.True(t, worked)
	receipt, err = restarted.Read(ctx, "admin", f.scope, f.id, request.ID)
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", receipt.Status)
	require.Equal(t, "delivery_unconfirmed", receipt.Reason)
	_, err = f.db.ExecContext(ctx, "UPDATE uem_audit_retention SET next_sweep_at=clock_timestamp()")
	require.NoError(t, err)
	require.NoError(t, audits.PruneRetention(ctx))
	receipt, err = restarted.Read(ctx, "admin", f.scope, f.id, request.ID)
	require.NoError(t, err)
	require.Nil(t, receipt.AttemptedAt)
	require.Equal(t, "unconfirmed", receipt.Status)
	worked, err = restarted.DispatchOne(ctx)
	require.NoError(t, err)
	require.False(t, worked)
	require.Equal(t, 1, calls)
}

func TestManualExecutionConcurrentAdmissionAndCancelledHandoff(t *testing.T) {
	f, _ := tagFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, taskID := manualTask(t, f, f.scope)
	var calls atomic.Int32
	store := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error {
		calls.Add(1)
		cancel()
		return nil
	})
	review, err := store.Review(ctx, "admin", f.scope, f.id, "task", int64(taskID))
	require.NoError(t, err)
	id := uuid.NewString()
	type outcome struct {
		request *inventory.ManualRequest
		err     error
	}
	results := make(chan outcome, 4)
	for range 4 {
		go func() {
			request, err := store.Request(ctx, "admin", f.scope, f.id, id, "task", int64(taskID), review.Source.Revision)
			results <- outcome{request, err}
		}()
	}
	for range 4 {
		result := <-results
		require.NoError(t, result.err)
		require.Equal(t, id, result.request.ID)
	}
	_, err = store.Request(ctx, "admin", f.scope, f.id, id, "task", int64(taskID+1), review.Source.Revision)
	require.ErrorIs(t, err, inventory.ErrManualConflict)
	_, err = store.DispatchOne(ctx)
	require.ErrorIs(t, err, context.Canceled)
	restarted := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error { calls.Add(1); return nil })
	_, err = restarted.DispatchOne(t.Context())
	require.NoError(t, err)
	receipt, err := restarted.Read(t.Context(), "admin", f.scope, f.id, id)
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", receipt.Status)
	require.NotNil(t, receipt.AttemptedAt)
	require.EqualValues(t, 1, calls.Load())
}

func TestManualExecutionHoldsAuthorityAndSourceUntilCompletionAudit(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	profileID, taskID := manualTask(t, f, f.scope)
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	var calls atomic.Int32
	store := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error { calls.Add(1); return nil })
	request := queueManual(t, f, store, "tag-admin", taskID)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810078)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810078)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, "CREATE SEQUENCE owned_manual_entered; CREATE FUNCTION hold_owned_manual() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.execution.accepted' THEN PERFORM nextval('owned_manual_entered'); PERFORM pg_advisory_xact_lock(673810078); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_manual AFTER INSERT ON uem_manual_execution_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_manual()")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := store.DispatchOne(ctx); done <- err }()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_manual_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	worked, err := store.DispatchOne(ctx)
	require.NoError(t, err)
	require.False(t, worked, "another worker must skip the held request")
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tasks SET version=version+1 WHERE id=$1", taskID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE profiles SET disabled=true WHERE id=$1", profileID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO tasks(profile_tasks,name,type,agent_type) VALUES($1,'Incoming task','powershell_script','windows')", profileID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM site_profiles WHERE profile_id=$1", profileID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE agents SET nickname='Concurrent endpoint' WHERE oid=$1", f.id)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)", f.id, f.otherSite)
			return err
		},
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: org}})
		},
	} {
		bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		err := mutation(bounded)
		cancel()
		require.Error(t, err)
		require.True(t, errors.Is(err, context.DeadlineExceeded) || stringsContainsCancellation(err), "mutation must block on held locks: %v", err)
	}
	release()
	require.NoError(t, <-done)
	require.EqualValues(t, 1, calls.Load())
	receipt, err := store.Read(ctx, "tag-admin", f.scope, f.id, request.ID)
	require.NoError(t, err)
	require.Equal(t, "accepted", receipt.Status)
}

// pgx may return the server's statement cancellation instead of the context.
func stringsContainsCancellation(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "canceling statement"))
}

func TestManualExecutionWorkerCancellationRetainsSoleAttempt(t *testing.T) {
	f, _ := tagFixture(t)
	started := make(chan struct{})
	store := manualStore(t, f, func(ctx context.Context, _, _ string, _ *taskexecution.Payload) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	_, id := manualTask(t, f, f.scope)
	request := queueManual(t, f, store, "admin", id)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); store.Run(ctx, nil) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("manual worker did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("manual worker did not join cancellation")
	}
	receipt, err := store.Read(t.Context(), "admin", f.scope, f.id, request.ID)
	require.NoError(t, err)
	require.Equal(t, "queued", receipt.Status)
	require.NotNil(t, receipt.AttemptedAt)
	restarted := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error {
		t.Error("restart repeated an attempted command")
		return nil
	})
	run, stop := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { defer close(stopped); restarted.Run(run, nil) }()
	defer func() { stop(); <-stopped }()
	require.Eventually(t, func() bool {
		page, err := restarted.Choices(t.Context(), "admin", f.scope, f.id, "task", "")
		return err == nil && page.Latest != nil && page.Latest.ID == request.ID && page.Latest.Status == "unconfirmed"
	}, 3*time.Second, 50*time.Millisecond)
}
