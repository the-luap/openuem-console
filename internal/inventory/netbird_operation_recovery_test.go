package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestNetbirdOperationsAuditFailureRecoveryAndRetention(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	sent := 0
	s := netbirdStore(t, f, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		sent++
		return netbirdSuccess(ctx, c)
	})
	fail := func(action string) {
		t.Helper()
		_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_failure CHECK(action<>'inventory.netbird.`+action+`') NOT VALID`)
		require.NoError(t, err)
	}
	recoverAudit := func() {
		t.Helper()
		_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_failure`)
		require.NoError(t, err)
	}
	review, err := s.Review(ctx, "tag-admin", f.scope, f.id, "up", "")
	require.NoError(t, err)
	fail("request")
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", review.Revision)
	require.Error(t, err)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations`).Scan(&count))
	require.Zero(t, count)
	recoverAudit()
	r := netbirdRequest(t, f, s, "up", "")
	fail("attempt")
	_, err = s.DispatchOne(ctx)
	require.Error(t, err)
	require.Zero(t, sent)
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operation_attempts`).Scan(&count))
	require.Zero(t, count)
	recoverAudit()
	fail("completed")
	_, err = s.DispatchOne(ctx)
	require.Error(t, err)
	require.Equal(t, 1, sent)
	recoverAudit()
	receipt := netbirdRead(t, f, s, r.ID)
	require.Equal(t, "queued", receipt.Status)
	require.NotNil(t, receipt.AttemptedAt)
	require.ErrorIs(t, s.Cancel(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID), inventory.ErrNetbirdOperationConflict)
	// The operator audit may be retained independently: a permanent receipt, not
	// a prunable event, is what prevents repeated external effects.
	_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_operations_audit SET created_at=clock_timestamp()-interval '45 days' WHERE action='inventory.netbird.attempt'`)
	require.NoError(t, err)
	a, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	org := access.Scope{TenantID: f.scope.TenantID}
	preview, err := a.PreviewRetention(ctx, "admin", org, 30)
	require.NoError(t, err)
	require.Equal(t, int64(1), preview.Counts["netbird-operations"])
	require.NoError(t, a.ApplyRetention(ctx, "admin", org, preview.ID, preview.Token))
	require.NoError(t, a.PruneRetention(ctx))
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE action='inventory.netbird.attempt'`).Scan(&count))
	require.Zero(t, count)
	receipt = netbirdRead(t, f, s, r.ID)
	require.NotNil(t, receipt.AttemptedAt)
	restarted := netbirdStore(t, f, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		t.Error("recovery repeated a command")
		return nil, errors.New("unexpected execution")
	})
	worked, err := restarted.DispatchOne(ctx)
	require.NoError(t, err)
	require.True(t, worked)
	receipt = netbirdRead(t, f, restarted, r.ID)
	require.Equal(t, "unconfirmed", receipt.Status)
	require.NotNil(t, receipt.AttemptedAt)
	_, err = restarted.Request(ctx, r.Actor, r.Scope, r.DeviceID, uuid.NewString(), r.Operation, r.Profile, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	// Outcomes, identities and attempt evidence cannot be rewritten or pruned.
	for _, query := range []string{
		`DELETE FROM uem_netbird_operations`,
		`DELETE FROM uem_netbird_operation_attempts`,
		`UPDATE uem_netbird_operation_attempts SET created_at=clock_timestamp()`,
		`UPDATE uem_netbird_operations SET status='queued',reason='',finished_at=NULL`,
		`UPDATE uem_netbird_operations SET profile='changed'`,
		`UPDATE uem_netbird_operations SET expires_at=expires_at+interval '1 minute'`,
	} {
		_, err = f.db.ExecContext(ctx, query)
		require.Error(t, err, query)
	}
	fail("release")
	require.Error(t, netbirdReleaseCompleted(t, f, restarted, "tag-admin", r))
	recoverAudit()
	require.Nil(t, netbirdRead(t, f, restarted, r.ID).ReleasedAt)
	require.NoError(t, netbirdReleaseCompleted(t, f, restarted, "tag-admin", r))
	_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_operations SET released_by='admin'`)
	require.Error(t, err)
	require.Equal(t, 1, sent)
}

func TestNetbirdOperationsCancellationRecoveryNeverRetries(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sent := 0
	s := netbirdStore(t, f, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		sent++
		cancel()
		return netbirdSuccess(ctx, c)
	})
	r := netbirdRequest(t, f, s, "up", "")
	_, err := s.DispatchOne(ctx)
	require.ErrorIs(t, err, context.Canceled)
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, sent)
	receipt := netbirdRead(t, f, s, r.ID)
	require.Equal(t, "unconfirmed", receipt.Status)
	require.NoError(t, netbirdReleaseCompleted(t, f, s, "tag-admin", r))
	r = netbirdRequest(t, f, s, "down", "")
	require.NoError(t, s.Cancel(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID))
	receipt = netbirdRead(t, f, s, r.ID)
	require.Equal(t, "stopped", receipt.Status)
	require.Equal(t, "cancelled", receipt.Reason)
	require.Nil(t, receipt.AttemptedAt)
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, sent)
}

func netbirdWaitForLocks(t *testing.T, ctx context.Context, f *refreshFixture, n int) {
	t.Helper()
	for {
		var pending int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE NOT l.granted AND a.application_name=current_setting('application_name')`).Scan(&pending))
		if pending >= n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNetbirdOperationsCancelRechecksAttemptAfterWaiting(t *testing.T) {
	f, _ := netbirdFixture(t)
	s := netbirdStore(t, f, nil)
	r := netbirdRequest(t, f, s, "up", "")
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `SELECT id FROM uem_netbird_operations WHERE id=$1 FOR UPDATE`, r.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- s.Cancel(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID) }()
	netbirdWaitForLocks(t, ctx, f, 1)
	// Simulate a dispatcher that committed its attempt then lost the request
	// transaction. The cancelling SELECT started before this receipt existed.
	_, err = f.db.ExecContext(ctx, `INSERT INTO uem_netbird_operation_attempts(request_id,device_id,tenant_id,site_id,actor,operation,revision) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.Actor, r.Operation, r.Revision)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback())
	select {
	case err := <-done:
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err = s.DispatchOne(ctx)
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", netbirdRead(t, f, s, r.ID).Status)
}

func TestNetbirdOperationsHoldAuthorityAndSourceDuringExecution(t *testing.T) {
	f, providerID := netbirdFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	s := netbirdStore(t, f, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		close(started)
		select {
		case <-release:
			return netbirdSuccess(ctx, c)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	r := netbirdRequest(t, f, s, "up", "")
	done := make(chan error, 1)
	go func() { _, err := s.DispatchOne(ctx); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	worked, err := s.DispatchOne(ctx)
	require.NoError(t, err)
	require.False(t, worked)
	moved, revoked, changed := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { moved <- f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx) }()
	go func() { revoked <- f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", 1, nil) }()
	go func() {
		changed <- f.client.NetbirdSettings.UpdateOneID(providerID).SetAccessToken("replacement").Exec(ctx)
	}()
	netbirdWaitForLocks(t, ctx, f, 3)
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, <-moved)
	require.NoError(t, <-revoked)
	require.NoError(t, <-changed)
	require.Equal(t, "completed", netbirdRead(t, f, s, r.ID).Status)
}

func TestNetbirdOperationsReviewUsesReportWriterLockOrder(t *testing.T) {
	f, _ := netbirdFixture(t)
	s := netbirdStore(t, f, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `SELECT id FROM netbirds WHERE agent_netbird=$1 FOR UPDATE`, f.id)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := s.Review(ctx, "tag-admin", f.scope, f.id, "up", ""); done <- err }()
	netbirdWaitForLocks(t, ctx, f, 1)
	// This trigger must acquire the device generation without deadlocking a
	// review that already owns that generation and is waiting on this report.
	_, err = tx.ExecContext(ctx, `UPDATE netbirds SET installed=false WHERE agent_netbird=$1`, f.id)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestNetbirdOperationsPreDispatchStopsAndSchemaGuards(t *testing.T) {
	for _, change := range []string{"permission", "source", "mode", "expired"} {
		t.Run(change, func(t *testing.T) {
			f, providerID := netbirdFixture(t)
			ctx := t.Context()
			s := netbirdStore(t, f, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				t.Error("stopped request executed")
				return nil, nil
			})
			r := netbirdRequest(t, f, s, "up", "")
			reason := "source_changed"
			switch change {
			case "permission":
				require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", 1, nil))
				reason = "not_authorized"
			case "source":
				require.NoError(t, f.client.NetbirdSettings.UpdateOneID(providerID).SetManagementURL("https://changed.example.test").Exec(ctx))
			case "mode":
				var err error
				s, err = inventory.NewNetbirdOperationStore(f.db, f.permissions, true, netbirdReady, netbirdSuccess)
				require.NoError(t, err)
				reason = "mode_changed"
			case "expired":
				// A separate historical intent avoids weakening immutable timestamps.
				require.NoError(t, s.Cancel(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID))
				r.ID = uuid.NewString()
				_, err := f.db.ExecContext(ctx, `INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,revision,requested_at,expires_at) VALUES($1,$2,$3,$4,$5,false,'up',$6,clock_timestamp()-interval '5 minutes',clock_timestamp()-interval '4 minutes')`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.Actor, r.Revision)
				require.NoError(t, err)
				reason = "expired"
			}
			worked, err := s.DispatchOne(ctx)
			require.NoError(t, err)
			require.True(t, worked)
			receipt := netbirdRead(t, f, s, r.ID)
			require.Equal(t, "stopped", receipt.Status)
			require.Equal(t, reason, receipt.Reason)
			require.Nil(t, receipt.AttemptedAt)
		})
	}
	f, _ := netbirdFixture(t)
	for _, guard := range [][2]string{{"agents", "uem_netbird_agent_binding"}, {"site_agents", "uem_netbird_scope_binding"}, {"sites", "uem_netbird_site_binding"}, {"netbirds", "uem_netbird_installation_binding"}, {"uem_netbird_operation_attempts", "uem_netbird_attempt_immutable"}, {"uem_netbird_operations", "uem_netbird_operation_immutable"}, {"uem_netbird_operations", "uem_netbird_wire_receipt"}} {
		_, err := f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` DISABLE TRIGGER `+guard[1])
		require.NoError(t, err)
		require.ErrorContains(t, inventory.Migrate(t.Context(), f.db), "NetBird operation protection")
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` ENABLE TRIGGER `+guard[1])
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}
