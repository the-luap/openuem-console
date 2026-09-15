package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func installationDeliveryStore(t *testing.T, f *refreshFixture, control inventory.NetbirdOperationControl, execute inventory.NetbirdInstallationExecutor) *inventory.NetbirdInstallationStore {
	t.Helper()
	if control == nil {
		control = installationCapabilities
	}
	s, err := inventory.NewNetbirdInstallationDeliveryStore(f.db, f.permissions, true, strings.Repeat("k", 32), control, func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		r, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &r, err
	}, execute)
	require.NoError(t, err)
	return s
}

func TestNetbirdInstallationDeliveryCommitsExactFreshCommandAndOpensOnlyCompletedBarrier(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	var calls atomic.Int32
	s := installationDeliveryStore(t, f, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		require.Equal(t, netbirdcommand.InstallationVersion, c.Version)
		require.Equal(t, pkg, c.Package)
		require.Equal(t, r.ID, c.RequestID)
		require.Equal(t, r.Revision, c.Revision)
		require.Equal(t, 10*time.Minute, c.ExpiresAt.Sub(c.IssuedAt))
		require.True(t, c.ExpiresAt.After(r.ExpiresAt))
		var hash string
		var preparedAt time.Time
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT a.command_hash,p.issued_at FROM uem_netbird_installation_attempts a JOIN uem_netbird_preparations p USING(request_id) WHERE request_id=$1`, r.ID).Scan(&hash, &preparedAt))
		digest, err := c.Digest()
		require.NoError(t, err)
		require.Equal(t, hash, digest)
		require.False(t, c.IssuedAt.Before(preparedAt))
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND resource_id LIKE '%/install/deliver'`, r.ID).Scan(&count))
		require.Equal(t, 1, count)
		_, err = requests.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_installations SET cancellation_id=$2,cancelled_by='tag-admin',cancelled_at=clock_timestamp() WHERE id=$1`, r.ID, uuid.NewString())
		require.Error(t, err)
		result, err := netbirdcommand.ReceiptFor(c, "completed")
		return &result, err
	})
	_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	got, err := s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", got.Outcome)
	require.NotNil(t, got.CompletedAt)
	require.NotNil(t, got.Receipt)
	replay, err := s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, got, replay)
	require.EqualValues(t, 1, calls.Load())
	record, err := requests.Read(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, got.CompletedAt, record.CompletedAt)
	read, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, got, read)
	data, err := json.Marshal(read)
	require.NoError(t, err)
	require.NotContains(t, string(data), "owned-installation-source")
	require.NotContains(t, string(data), "certificate_hash")
	_, err = s.ReadDelivery(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, r.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	// Both the SQL admission function and the installation-specific partial index
	// must release completed work while preserving the permanent UUID namespace.
	insert := `INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,profile,revision,requested_at,expires_at) VALUES($1,$2,$3,$4,'tag-admin',true,'up','',repeat('a',64),clock_timestamp(),clock_timestamp()+interval '1 minute')`
	_, err = f.db.ExecContext(t.Context(), insert, r.ID, f.id, f.scope.TenantID, f.scope.SiteID)
	require.Error(t, err)
	other := uuid.NewString()
	_, err = f.db.ExecContext(t.Context(), insert, other, f.id, f.scope.TenantID, f.scope.SiteID)
	require.NoError(t, err)
	ops, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, true, netbirdReady, netbirdSuccess)
	require.NoError(t, err)
	require.NoError(t, ops.Cancel(t.Context(), "tag-admin", f.scope, f.id, other))
	next := installationRequest(t, f, requests, pkg)
	require.NotEqual(t, r.ID, next.ID)
	_, err = requests.Cancel(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
}

func TestNetbirdInstallationDeliveryRejectsStaleOrAlteredPreparationBeforeAttempt(t *testing.T) {
	for _, change := range []string{"missing", "cancel", "approval", "certificate", "consumer", "permission", "hash", "timestamps", "response", "journal", "audit"} {
		t.Run(change, func(t *testing.T) {
			f, requests, packages, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var changed atomic.Bool
			var calls atomic.Int32
			s := installationDeliveryStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				response, err := installationCapabilities(ctx, c)
				if change == "journal" && changed.Load() {
					response.State.Revision = strings.Repeat("e", 64)
				}
				return response, err
			}, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				return nil, nil
			})
			if change != "missing" {
				_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
				require.NoError(t, err)
			}
			var err error
			switch change {
			case "cancel":
				_, err = requests.Cancel(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
			case "approval":
				_, err = packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, pkg.ApprovalID, r.ApprovalDigest, uuid.NewString())
			case "certificate":
				_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
			case "permission":
				principal, e := f.permissions.Principal(t.Context(), "tag-admin")
				require.NoError(t, e)
				err = f.permissions.ReplaceGrants(t.Context(), "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
			case "hash", "timestamps":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_preparations DISABLE TRIGGER uem_netbird_preparation_immutable`)
				require.NoError(t, err)
				query := `UPDATE uem_netbird_preparations SET request_hash=repeat('f',64)`
				if change == "timestamps" {
					query = `UPDATE uem_netbird_preparations SET issued_at=issued_at+interval '1 millisecond'`
				}
				_, err = f.db.ExecContext(t.Context(), query)
			case "response":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_preparation_results DISABLE TRIGGER uem_netbird_preparation_result_immutable`)
				require.NoError(t, err)
				_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_preparation_results SET response=jsonb_set(response,'{request_hash}',to_jsonb(repeat('f',64)))`)
			case "journal":
				changed.Store(true)
			case "audit":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_delivery_failure CHECK(resource_id NOT LIKE '%/install/deliver') NOT VALID`)
			}
			require.NoError(t, err)
			_, err = s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.Error(t, err)
			require.Zero(t, calls.Load())
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_attempts`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdInstallationDeliveryNeverRepeatsUncertainNativeWork(t *testing.T) {
	for _, status := range []string{"unconfirmed", "busy", "rejected", "withdrawn", "nil", "error", "wrong-hash", "cancel", "audit"} {
		t.Run(status, func(t *testing.T) {
			f, requests, _, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var calls atomic.Int32
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := installationDeliveryStore(t, f, nil, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				receipt, err := netbirdcommand.ReceiptFor(c, "completed")
				switch status {
				case "unconfirmed", "busy", "rejected", "withdrawn":
					receipt.Status = status
				case "nil":
					return nil, nil
				case "error":
					return nil, errors.New("owned private installer output")
				case "wrong-hash":
					receipt.CommandHash = strings.Repeat("f", 64)
				case "cancel":
					cancel()
				case "audit":
					_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_result_failure CHECK(resource_id NOT LIKE '%/install/result-%') NOT VALID`)
				}
				return &receipt, err
			})
			_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			got, err := s.Install(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
			want := "unconfirmed"
			if status == "audit" {
				require.Error(t, err)
				want = "pending"
			} else {
				require.NoError(t, err)
				require.Equal(t, want, got.Outcome)
				require.Nil(t, got.CompletedAt)
			}
			// A reconstructed store reads the same durable evidence after a caller or
			// server restart. No callback or source can authorize a second installation.
			restarted := installationDeliveryStore(t, f, nil, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				t.Error("installation redelivered")
				return nil, nil
			})
			replay, err := restarted.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			require.Equal(t, want, replay.Outcome)
			require.EqualValues(t, 1, calls.Load())
			_, err = requests.Cancel(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			_, err = requests.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), pkg.ApprovalID, r.ApprovalDigest, r.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		})
	}
}

func TestNetbirdInstallationDeliveryReleasesDatabaseLocksDuringNativeExecution(t *testing.T) {
	f, requests, packages, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s := installationDeliveryStore(t, f, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		result, err := netbirdcommand.ReceiptFor(c, "completed")
		return &result, err
	})
	_, err := s.Prepare(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := s.Install(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("native delivery did not start")
	}
	bounded, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	replay, err := s.Install(bounded, "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "pending", replay.Outcome)
	_, err = requests.Cancel(bounded, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = packages.Revoke(bounded, "tag-admin", access.Scope{TenantID: f.scope.TenantID}, pkg.ApprovalID, r.ApprovalDigest, uuid.NewString())
	require.NoError(t, err)
	close(release)
	require.NoError(t, <-done)
	got, err := s.ReadDelivery(ctx, "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, "completed", got.Outcome)
}

func TestNetbirdInstallationDeliveryWinsConcurrentDirectSQLCancellation(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	entered, release := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	var calls atomic.Int32
	s := installationDeliveryStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if hold.Load() && c.Kind == "preparation-state" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return installationCapabilities(ctx, c)
	}, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		r, err := netbirdcommand.ReceiptFor(c, "unconfirmed")
		return &r, err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := s.Prepare(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	hold.Store(true)
	installed := make(chan error, 1)
	go func() { _, err := s.Install(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision); installed <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("installation admission did not enter inspection")
	}
	cancelled := make(chan error, 1)
	go func() {
		_, err := f.db.ExecContext(ctx, `UPDATE uem_netbird_installations SET cancellation_id=$2,cancelled_by='tag-admin',cancelled_at=clock_timestamp() WHERE id=$1`, r.ID, uuid.NewString())
		cancelled <- err
	}()
	// Observe the actual blocked SQL statement before releasing admission. Its
	// initial snapshot predates the new attempt; the trigger must re-read evidence.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	waiting := false
	for !waiting {
		select {
		case <-ticker.C:
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE uem_netbird_installations SET cancellation_id=%')`).Scan(&waiting))
		case err := <-cancelled:
			t.Fatalf("cancellation bypassed installation admission: %v", err)
		case <-limit.C:
			t.Fatal("direct cancellation did not wait for the request lock")
		}
	}
	close(release)
	require.Error(t, <-cancelled)
	require.NoError(t, <-installed)
	require.EqualValues(t, 1, calls.Load())
	got, err := requests.Read(ctx, "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Nil(t, got.CancelledAt)
}
