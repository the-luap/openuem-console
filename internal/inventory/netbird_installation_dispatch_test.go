package inventory_test

import (
	"context"
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

func installationDispatchStore(t *testing.T, f *refreshFixture, prepare inventory.NetbirdPreparationExecutor, execute inventory.NetbirdInstallationExecutor) *inventory.NetbirdInstallationStore {
	t.Helper()
	s, err := inventory.NewNetbirdInstallationDeliveryStore(f.db, f.permissions, true, strings.Repeat("k", 32), installationCapabilities, prepare, execute)
	require.NoError(t, err)
	return s
}

func TestNetbirdInstallationDispatchPreparesAndDeliversOnceAcrossRestart(t *testing.T) {
	for _, preprepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued", true: "prepared"}[preprepared], func(t *testing.T) {
			f, requests, _, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var preparations, native atomic.Int32
			prepare := func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
				preparations.Add(1)
				out, err := netbirdcommand.PreparationResponseFor(p, "prepared")
				return &out, err
			}
			execute := func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				native.Add(1)
				stop, err := requests.ReadDispatchStop(ctx, "viewer", f.scope, f.id, r.ID, r.Revision)
				require.NoError(t, err)
				require.Nil(t, stop)
				out, err := netbirdcommand.ReceiptFor(c, "completed")
				return &out, err
			}
			s := installationDispatchStore(t, f, prepare, execute)
			if preprepared {
				_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
				require.NoError(t, err)
			}
			restarted := installationDispatchStore(t, f, prepare, execute)
			worked, err := restarted.DispatchOne(t.Context())
			require.NoError(t, err)
			require.True(t, worked)
			got, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
			require.NoError(t, err)
			require.Equal(t, "completed", got.Outcome)
			worked, err = s.DispatchOne(t.Context())
			require.NoError(t, err)
			require.False(t, worked)
			require.EqualValues(t, 1, preparations.Load())
			require.EqualValues(t, 1, native.Load())
		})
	}
}

func TestNetbirdInstallationDispatchRetainsUncertainAttemptsWithoutRetry(t *testing.T) {
	for _, stage := range []string{"prepare", "prepare-audit", "install"} {
		t.Run(stage, func(t *testing.T) {
			f, requests, _, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var preparations, native atomic.Int32
			s := installationDispatchStore(t, f, func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
				preparations.Add(1)
				if stage == "prepare" {
					return nil, errors.New("owned lost preparation")
				}
				out, err := netbirdcommand.PreparationResponseFor(p, "prepared")
				return &out, err
			}, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				native.Add(1)
				return nil, errors.New("owned lost native reply")
			})
			if stage == "prepare-audit" {
				_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_dispatch_result_audit CHECK(resource_id NOT LIKE '%/preparation-prepared') NOT VALID`)
				require.NoError(t, err)
			}
			worked, err := s.DispatchOne(t.Context())
			require.True(t, worked)
			if stage == "prepare-audit" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			worked, err = s.DispatchOne(t.Context())
			require.NoError(t, err)
			require.False(t, worked)
			require.EqualValues(t, 1, preparations.Load())
			if stage == "install" {
				require.EqualValues(t, 1, native.Load())
			} else {
				require.Zero(t, native.Load())
			}
			stop, err := s.ReadDispatchStop(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			if stage == "prepare" {
				require.Equal(t, "preparation_unconfirmed", stop.Reason)
				_, err = s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
				_, err = requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
				require.NoError(t, err)
			} else {
				require.Nil(t, stop)
			}
		})
	}
}

func TestNetbirdInstallationDispatchStopsChangedPreflightWithoutClearingBarrier(t *testing.T) {
	for _, change := range []string{"permission", "approval", "stop-audit"} {
		t.Run(change, func(t *testing.T) {
			f, requests, packages, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var calls atomic.Int32
			s := installationDispatchStore(t, f, func(context.Context, netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
				calls.Add(1)
				return nil, nil
			}, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				return nil, nil
			})
			if change == "approval" {
				_, err := packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, r.ApprovalID, r.ApprovalDigest, uuid.NewString())
				require.NoError(t, err)
			} else {
				p, err := f.permissions.Principal(t.Context(), "tag-admin")
				require.NoError(t, err)
				require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", "tag-admin", p.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
			}
			if change == "stop-audit" {
				_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_dispatch_stop_audit CHECK(action<>'inventory.netbird.stopped') NOT VALID`)
				require.NoError(t, err)
			}
			worked, err := s.DispatchOne(t.Context())
			require.True(t, worked)
			if change == "stop-audit" {
				require.Error(t, err)
				stop, e := s.ReadDispatchStop(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
				require.NoError(t, e)
				require.Nil(t, stop)
				return
			}
			require.NoError(t, err)
			require.Zero(t, calls.Load())
			stop, err := s.ReadDispatchStop(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			require.NotNil(t, stop)
			reason := "not_authorized"
			if change == "approval" {
				reason = "source_changed"
			}
			require.Equal(t, reason, stop.Reason)
			worked, err = s.DispatchOne(t.Context())
			require.NoError(t, err)
			require.False(t, worked)
			read, err := requests.Read(t.Context(), "viewer", f.scope, f.id, r.ID)
			require.NoError(t, err)
			require.Nil(t, read.CancelledAt)
			require.Nil(t, read.CompletedAt)
			require.Nil(t, read.ReleasedAt)
			_, err = requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
			require.NoError(t, err)
			for _, query := range []string{`DELETE FROM uem_netbird_installation_dispatch_stops`, `UPDATE uem_netbird_installation_dispatch_stops SET reason='expired'`} {
				_, err = f.db.ExecContext(t.Context(), query)
				require.Error(t, err)
			}
		})
	}
}

func TestNetbirdInstallationDispatchJoinsShutdownAndConcurrentDelivery(t *testing.T) {
	for _, phase := range []string{"prepare", "install"} {
		t.Run(phase, func(t *testing.T) {
			f, requests, _, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			entered := make(chan struct{})
			joined := make(chan struct{})
			var preparations, native atomic.Int32
			s := installationDispatchStore(t, f, func(ctx context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
				preparations.Add(1)
				if phase == "prepare" {
					close(entered)
					<-ctx.Done()
					close(joined)
					return nil, ctx.Err()
				}
				out, err := netbirdcommand.PreparationResponseFor(p, "prepared")
				return &out, err
			}, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				native.Add(1)
				close(entered)
				<-ctx.Done()
				close(joined)
				return nil, ctx.Err()
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); s.Run(ctx, nil) }()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("dispatch did not enter its owned callback")
			}
			// Another dispatcher observes the durable attempt and performs no RPC.
			worked, err := s.DispatchOne(t.Context())
			require.NoError(t, err)
			require.False(t, worked)
			if phase == "prepare" {
				_, err = requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
				require.NoError(t, err)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("dispatch did not join shutdown")
			}
			select {
			case <-joined:
			default:
				t.Fatal("callback was not joined")
			}
			require.EqualValues(t, 1, preparations.Load())
			if phase == "prepare" {
				require.Zero(t, native.Load())
			} else {
				require.EqualValues(t, 1, native.Load())
			}
		})
	}
}

func TestNetbirdInstallationDispatchStopGuardsNativeAdmissionAndStartup(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	var calls atomic.Int32
	s := installationDispatchStore(t, f, func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		calls.Add(1)
		out, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &out, err
	}, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		return nil, nil
	})
	_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_dispatch_stops(request_id,reason) VALUES($1,'source_changed')`, r.ID)
	require.NoError(t, err)
	_, err = s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.EqualValues(t, 1, calls.Load())
	_, err = f.db.ExecContext(t.Context(), `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_installation_attempts(request_id,wire_version,certificate_hash,command_hash,issued_at,expires_at) SELECT request_id,3,certificate_hash,repeat('f',64),stamp.at,stamp.at+interval '1 minute' FROM uem_netbird_preparations,stamp WHERE request_id=$1`, r.ID)
	require.ErrorContains(t, err, "dispatch was stopped")
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_preparations(request_id,wire_version,certificate_hash,request_hash,issued_at,expires_at) SELECT request_id,wire_version,certificate_hash,request_hash,issued_at,expires_at FROM uem_netbird_preparations WHERE request_id=$1`, r.ID)
	require.ErrorContains(t, err, "dispatch was stopped")
	for _, guard := range [][2]string{{"uem_netbird_installation_dispatch_stops", "uem_netbird_installation_dispatch_stop_immutable"}, {"uem_netbird_installation_dispatch_stops", "uem_netbird_installation_dispatch_stop_valid"}, {"uem_netbird_preparations", "uem_netbird_installation_dispatch_required"}, {"uem_netbird_installation_attempts", "uem_netbird_installation_dispatch_required"}} {
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` DISABLE TRIGGER `+guard[1])
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` ENABLE TRIGGER `+guard[1])
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}
