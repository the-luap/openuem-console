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

func TestNetbirdAbsenceDispatchDeliversOnceAcrossRestart(t *testing.T) {
	x, requests, r := absenceDeliveryFixture(t)
	f := x.f
	var calls atomic.Int32
	execute := func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		require.Equal(t, netbirdcommand.RemovalAbsenceVersion, c.Version)
		require.Equal(t, "verify-removal-absence", c.Operation)
		require.Equal(t, r.Absence, c.RemovalAbsence)
		// This read uses a separate connection: native dispatch holds no transaction.
		stop, err := requests.ReadDispatchStop(ctx, "viewer", f.scope, f.id, r.ID, r.Revision)
		require.NoError(t, err)
		require.Nil(t, stop)
		var admitted int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_removal_absence_attempts WHERE request_id=$1`, r.ID).Scan(&admitted))
		require.Equal(t, 1, admitted)
		_, err = f.db.ExecContext(ctx, `INSERT INTO uem_netbird_removal_absence_dispatch_stops(request_id,reason) VALUES($1,'source_changed')`, r.ID)
		require.ErrorContains(t, err, "cannot stop before delivery")
		out, err := netbirdcommand.ReceiptFor(c, "completed")
		return &out, err
	}
	s := absenceDeliveryStore(t, x, nil, execute)
	worked, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.True(t, worked)
	got, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, "completed", got.Outcome)
	restarted := absenceDeliveryStore(t, x, nil, execute)
	worked, err = restarted.DispatchOne(t.Context())
	require.NoError(t, err)
	require.False(t, worked)
	require.EqualValues(t, 1, calls.Load())
}

func TestNetbirdAbsenceDispatchRetainsUncertainAttemptsWithoutRetry(t *testing.T) {
	for _, outcome := range []string{"lost", "rejected", "result-audit"} {
		t.Run(outcome, func(t *testing.T) {
			x, requests, r := absenceDeliveryFixture(t)
			f := x.f
			var calls atomic.Int32
			execute := func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				if outcome == "lost" {
					return nil, errors.New("owned lost removal reply")
				}
				out, err := netbirdcommand.ReceiptFor(c, "rejected")
				return &out, err
			}
			s := absenceDeliveryStore(t, x, nil, execute)
			if outcome == "result-audit" {
				_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_dispatch_audit CHECK(resource_id NOT LIKE '%/verify-removal-absence/result-unconfirmed') NOT VALID`)
				require.NoError(t, err)
			}
			worked, err := s.DispatchOne(t.Context())
			require.True(t, worked)
			if outcome == "result-audit" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			restarted := absenceDeliveryStore(t, x, nil, execute)
			worked, err = restarted.DispatchOne(t.Context())
			require.NoError(t, err)
			require.False(t, worked)
			require.EqualValues(t, 1, calls.Load())
			delivery, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
			require.NoError(t, err)
			if outcome == "result-audit" {
				require.Equal(t, "pending", delivery.Outcome)
			} else {
				require.Equal(t, "unconfirmed", delivery.Outcome)
			}
			stop, err := s.ReadDispatchStop(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			require.Nil(t, stop)
			_, err = requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		})
	}
}

func TestNetbirdAbsenceDispatchStopsChangedPreflightWithoutClearingBarrier(t *testing.T) {
	for _, change := range []string{"permission", "certificate", "descriptor", "absent", "unavailable", "stop-audit"} {
		t.Run(change, func(t *testing.T) {
			x, requests, r := absenceDeliveryFixture(t)
			f := x.f
			var calls atomic.Int32
			control := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				if change == "unavailable" {
					return nil, errors.New("owned inspection unavailable")
				}
				p, err := absenceControl(t, x)(ctx, c)
				if err == nil && change == "descriptor" {
					p.RemovalAbsence.StateDigest = strings.Repeat("e", 64)
				}
				if change == "absent" {
					p.Outcome = "absent"
					p.RemovalAbsence = netbirdcommand.RemovalAbsence{}
				}
				return p, err
			}
			s := absenceDeliveryStore(t, x, control, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				return nil, nil
			})
			if change == "certificate" {
				_, err := f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
				require.NoError(t, err)
			}
			if change == "permission" || change == "stop-audit" {
				p, err := f.permissions.Principal(t.Context(), "tag-admin")
				require.NoError(t, err)
				require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", "tag-admin", p.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
			}
			if change == "stop-audit" {
				_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_dispatch_stop_audit CHECK(action<>'inventory.netbird.stopped') NOT VALID`)
				require.NoError(t, err)
			}
			worked, err := s.DispatchOne(t.Context())
			require.True(t, worked)
			require.Zero(t, calls.Load())
			if change == "stop-audit" {
				require.Error(t, err)
				stop, e := s.ReadDispatchStop(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
				require.NoError(t, e)
				require.Nil(t, stop)
				return
			}
			require.NoError(t, err)
			stop, err := s.ReadDispatchStop(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			require.NotNil(t, stop)
			reason := "source_changed"
			if change == "permission" {
				reason = "not_authorized"
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
			for _, query := range []string{`DELETE FROM uem_netbird_removal_absence_dispatch_stops`, `UPDATE uem_netbird_removal_absence_dispatch_stops SET reason='expired'`} {
				_, err = f.db.ExecContext(t.Context(), query)
				require.Error(t, err)
			}
		})
	}
}

func TestNetbirdAbsenceDispatchJoinsShutdownAndConcurrentDelivery(t *testing.T) {
	x, requests, r := absenceDeliveryFixture(t)
	f := x.f
	entered, joined := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := absenceDeliveryStore(t, x, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
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
	worked, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.False(t, worked)
	_, err = requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
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
	require.EqualValues(t, 1, calls.Load())
	delivery, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", delivery.Outcome)
}

func TestNetbirdAbsenceDispatchStopGuardsNativeAdmissionAndStartup(t *testing.T) {
	x, _, r := absenceDeliveryFixture(t)
	f := x.f
	var calls atomic.Int32
	s := absenceDeliveryStore(t, x, nil, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		return nil, nil
	})
	_, err := f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_removal_absence_dispatch_stops(request_id,reason) VALUES($1,'source_changed')`, r.ID)
	require.NoError(t, err)
	_, err = s.Verify(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.Zero(t, calls.Load())
	_, err = f.db.ExecContext(t.Context(), `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removal_absence_attempts(request_id,wire_version,certificate_hash,command_hash,issued_at,expires_at) SELECT $1,5,certificate_hash,repeat('f',64),stamp.at,stamp.at+interval '1 minute' FROM uem_agent_identities,stamp WHERE id=$2`, r.ID, f.id)
	require.ErrorContains(t, err, "dispatch was stopped")
	_, err = s.ReadDispatchStop(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.ReadDispatchStop(t.Context(), "missing", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	for _, guard := range [][2]string{{"uem_netbird_removal_absence_dispatch_stops", "uem_netbird_removal_absence_dispatch_stop_immutable"}, {"uem_netbird_removal_absence_dispatch_stops", "uem_netbird_removal_absence_dispatch_stop_valid"}, {"uem_netbird_removal_absence_attempts", "uem_netbird_removal_absence_dispatch_required"}} {
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` DISABLE TRIGGER `+guard[1])
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` ENABLE TRIGGER `+guard[1])
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}

func TestNetbirdAbsenceDispatchExpiresWithoutNativeInspection(t *testing.T) {
	x, _, r := absenceDeliveryFixture(t)
	f := x.f
	id := r.ID
	// Shorten only the owned request lifetime; original release proof stays intact.
	_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_absences DISABLE TRIGGER uem_netbird_removal_absence_immutable`)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_removal_absences SET expires_at=clock_timestamp() WHERE id=$1`, r.ID)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_absences ENABLE TRIGGER uem_netbird_removal_absence_immutable`)
	require.NoError(t, err)
	var calls atomic.Int32
	s := absenceDeliveryStore(t, x, func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		calls.Add(1)
		return nil, nil
	}, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		return nil, nil
	})
	worked, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.True(t, worked)
	require.Zero(t, calls.Load())
	stop, err := s.ReadDispatchStop(t.Context(), "viewer", f.scope, f.id, id, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "expired", stop.Reason)
	worked, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.False(t, worked)
}
