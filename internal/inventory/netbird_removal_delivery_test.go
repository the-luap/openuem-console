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
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func removalRequest(t *testing.T, f *refreshFixture, s *inventory.NetbirdRemovalStore) *inventory.NetbirdRemoval {
	t.Helper()
	review := removalReview(t, f, s)
	r, err := s.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), review.DescriptorDigest, review.Revision)
	require.NoError(t, err)
	return r
}

func removalDeliveryStore(t *testing.T, f *refreshFixture, control inventory.NetbirdOperationControl, execute inventory.NetbirdRemovalExecutor) *inventory.NetbirdRemovalStore {
	t.Helper()
	if control == nil {
		control = removalControl
	}
	s, err := inventory.NewNetbirdRemovalDeliveryStore(f.db, f.permissions, true, control, execute)
	require.NoError(t, err)
	return s
}

func TestNetbirdRemovalDeliveryCommitsExactCommandAndVerifiedCompletion(t *testing.T) {
	f, requests := removalFixture(t, nil)
	r := removalRequest(t, f, requests)
	var calls atomic.Int32
	s := removalDeliveryStore(t, f, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		require.Equal(t, netbirdcommand.RemovalVersion, c.Version)
		require.Equal(t, "uninstall", c.Operation)
		require.Equal(t, r.Descriptor, c.Removal)
		require.Equal(t, r.ID, c.RequestID)
		require.Equal(t, r.Revision, c.Revision)
		require.Equal(t, 10*time.Minute, c.ExpiresAt.Sub(c.IssuedAt))
		require.True(t, c.ExpiresAt.After(r.ExpiresAt))
		var hash string
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT command_hash FROM uem_netbird_removal_attempts WHERE request_id=$1`, r.ID).Scan(&hash))
		actual, err := c.Digest()
		require.NoError(t, err)
		require.Equal(t, actual, hash)
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND resource_id LIKE '%/uninstall/deliver'`, r.ID).Scan(&count))
		require.Equal(t, 1, count)
		_, err = requests.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_removals SET cancellation_id=$2,cancelled_by='tag-admin',cancelled_at=clock_timestamp() WHERE id=$1`, r.ID, uuid.NewString())
		require.Error(t, err)
		for _, query := range []string{
			`UPDATE uem_netbird_removals SET completed_at=clock_timestamp() WHERE id=$1`,
			`UPDATE uem_netbird_removal_attempts SET command_hash=repeat('a',64) WHERE request_id=$1`,
			`DELETE FROM uem_netbird_removal_attempts WHERE request_id=$1`,
		} {
			_, err = f.db.ExecContext(ctx, query, r.ID)
			require.Error(t, err, "direct SQL changed immutable admission or manufactured completion")
		}
		wrong, err := netbirdcommand.ReceiptFor(c, "unconfirmed")
		require.NoError(t, err)
		wrongData, err := netbirdcommand.EncodeReceipt(wrong)
		require.NoError(t, err)
		_, err = f.db.ExecContext(ctx, `INSERT INTO uem_netbird_removal_results(request_id,outcome,receipt) VALUES($1,'completed',$2::jsonb)`, r.ID, string(wrongData))
		require.Error(t, err, "uncertain receipt manufactured completion")
		receipt, err := netbirdcommand.ReceiptFor(c, "completed")
		return &receipt, err
	})
	d, err := s.Uninstall(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", d.Outcome)
	require.Equal(t, "completed", d.OriginalOutcome)
	require.NotNil(t, d.CompletedAt)
	require.NotNil(t, d.Receipt)
	got, err := s.Uninstall(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, d, got)
	require.EqualValues(t, 1, calls.Load())
	record, err := requests.Read(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, d.CompletedAt, record.CompletedAt)
	read, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, d, read)
	_, err = requests.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), r.DescriptorDigest, r.Revision)
	require.NoError(t, err, "completed removal retained device exclusion")
}

func TestNetbirdRemovalDeliveryRechecksReviewBeforeCreatingAttempt(t *testing.T) {
	for _, kind := range []string{"state", "absent", "journal", "certificate", "consumer", "revoked", "permission", "cancelled", "actor", "revision", "audit"} {
		t.Run(kind, func(t *testing.T) {
			f, requests := removalFixture(t, nil)
			r := removalRequest(t, f, requests)
			ctx := t.Context()
			control := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				response, err := removalControl(ctx, c)
				if err != nil {
					return nil, err
				}
				switch kind {
				case "state":
					response.Removal.StateDigest = strings.Repeat("a", 64)
				case "absent":
					response.Outcome = "absent"
					response.Removal = packageapi.Removal{}
				case "journal":
					response.State.Revision = strings.Repeat("a", 64)
				}
				return response, nil
			}
			calls := 0
			s := removalDeliveryStore(t, f, control, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls++
				return nil, errors.New("unexpected native delivery")
			})
			var err error
			actor, revision := "tag-admin", r.Revision
			switch kind {
			case "certificate":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET revision=revision+1 WHERE device_id=$1`, f.id)
			case "revoked":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "permission":
				p, e := f.permissions.Principal(ctx, actor)
				require.NoError(t, e)
				err = f.permissions.ReplaceGrants(ctx, "admin", actor, p.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
			case "cancelled":
				_, err = requests.Cancel(ctx, actor, f.scope, f.id, r.ID, revision, uuid.NewString())
			case "actor":
				actor = "operator"
			case "revision":
				revision = strings.Repeat("a", 64)
			case "audit":
				_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_attempt_failure CHECK(resource_id NOT LIKE '%/uninstall/deliver') NOT VALID`)
			}
			require.NoError(t, err)
			_, err = s.Uninstall(ctx, actor, f.scope, f.id, r.ID, revision)
			require.Error(t, err)
			require.Zero(t, calls)
			var count int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_removal_attempts`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdRemovalDeliveryRetainsAllUncertainResultsWithoutRetry(t *testing.T) {
	for _, kind := range []string{"error", "nil", "unconfirmed", "busy", "rejected", "withdrawn", "wrong-hash", "wrong-operation", "cancelled", "result-audit"} {
		t.Run(kind, func(t *testing.T) {
			f, requests := removalFixture(t, nil)
			r := removalRequest(t, f, requests)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			s := removalDeliveryStore(t, f, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls++
				if kind == "error" {
					return nil, errors.New("owned unavailable reply")
				}
				if kind == "nil" {
					return nil, nil
				}
				if kind == "cancelled" {
					cancel()
				}
				status := kind
				if status == "wrong-hash" || status == "wrong-operation" || status == "cancelled" || status == "result-audit" {
					status = "completed"
				}
				response, err := netbirdcommand.ReceiptFor(c, status)
				if kind == "wrong-hash" {
					response.CommandHash = strings.Repeat("a", 64)
				}
				if kind == "wrong-operation" {
					response.Operation = "install"
				}
				if kind == "result-audit" {
					_, e := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_result_failure CHECK(resource_id NOT LIKE '%/uninstall/result-%') NOT VALID`)
					require.NoError(t, e)
				}
				return &response, err
			})
			d, err := s.Uninstall(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
			if kind == "result-audit" {
				require.Error(t, err)
				require.Nil(t, d)
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_removal_result_failure`)
				require.NoError(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, "unconfirmed", d.Outcome)
				require.Nil(t, d.CompletedAt)
			}
			_, err = requests.Cancel(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			replayed, err := s.Uninstall(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			if kind == "result-audit" {
				require.Equal(t, "pending", replayed.Outcome)
			} else {
				require.Equal(t, d, replayed)
			}
			require.Equal(t, 1, calls)
			_, err = requests.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), r.DescriptorDigest, r.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		})
	}
}

func TestNetbirdRemovalConcurrentDeliveryReturnsPendingAndExcludesCancellation(t *testing.T) {
	f, requests := removalFixture(t, nil)
	r := removalRequest(t, f, requests)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := removalDeliveryStore(t, f, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		reply, err := netbirdcommand.ReceiptFor(c, "completed")
		return &reply, err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.Uninstall(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	pending, err := s.Uninstall(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Outcome)
	_, err = requests.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	close(release)
	require.NoError(t, <-done)
	require.EqualValues(t, 1, calls.Load())
}

func TestNetbirdRemovalObservationRecoversOriginalReceiptUnderCurrentCertificate(t *testing.T) {
	for _, kind := range []string{"completed", "unconfirmed", "missing", "absent-only", "wrong-hash", "wrong-operation", "result-pending"} {
		t.Run(kind, func(t *testing.T) {
			f, requests := removalFixture(t, nil)
			r := removalRequest(t, f, requests)
			var original netbirdcommand.Command
			var calls, observations atomic.Int32
			control := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				if c.Kind == "removal-state" {
					return removalControl(ctx, c)
				}
				observations.Add(1)
				require.Equal(t, netbirdcommand.RecoveryVersion, c.Version)
				require.Equal(t, "receipt", c.Kind)
				require.Equal(t, "uninstall", c.Operation)
				require.Equal(t, r.ID, c.ReferenceID)
				require.Equal(t, r.Revision, c.Revision)
				require.Equal(t, strings.Repeat("e", 64), c.CertificateHash)
				reply, _ := netbirdcommand.ControlResponseFor(c, "ok")
				status := kind
				if kind == "result-pending" {
					status = "completed"
				}
				if status == "wrong-hash" || status == "wrong-operation" {
					status = "completed"
				}
				if kind == "missing" {
					reply.Outcome = "missing"
				} else if kind == "absent-only" {
					reply.Outcome = "absent"
				} else {
					reply.Receipt, _ = netbirdcommand.ReceiptFor(original, status)
				}
				if kind == "wrong-hash" {
					reply.Receipt.CommandHash = strings.Repeat("a", 64)
				}
				if kind == "wrong-operation" {
					reply.Receipt.Operation = "install"
				}
				return &reply, nil
			}
			s := removalDeliveryStore(t, f, control, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				original = c
				if kind == "result-pending" {
					_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_observation_failure CHECK(resource_id NOT LIKE '%/uninstall/result-%') NOT VALID`)
					require.NoError(t, err)
				}
				return nil, errors.New("owned lost reply")
			})
			initial, err := s.Uninstall(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			if kind == "result-pending" {
				require.Error(t, err)
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_removal_observation_failure`)
				require.NoError(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, "unconfirmed", initial.Outcome)
			}
			_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
			require.NoError(t, err)
			observed, err := s.ObserveRemoval(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			if kind == "completed" || kind == "result-pending" {
				require.Equal(t, "completed", observed.Outcome)
				require.NotNil(t, observed.CompletedAt)
				require.Equal(t, "completed", observed.Receipt.Status)
			} else {
				require.Equal(t, "unconfirmed", observed.Outcome)
				require.Nil(t, observed.CompletedAt)
			}
			if kind == "result-pending" {
				require.Equal(t, "pending", observed.OriginalOutcome)
			} else {
				require.Equal(t, "unconfirmed", observed.OriginalOutcome)
			}
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_removal_observations WHERE request_id=$1`, r.ID).Scan(&count))
			require.Equal(t, 1, count)
			replayed, err := s.Uninstall(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			require.Equal(t, observed, replayed)
			require.EqualValues(t, 1, calls.Load())
			require.EqualValues(t, 1, observations.Load())
		})
	}
}
