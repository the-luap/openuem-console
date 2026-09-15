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

func stageCleanupDeliveryFixture(t *testing.T) (*removalResolutionFixture, *inventory.NetbirdRemovalStageCleanupStore, *inventory.NetbirdRemovalStageCleanup) {
	t.Helper()
	x := stageCleanupFixture(t)
	s := stageCleanupStore(t, x, nil)
	r := stageCleanupRequest(t, x, s, stageCleanupReview(t, x, s))
	return x, s, r
}
func stageCleanupDeliveryStore(t *testing.T, x *removalResolutionFixture, control inventory.NetbirdOperationControl, execute inventory.NetbirdRemovalStageCleanupExecutor) *inventory.NetbirdRemovalStageCleanupStore {
	t.Helper()
	if control == nil {
		control = stageCleanupControl(t, x)
	}
	s, err := inventory.NewNetbirdRemovalStageCleanupDeliveryStore(x.f.db, x.f.permissions, true, control, execute)
	require.NoError(t, err)
	return s
}

func TestNetbirdStageCleanupDeliveryCommitsExactCommandAndVerifiedCompletion(t *testing.T) {
	x, requests, r := stageCleanupDeliveryFixture(t)
	f := x.f
	var calls atomic.Int32
	s := stageCleanupDeliveryStore(t, x, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		require.Equal(t, netbirdcommand.RemovalStageCleanupVersion, c.Version)
		require.Equal(t, "cleanup-removal-stage", c.Operation)
		require.Equal(t, r.StageCleanup, c.RemovalStageCleanup)
		require.Equal(t, r.ID, c.RequestID)
		require.Equal(t, r.Revision, c.Revision)
		require.NotEqual(t, c.Revision, c.RemovalStageCleanup.JournalRevision)
		require.Equal(t, r.JournalRevision, c.RemovalStageCleanup.JournalRevision)
		require.Equal(t, 5*time.Minute, c.ExpiresAt.Sub(c.IssuedAt))
		require.True(t, c.ExpiresAt.After(r.ExpiresAt))
		var hash string
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT command_hash FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=$1`, r.ID).Scan(&hash))
		actual, err := c.Digest()
		require.NoError(t, err)
		require.Equal(t, actual, hash)
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND resource_id LIKE '%/cleanup-removal-stage/deliver'`, r.ID).Scan(&count))
		require.Equal(t, 1, count)
		_, err = requests.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_removal_stage_cleanups SET cancellation_id=$2,cancelled_by='tag-admin',cancelled_at=clock_timestamp() WHERE id=$1`, r.ID, uuid.NewString())
		require.Error(t, err)
		for _, query := range []string{
			`UPDATE uem_netbird_removal_stage_cleanups SET completed_at=clock_timestamp() WHERE id=$1`,
			`UPDATE uem_netbird_removal_stage_cleanup_attempts SET command_hash=repeat('a',64) WHERE request_id=$1`,
			`DELETE FROM uem_netbird_removal_stage_cleanup_attempts WHERE request_id=$1`,
		} {
			_, err = f.db.ExecContext(ctx, query, r.ID)
			require.Error(t, err, "direct SQL changed immutable admission or manufactured completion")
		}
		wrong, err := netbirdcommand.ReceiptFor(c, "unconfirmed")
		require.NoError(t, err)
		wrongData, err := netbirdcommand.EncodeReceipt(wrong)
		require.NoError(t, err)
		_, err = f.db.ExecContext(ctx, `INSERT INTO uem_netbird_removal_stage_cleanup_results(request_id,outcome,receipt) VALUES($1,'completed',$2::jsonb)`, r.ID, string(wrongData))
		require.Error(t, err, "uncertain receipt manufactured completion")
		receipt, err := netbirdcommand.ReceiptFor(c, "completed")
		return &receipt, err
	})
	d, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", d.Outcome)
	original, err := x.requests.Read(t.Context(), "viewer", f.scope, f.id, x.r.ID)
	require.NoError(t, err)
	require.Nil(t, original.CompletedAt)
	require.Equal(t, x.releaseID, original.ResolutionID)
	require.NotNil(t, original.ReleasedAt)
	require.Equal(t, 1, x.native)

	require.Equal(t, "completed", d.OriginalOutcome)
	require.NotNil(t, d.CompletedAt)
	require.NotNil(t, d.Receipt)
	got, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, d, got)
	require.EqualValues(t, 1, calls.Load())
	record, err := requests.Read(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, d.CompletedAt, record.CompletedAt)
	read, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, d, read)
	_, err = requests.Request(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), r.StageCleanupDigest, r.Revision)
	require.NoError(t, err, "completed removal retained device exclusion")
}

func TestNetbirdStageCleanupDeliveryRechecksReviewBeforeCreatingAttempt(t *testing.T) {
	for _, kind := range []string{"state", "absent", "journal", "certificate", "consumer", "revoked", "permission", "cancelled", "actor", "revision", "audit"} {
		t.Run(kind, func(t *testing.T) {
			x, requests, r := stageCleanupDeliveryFixture(t)
			f := x.f
			ctx := t.Context()
			control := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				response, err := stageCleanupControl(t, x)(ctx, c)
				if err != nil {
					return nil, err
				}
				switch kind {
				case "state":
					response.RemovalStageCleanup.StateDigest = strings.Repeat("a", 64)
				case "absent":
					response.Outcome = "absent"
					response.RemovalStageCleanup = netbirdcommand.RemovalStageCleanup{}
				case "journal":
					response.State.Revision = strings.Repeat("a", 64)
					response.RemovalStageCleanup.JournalRevision = response.State.Revision
				}
				return response, nil
			}
			calls := 0
			s := stageCleanupDeliveryStore(t, x, control, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
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
				_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_attempt_failure CHECK(resource_id NOT LIKE '%/cleanup-removal-stage/deliver') NOT VALID`)
			}
			require.NoError(t, err)
			_, err = s.Cleanup(ctx, actor, f.scope, f.id, r.ID, revision)
			require.Error(t, err)
			require.Zero(t, calls)
			var count int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_removal_stage_cleanup_attempts`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdStageCleanupDeliveryRetainsAllUncertainResultsWithoutRetry(t *testing.T) {
	for _, kind := range []string{"error", "nil", "unconfirmed", "busy", "rejected", "withdrawn", "wrong-hash", "wrong-operation", "cancelled", "result-audit"} {
		t.Run(kind, func(t *testing.T) {
			x, requests, r := stageCleanupDeliveryFixture(t)
			f := x.f
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			s := stageCleanupDeliveryStore(t, x, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
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
					_, e := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_result_failure CHECK(resource_id NOT LIKE '%/cleanup-removal-stage/result-%') NOT VALID`)
					require.NoError(t, e)
				}
				return &response, err
			})
			d, err := s.Cleanup(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
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
			replayed, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			if kind == "result-audit" {
				require.Equal(t, "pending", replayed.Outcome)
			} else {
				require.Equal(t, d, replayed)
			}
			require.Equal(t, 1, calls)
			_, err = requests.Request(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), r.StageCleanupDigest, r.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		})
	}
}

func TestNetbirdStageCleanupConcurrentDeliveryReturnsPendingAndExcludesCancellation(t *testing.T) {
	x, requests, r := stageCleanupDeliveryFixture(t)
	f := x.f
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := stageCleanupDeliveryStore(t, x, nil, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
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
	go func() { _, err := s.Cleanup(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	pending, err := s.Cleanup(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Outcome)
	_, err = requests.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	close(release)
	require.NoError(t, <-done)
	require.EqualValues(t, 1, calls.Load())
}

func TestNetbirdStageCleanupObservationRecoversOriginalReceiptUnderCurrentCertificate(t *testing.T) {
	for _, kind := range []string{"completed", "unconfirmed", "missing", "absent-only", "wrong-hash", "wrong-operation", "result-pending"} {
		t.Run(kind, func(t *testing.T) {
			x, _, r := stageCleanupDeliveryFixture(t)
			f := x.f
			var original netbirdcommand.Command
			var calls, observations atomic.Int32
			control := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				if c.Kind == "removal-stage-cleanup-state" {
					return stageCleanupControl(t, x)(ctx, c)
				}
				observations.Add(1)
				require.Equal(t, netbirdcommand.RecoveryVersion, c.Version)
				require.Equal(t, "receipt", c.Kind)
				require.Equal(t, "cleanup-removal-stage", c.Operation)
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
			s := stageCleanupDeliveryStore(t, x, control, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				original = c
				if kind == "result-pending" {
					_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_observation_failure CHECK(resource_id NOT LIKE '%/cleanup-removal-stage/result-%') NOT VALID`)
					require.NoError(t, err)
				}
				return nil, errors.New("owned lost reply")
			})
			initial, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
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
			observed, err := s.ObserveStageCleanup(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
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
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_removal_stage_cleanup_observations WHERE request_id=$1`, r.ID).Scan(&count))
			require.Equal(t, 1, count)
			replayed, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			require.Equal(t, observed, replayed)
			require.EqualValues(t, 1, calls.Load())
			require.EqualValues(t, 1, observations.Load())
		})
	}
}

func TestNetbirdStageCleanupObservationCompletionSurvivesLateUnconfirmedDelivery(t *testing.T) {
	x, _, r := stageCleanupDeliveryFixture(t)
	f := x.f
	entered := make(chan netbirdcommand.Command, 1)
	release := make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var command netbirdcommand.Command
	var queries atomic.Int32
	s := stageCleanupDeliveryStore(t, x, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if c.Kind == "removal-stage-cleanup-state" {
			return stageCleanupControl(t, x)(ctx, c)
		}
		queries.Add(1)
		p, err := netbirdcommand.ControlResponseFor(c, "ok")
		p.Receipt, _ = netbirdcommand.ReceiptFor(command, "completed")
		return &p, err
	}, func(ctx context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		entered <- c
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, errors.New("owned late lost reply")
	})
	type result struct {
		d   *inventory.NetbirdRemovalStageCleanupDelivery
		err error
	}
	done := make(chan result, 1)
	go func() { d, err := s.Cleanup(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision); done <- result{d, err} }()
	select {
	case command = <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	observed, err := s.ObserveStageCleanup(ctx, "operator", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", observed.Outcome)
	require.Equal(t, "pending", observed.OriginalOutcome)
	close(release)
	var finished result
	select {
	case finished = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, finished.err)
	require.Equal(t, "completed", finished.d.Outcome)
	require.Equal(t, "unconfirmed", finished.d.OriginalOutcome)
	require.Equal(t, observed.CompletedAt, finished.d.CompletedAt)
	require.Equal(t, observed.Receipt, finished.d.Receipt)
	again, err := s.ObserveStageCleanup(ctx, "operator", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, finished.d, again)
	require.EqualValues(t, 1, queries.Load())
	var original string
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT outcome FROM uem_netbird_removal_results WHERE request_id=$1`, x.r.ID).Scan(&original))
	require.Equal(t, "unconfirmed", original)
}

func TestNetbirdStageCleanupObservationAuditAndScopeCannotManufactureCompletion(t *testing.T) {
	x, _, r := stageCleanupDeliveryFixture(t)
	f := x.f
	var command netbirdcommand.Command
	var queries atomic.Int32
	s := stageCleanupDeliveryStore(t, x, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if c.Kind == "removal-stage-cleanup-state" {
			return stageCleanupControl(t, x)(ctx, c)
		}
		queries.Add(1)
		p, err := netbirdcommand.ControlResponseFor(c, "ok")
		p.Receipt, _ = netbirdcommand.ReceiptFor(command, "completed")
		return &p, err
	}, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		command = c
		return nil, errors.New("owned lost reply")
	})
	d, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	for _, kind := range []string{"scope", "permission", "revision", "device", "request"} {
		actor, scope, device, id, revision := "operator", f.scope, f.id, r.ID, r.Revision
		switch kind {
		case "scope":
			scope.SiteID = f.otherSite
		case "permission":
			actor = "viewer"
		case "revision":
			revision = strings.Repeat("a", 64)
		case "device":
			device = uuid.NewString()
		case "request":
			id = x.r.ID
		}
		_, err := s.ObserveStageCleanup(t.Context(), actor, scope, device, id, revision)
		require.Error(t, err, kind)
	}
	require.Zero(t, queries.Load())
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_stage_cleanup_observe_failure CHECK(action<>'inventory.netbird.resolution.observe') NOT VALID`)
	require.NoError(t, err)
	_, err = s.ObserveStageCleanup(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
	require.Error(t, err)
	got, err := s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, d, got)
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_removal_stage_cleanup_observations`).Scan(&count))
	require.Zero(t, count)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_stage_cleanup_observe_failure`)
	require.NoError(t, err)
	got, err = s.ObserveStageCleanup(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", got.Outcome)
	require.Equal(t, "unconfirmed", got.OriginalOutcome)
}

func TestNetbirdStageCleanupDeliveryStartupAndRetainedEvidenceGuards(t *testing.T) {
	x, _, r := stageCleanupDeliveryFixture(t)
	f := x.f
	s := stageCleanupDeliveryStore(t, x, nil, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		p, err := netbirdcommand.ReceiptFor(c, "unconfirmed")
		return &p, err
	})
	_, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	for _, pair := range [][2]string{
		{"attempts", "attempt"}, {"results", "result"}, {"observations", "observation"},
	} {
		table := "uem_netbird_removal_stage_cleanup_" + pair[0]
		for _, suffix := range []string{"immutable", "valid"} {
			guard := "uem_netbird_removal_stage_cleanup_" + pair[1] + "_" + suffix
			_, err := f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` DISABLE TRIGGER `+guard)
			require.NoError(t, err)
			require.Error(t, inventory.Migrate(t.Context(), f.db))
			_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` ENABLE TRIGGER `+guard)
			require.NoError(t, err)
		}
		_, err := f.db.ExecContext(t.Context(), `DELETE FROM `+table)
		if pair[0] != "observations" {
			require.Error(t, err)
		}
	}
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanups DISABLE TRIGGER uem_netbird_removal_stage_cleanup_completion_valid`)
	require.NoError(t, err)
	require.Error(t, inventory.Migrate(t.Context(), f.db))
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanups ENABLE TRIGGER uem_netbird_removal_stage_cleanup_completion_valid`)
	require.NoError(t, err)
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
	// Corrupt only this disposable fixture to verify that reads reconstruct the
	// complete historical command rather than trusting a well-shaped hash.
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanup_attempts DISABLE TRIGGER uem_netbird_removal_stage_cleanup_attempt_immutable`)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_removal_stage_cleanup_attempts SET certificate_hash=repeat('e',64)`)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanup_attempts ENABLE TRIGGER uem_netbird_removal_stage_cleanup_attempt_immutable`)
	require.NoError(t, err)
	var calls atomic.Int32
	s = stageCleanupDeliveryStore(t, x, func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		calls.Add(1)
		return nil, errors.New("unexpected query")
	}, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		return nil, errors.New("unexpected native execution")
	})
	_, err = s.ReadDelivery(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = s.ObserveStageCleanup(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.Zero(t, calls.Load())
}

func TestNetbirdStageCleanupObservationSQLRejectsForeignAndMalformedEvidence(t *testing.T) {
	x, _, r := stageCleanupDeliveryFixture(t)
	f := x.f
	var command netbirdcommand.Command
	s := stageCleanupDeliveryStore(t, x, nil, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		command = c
		return nil, nil
	})
	d, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	for _, kind := range []string{"control-operation", "control-reference", "control-revision", "control-source", "receipt-operation", "receipt-reference", "receipt-revision", "receipt-hash", "receipt-null", "receipt-source", "response-hash", "response-source", "release", "outcome", "timestamp", "valid"} {
		q := netbirdcommand.ControlRequest{Version: netbirdcommand.RecoveryVersion, Identity: command.Identity, RequestID: uuid.NewString(), Kind: "receipt", ReferenceID: r.ID, CommandHash: d.CommandHash, Revision: r.Revision, Operation: "cleanup-removal-stage", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(2 * time.Second)}
		p, err := netbirdcommand.ControlResponseFor(q, "ok")
		require.NoError(t, err)
		p.Receipt, err = netbirdcommand.ReceiptFor(command, "completed")
		require.NoError(t, err)
		control, err := netbirdcommand.EncodeControl(q)
		require.NoError(t, err)
		response, err := netbirdcommand.EncodeControlResponse(q, p)
		require.NoError(t, err)
		hash, err := q.Digest()
		require.NoError(t, err)
		var c, v map[string]any
		require.NoError(t, json.Unmarshal(control, &c))
		require.NoError(t, json.Unmarshal(response, &v))
		receipt := v["receipt"].(map[string]any)
		switch kind {
		case "control-operation":
			c["operation"] = "uninstall"
		case "control-reference":
			c["reference_id"] = x.r.ID
		case "control-revision":
			c["revision"] = r.JournalRevision
		case "control-source":
			c["url"] = "https://owned.test/private"
		case "receipt-operation":
			receipt["operation"] = "uninstall"
		case "receipt-reference":
			receipt["request_id"] = x.r.ID
		case "receipt-revision":
			receipt["revision"] = r.JournalRevision
		case "receipt-hash":
			receipt["command_hash"] = strings.Repeat("e", 64)
		case "receipt-null":
			v["receipt"] = nil
		case "receipt-source":
			receipt["url"] = "https://owned.test/private"
		case "response-hash":
			v["request_hash"] = strings.Repeat("e", 64)
		case "response-source":
			v["url"] = "https://owned.test/private"
		case "release":
			v["release_id"] = x.releaseID
		case "outcome":
			v["outcome"] = "absent"
		case "timestamp":
			c["expires_at"] = q.IssuedAt
		}
		control, err = json.Marshal(c)
		require.NoError(t, err)
		response, err = json.Marshal(v)
		require.NoError(t, err)
		_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_removal_stage_cleanup_observations(id,request_id,actor,control_hash,control,response) VALUES($1,$2,'operator',$3,$4::jsonb,$5::jsonb)`, q.RequestID, r.ID, hash, string(control), string(response))
		if kind == "valid" {
			require.NoError(t, err)
		} else {
			require.Error(t, err, kind)
		}
	}
	for _, query := range []string{`UPDATE uem_netbird_removal_stage_cleanup_observations SET actor='admin'`, `DELETE FROM uem_netbird_removal_stage_cleanup_observations`} {
		_, err := f.db.ExecContext(t.Context(), query)
		require.Error(t, err)
	}
}

func TestNetbirdStageCleanupDeliveryExpiryDoesNotGrantReplayOrFreeDevice(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unattempted", true: "retained"}[attempted], func(t *testing.T) {
			x, requests, r := stageCleanupDeliveryFixture(t)
			f := x.f
			var calls atomic.Int32
			s := stageCleanupDeliveryStore(t, x, nil, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				return nil, nil
			})
			if attempted {
				_, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
				require.NoError(t, err)
			}
			// Shorten only the owned fixture's request lifetime; neither its command
			// nor its original uninstall evidence changes.
			_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanups DISABLE TRIGGER uem_netbird_removal_stage_cleanup_immutable`)
			require.NoError(t, err)
			_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_removal_stage_cleanups SET expires_at=clock_timestamp()`)
			require.NoError(t, err)
			_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanups ENABLE TRIGGER uem_netbird_removal_stage_cleanup_immutable`)
			require.NoError(t, err)
			s = stageCleanupDeliveryStore(t, x, func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				calls.Add(1)
				return nil, errors.New("unexpected inspection")
			}, func(context.Context, netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				calls.Add(1)
				return nil, errors.New("unexpected delivery")
			})
			got, err := s.Cleanup(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			if attempted {
				require.NoError(t, err)
				require.Equal(t, "unconfirmed", got.Outcome)
				require.EqualValues(t, 1, calls.Load())
			} else {
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
				require.Zero(t, calls.Load())
			}
			_, err = requests.Request(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), r.StageCleanupDigest, r.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		})
	}
}
