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

func installationCapabilities(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
	if c.Kind != "preparation-state" && c.Kind != "installation-state" {
		return nil, errors.New("unexpected capability")
	}
	r, err := netbirdcommand.ControlResponseFor(c, "ok")
	if err != nil {
		return nil, err
	}
	r.State, err = netbirdReady(ctx, c.Identity)
	return &r, err
}

func preparationStore(t *testing.T, f *refreshFixture, control inventory.NetbirdOperationControl, execute inventory.NetbirdPreparationExecutor) *inventory.NetbirdInstallationStore {
	t.Helper()
	if control == nil {
		control = installationCapabilities
	}
	s, err := inventory.NewNetbirdInstallationPreparationStore(f.db, f.permissions, true, strings.Repeat("k", 32), control, execute)
	require.NoError(t, err)
	return s
}

func TestNetbirdPreparationCommitsExactIntentBeforeOneRPCAndRetainsPrivateHistory(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	var calls, probes atomic.Int32
	var sent netbirdcommand.PreparationRequest
	s := preparationStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		probes.Add(1)
		return installationCapabilities(ctx, c)
	}, func(ctx context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		calls.Add(1)
		sent = p
		require.Equal(t, pkg, p.Package)
		require.Equal(t, r.ID, p.RequestID)
		require.Equal(t, r.Revision, p.Revision)
		require.Equal(t, r.JournalRevision, p.JournalRevision)
		require.True(t, p.Individual)
		require.Equal(t, r.ExpiresAt.UTC(), p.ExpiresAt)
		var hash string
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT request_hash FROM uem_netbird_preparations WHERE request_id=$1`, r.ID).Scan(&hash))
		digest, err := p.Digest()
		require.NoError(t, err)
		require.Equal(t, hash, digest)
		var audits int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND action='inventory.netbird.attempt'`, r.ID).Scan(&audits))
		require.Equal(t, 1, audits)
		result, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &result, err
	})
	got, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "prepared", got.Outcome)
	require.NotNil(t, got.RecordedAt)
	require.EqualValues(t, 2, probes.Load())
	replay, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, got, replay)
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 2, probes.Load())
	read, err := s.ReadPreparation(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, got, read)
	data, err := json.Marshal(read)
	require.NoError(t, err)
	require.NotContains(t, string(data), "owned-installation-source")
	require.NotContains(t, string(data), sent.CertificateHash)
	var stored string
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT to_jsonb(p)::text || to_jsonb(r)::text FROM uem_netbird_preparations p JOIN uem_netbird_preparation_results r USING(request_id) WHERE request_id=$1`, r.ID).Scan(&stored))
	require.NotContains(t, stored, "owned-installation-source")
	require.NotContains(t, stored, "https://")
	_, err = s.ReadPreparation(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, r.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.Prepare(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.Prepare(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, strings.Repeat("f", 64))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.EqualValues(t, 1, calls.Load())
}

func TestNetbirdPreparationRequiresBothMatchingCapabilities(t *testing.T) {
	for _, kind := range []string{"ordinary", "missing-installation", "different-revision", "wrong-correlation", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f, requests, _, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var calls atomic.Int32
			s := preparationStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				response, err := installationCapabilities(ctx, c)
				switch kind {
				case "ordinary":
					response.Kind = "state"
				case "missing-installation":
					if c.Kind == "installation-state" {
						return nil, errors.New("unavailable")
					}
				case "different-revision":
					if c.Kind == "installation-state" {
						response.State.Revision = strings.Repeat("f", 64)
					}
				case "wrong-correlation":
					response.RequestID = uuid.NewString()
				case "cancelled":
					return nil, context.Canceled
				}
				return response, err
			}, func(context.Context, netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
				calls.Add(1)
				return nil, nil
			})
			_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationNotReady)
			require.Zero(t, calls.Load())
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_preparations`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdPreparationRechecksApprovalRecipientAndCancellation(t *testing.T) {
	for _, change := range []string{"revocation", "certificate", "consumer", "cancel", "journal", "permissions", "audit"} {
		t.Run(change, func(t *testing.T) {
			f, requests, packages, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var calls atomic.Int32
			s := preparationStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				result, err := installationCapabilities(ctx, c)
				if change == "journal" {
					result.State.Revision = strings.Repeat("e", 64)
				}
				return result, err
			}, func(context.Context, netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
				calls.Add(1)
				return nil, nil
			})
			var err error
			actor := "tag-admin"
			switch change {
			case "revocation":
				_, err = packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, pkg.ApprovalID, r.ApprovalDigest, uuid.NewString())
			case "certificate":
				_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
			case "cancel":
				_, err = requests.Cancel(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
			case "permissions":
				principal, readErr := f.permissions.Principal(t.Context(), actor)
				require.NoError(t, readErr)
				err = f.permissions.ReplaceGrants(t.Context(), "admin", actor, principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
			case "audit":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_preparation_audit_failure CHECK(action<>'inventory.netbird.attempt') NOT VALID`)
			}
			require.NoError(t, err)
			_, err = s.Prepare(t.Context(), actor, f.scope, f.id, r.ID, r.Revision)
			require.Error(t, err)
			require.Zero(t, calls.Load())
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_preparations`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdPreparationDoesNotRetainDatabaseLocksDuringDownload(t *testing.T) {
	f, requests, packages, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := preparationStore(t, f, nil, func(ctx context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		response, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &response, err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.Prepare(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("preparation did not start")
	}
	// An exact duplicate reads the committed pending attempt without another RPC.
	pending, err := s.Prepare(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Outcome)
	// Both mutations must finish while the remote download remains in flight.
	mutation, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	_, err = packages.Revoke(mutation, "tag-admin", access.Scope{TenantID: f.scope.TenantID}, pkg.ApprovalID, r.ApprovalDigest, uuid.NewString())
	require.NoError(t, err)
	cancelled, err := requests.Cancel(mutation, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.NoError(t, err)
	require.NotNil(t, cancelled.CancelledAt)
	close(release)
	require.NoError(t, <-done)
	after, err := requests.Read(ctx, "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, cancelled, after)
	retained, err := s.Prepare(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "prepared", retained.Outcome)
	require.EqualValues(t, 1, calls.Load())
}

func TestNetbirdPreparationUncertainRepliesNeverRedeliver(t *testing.T) {
	for _, kind := range []string{"prepared", "blocked", "conflict", "unavailable", "error", "nil", "wrong-hash", "wrong-identity", "cancel", "result-audit"} {
		t.Run(kind, func(t *testing.T) {
			f, requests, _, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			var calls atomic.Int32
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := preparationStore(t, f, nil, func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
				calls.Add(1)
				result, err := netbirdcommand.PreparationResponseFor(p, "prepared")
				switch kind {
				case "blocked", "conflict", "unavailable":
					result.Outcome = kind
				case "error":
					return nil, errors.New("owned private source diagnostic")
				case "nil":
					return nil, nil
				case "wrong-hash":
					result.RequestHash = strings.Repeat("f", 64)
				case "wrong-identity":
					result.CertificateHash = strings.Repeat("f", 64)
				case "cancel":
					cancel()
				case "result-audit":
					_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_preparation_result_failure CHECK(resource_id NOT LIKE '%/install/preparation-%') NOT VALID`)
				}
				return &result, err
			})
			got, err := s.Prepare(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision)
			want := kind
			if kind == "result-audit" {
				require.Error(t, err)
				want = "pending"
			} else {
				require.NoError(t, err)
				if kind != "prepared" && kind != "blocked" && kind != "conflict" && kind != "unavailable" {
					want = "unconfirmed"
				}
				require.Equal(t, want, got.Outcome)
			}
			replay, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			require.Equal(t, want, replay.Outcome)
			require.EqualValues(t, 1, calls.Load())
		})
	}
}

func TestNetbirdPreparationSQLGuardsAndMigrationVerification(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	s := preparationStore(t, f, nil, func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		result, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &result, err
	})
	_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	for _, query := range []string{
		`DELETE FROM uem_netbird_preparations`, `UPDATE uem_netbird_preparations SET request_hash=repeat('f',64)`,
		`DELETE FROM uem_netbird_preparation_results`, `UPDATE uem_netbird_preparation_results SET outcome='unconfirmed',response=NULL`,
		`INSERT INTO uem_netbird_preparations SELECT * FROM uem_netbird_preparations`,
	} {
		_, err = f.db.ExecContext(t.Context(), query)
		require.Error(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_preparation_results DISABLE TRIGGER uem_netbird_preparation_result_valid`)
	require.NoError(t, err)
	require.Error(t, inventory.Migrate(t.Context(), f.db))
}

func TestNetbirdPreparationDatabaseRejectsUncorrelatedResultsAndCancelledAdmission(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	var command netbirdcommand.PreparationRequest
	s := preparationStore(t, f, nil, func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		command = p
		_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_preparation_pending CHECK(resource_id NOT LIKE '%/install/preparation-%') NOT VALID`)
		require.NoError(t, err)
		response, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &response, err
	})
	_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.Error(t, err)
	response, err := netbirdcommand.PreparationResponseFor(command, "prepared")
	require.NoError(t, err)
	for _, change := range []string{"hash", "identity", "outcome", "extra", "null", "future"} {
		data, err := json.Marshal(response)
		require.NoError(t, err)
		var value map[string]any
		require.NoError(t, json.Unmarshal(data, &value))
		switch change {
		case "hash":
			value["request_hash"] = strings.Repeat("f", 64)
		case "identity":
			value["certificate_hash"] = strings.Repeat("f", 64)
		case "outcome":
			value["outcome"] = "unavailable"
		case "extra":
			value["source"] = "https://never-retain.example.test"
		case "null":
			value = nil
		}
		data, err = json.Marshal(value)
		require.NoError(t, err)
		recorded := time.Now().UTC()
		if change == "future" {
			recorded = recorded.Add(time.Minute)
		}
		_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_preparation_results(request_id,outcome,response,recorded_at) VALUES($1,'prepared',$2::jsonb,$3)`, r.ID, string(data), recorded)
		require.Error(t, err, change)
	}
	_, err = requests.Cancel(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.NoError(t, err)
	// A second reviewed request is cancelled before preparation admission. Even
	// direct SQL cannot create a download attempt after this cancellation.
	next := installationRequest(t, f, requests, pkg)
	_, err = requests.Cancel(t.Context(), "tag-admin", f.scope, f.id, next.ID, next.Revision, uuid.NewString())
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_preparations(request_id,wire_version,certificate_hash,request_hash,issued_at,expires_at) VALUES($1,1,$2,$3,clock_timestamp(),$4)`, next.ID, command.CertificateHash, strings.Repeat("e", 64), next.ExpiresAt)
	require.Error(t, err)
}

func TestNetbirdPreparationExpiryAndResultPersistenceDoNotRedeliver(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	_, err := f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, f.id)
	require.NoError(t, err)
	r := installationRequest(t, f, requests, pkg)
	var calls atomic.Int32
	s := preparationStore(t, f, nil, func(ctx context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.Equal(t, p.ExpiresAt, deadline)
		<-ctx.Done()
		// Even a callback that supplies a matching response after cancellation must
		// not make an expired ephemeral cache available for native admission.
		response, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &response, err
	})
	got, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", got.Outcome)
	replay, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, got, replay)
	require.EqualValues(t, 1, calls.Load())
}
