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
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func netbirdResolutionResponse(t *testing.T, f *refreshFixture, c netbirdcommand.ControlRequest, status, release string) *netbirdcommand.ControlResponse {
	t.Helper()
	r, err := netbirdcommand.ControlResponseFor(c, "ok")
	require.NoError(t, err)
	r.Receipt = netbirdcommand.Receipt{Version: netbirdcommand.Version, RequestID: c.ReferenceID, DeviceID: c.DeviceID, CommandHash: c.CommandHash, Status: status}
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT revision,operation FROM uem_netbird_operations WHERE id=$1`, c.ReferenceID).Scan(&r.Receipt.Revision, &r.Receipt.Operation))
	r.ReleaseID = release
	require.True(t, r.Matches(c))
	return &r
}

// Older execution-store cases now resolve through positive retained agent
// evidence. A bare database-only Release cannot unblock an uncertain request.
func netbirdReleaseCompleted(t *testing.T, f *refreshFixture, s *inventory.NetbirdOperationStore, actor string, r *inventory.NetbirdOperation) error {
	t.Helper()
	resolver, err := inventory.NewNetbirdResolutionStore(s, func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		require.Equal(t, "receipt", c.Kind)
		return netbirdResolutionResponse(t, f, c, "completed", ""), nil
	})
	require.NoError(t, err)
	review, err := resolver.Review(t.Context(), actor, r.Scope, r.DeviceID, r.ID)
	if err != nil {
		return err
	}
	if review.Resolution != nil {
		_, err = resolver.Reconcile(t.Context(), actor, r.Scope, r.DeviceID, r.ID, review.Resolution.ID)
	} else {
		_, err = resolver.Resolve(t.Context(), actor, r.Scope, r.DeviceID, r.ID, uuid.NewString(), review.Revision)
	}
	return err
}

func TestNetbirdResolutionLostReplyAndImmutableIntent(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	var command inventory.NetbirdOperationCommand
	execute := func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		command = c
		return nil, errors.New("owned response loss")
	}
	inspect := func(_ context.Context, _ netbirdcommand.Identity) (netbirdcommand.State, error) {
		if command.RequestID == "" {
			return netbirdReady(ctx, netbirdcommand.Identity{})
		}
		hash, _ := command.Digest()
		return netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("e", 64), Remaining: 4095, PendingID: command.RequestID, PendingHash: hash, CanRelease: true}, nil
	}
	operations, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, false, inspect, execute)
	require.NoError(t, err)
	r := netbirdRequest(t, f, operations, "up", "")
	_, err = operations.DispatchOne(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, operations.Release(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID), inventory.ErrNetbirdOperationNotReady)
	var releases, queries atomic.Int64
	var releaseID string
	resolver, err := inventory.NewNetbirdResolutionStore(operations, func(call context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		require.True(t, c.Executable(c.Identity, time.Now()))
		require.Equal(t, f.id, c.DeviceID)
		if c.Kind == "release" {
			releases.Add(1)
			var id, hash string
			require.NoError(t, f.db.QueryRowContext(call, `SELECT id,control_hash FROM uem_netbird_resolutions WHERE request_id=$1`, r.ID).Scan(&id, &hash))
			digest, e := c.Digest()
			require.NoError(t, e)
			require.Equal(t, id, c.RequestID)
			require.Equal(t, digest, hash)
			releaseID = c.RequestID
			return nil, errors.New("owned lost release reply")
		}
		queries.Add(1)
		return netbirdResolutionResponse(t, f, c, "unconfirmed", releaseID), nil
	})
	require.NoError(t, err)
	for _, actor := range []string{"viewer", "operator", "missing"} {
		_, err = resolver.Review(ctx, actor, r.Scope, r.DeviceID, r.ID)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	require.Zero(t, queries.Load())
	review, err := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, review.CanRelease)
	id := uuid.NewString()
	first, err := resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, id, review.Revision)
	require.NoError(t, err)
	require.Nil(t, first.ConfirmedAt)
	require.Equal(t, int64(1), releases.Load())
	require.Nil(t, netbirdRead(t, f, operations, r.ID).ReleasedAt)
	_, err = f.db.ExecContext(ctx, `INSERT INTO uem_netbird_resolution_evidence(request_id,resolution_id,actor,control,response) SELECT request_id,id,actor,control,'{}'::jsonb FROM uem_netbird_resolutions WHERE request_id=$1`, r.ID)
	require.Error(t, err, "partial evidence must not authorize a database-only release")
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			d, e := resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, id, review.Revision)
			require.NoError(t, e)
			require.Equal(t, id, d.ID)
		})
	}
	wg.Wait()
	require.Equal(t, int64(1), releases.Load())
	_, err = resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = resolver.Resolve(ctx, "admin", r.Scope, r.DeviceID, r.ID, id, review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	confirmed, err := resolver.Reconcile(ctx, "admin", r.Scope, r.DeviceID, r.ID, id)
	require.NoError(t, err)
	require.NotNil(t, confirmed.ConfirmedAt)
	require.Equal(t, "admin", confirmed.ConfirmedBy)
	receipt := netbirdRead(t, f, operations, r.ID)
	require.Equal(t, "unconfirmed", receipt.Status)
	require.Nil(t, receipt.Result)
	require.NotNil(t, receipt.ReleasedAt)
	require.Equal(t, int64(1), releases.Load())
	for _, query := range []string{`DELETE FROM uem_netbird_resolutions`, `UPDATE uem_netbird_resolutions SET actor='admin'`, `DELETE FROM uem_netbird_resolution_evidence`, `UPDATE uem_netbird_resolution_evidence SET response='{}'::jsonb`, `UPDATE uem_netbird_operations SET released_by='tag-admin'`} {
		_, err = f.db.ExecContext(ctx, query)
		require.Error(t, err, query)
	}
}

func TestNetbirdResolutionCompletedEvidenceAndAuditRollback(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	s := netbirdStore(t, f, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		return nil, errors.New("owned lost command response")
	})
	r := netbirdRequest(t, f, s, "down", "")
	_, err := s.DispatchOne(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_resolution_failure CHECK(action<>'inventory.netbird.release') NOT VALID`)
	require.NoError(t, err)
	require.Error(t, netbirdReleaseCompleted(t, f, s, "tag-admin", r))
	var intents, evidence int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM uem_netbird_resolutions),(SELECT count(*) FROM uem_netbird_resolution_evidence)`).Scan(&intents, &evidence))
	require.Equal(t, 1, intents)
	require.Zero(t, evidence)
	require.Nil(t, netbirdRead(t, f, s, r.ID).ReleasedAt)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_resolution_failure`)
	require.NoError(t, err)
	require.NoError(t, netbirdReleaseCompleted(t, f, s, "admin", r))
	receipt := netbirdRead(t, f, s, r.ID)
	require.Equal(t, "unconfirmed", receipt.Status)
	require.NotNil(t, receipt.ReleasedAt)
	require.Nil(t, receipt.Result)
	_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_operations_audit SET created_at=clock_timestamp()-interval '45 days' WHERE action LIKE 'inventory.netbird.resolution.%' OR action='inventory.netbird.release'`)
	require.NoError(t, err)
	a, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	preview, err := a.PreviewRetention(ctx, "admin", access.Scope{TenantID: f.scope.TenantID}, 30)
	require.NoError(t, err)
	require.NoError(t, a.ApplyRetention(ctx, "admin", access.Scope{TenantID: f.scope.TenantID}, preview.ID, preview.Token))
	require.NoError(t, a.PruneRetention(ctx))
	require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(ctx))
	receipt = netbirdRead(t, f, s, r.ID)
	require.NotNil(t, receipt.Resolution)
	require.NotNil(t, receipt.Resolution.ConfirmedAt)
	require.Equal(t, "admin", receipt.Resolution.ConfirmedBy)
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM uem_netbird_resolutions),(SELECT count(*) FROM uem_netbird_resolution_evidence)`).Scan(&intents, &evidence))
	require.Equal(t, 1, intents)
	require.Equal(t, 1, evidence)
}

func TestNetbirdResolutionReviewAndAdmissionBoundaries(t *testing.T) {
	for _, change := range []string{"moved", "ambiguous", "disabled", "scope-aba", "foreign-release", "missing", "wrong-revision", "wrong-operation", "wrong-hash", "invalid-response", "expired-response", "audit-attempt"} {
		t.Run(change, func(t *testing.T) {
			f, _ := netbirdFixture(t)
			ctx := t.Context()
			s := netbirdStore(t, f, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				return nil, errors.New("owned loss")
			})
			r := netbirdRequest(t, f, s, "up", "")
			_, err := s.DispatchOne(ctx)
			require.NoError(t, err)
			changed := false
			resolver, err := inventory.NewNetbirdResolutionStore(s, func(call context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				require.Equal(t, "receipt", c.Kind, "ineligible resolution sent a mutation")
				p := netbirdResolutionResponse(t, f, c, "completed", "")
				if changed {
					switch change {
					case "foreign-release":
						p = netbirdResolutionResponse(t, f, c, "unconfirmed", uuid.NewString())
					case "missing":
						missing, e := netbirdcommand.ControlResponseFor(c, "missing")
						require.NoError(t, e)
						p = &missing
					case "wrong-revision":
						p.Receipt.Revision = strings.Repeat("c", 64)
					case "wrong-operation":
						p.Receipt.Operation = "down"
					case "wrong-hash":
						p.Receipt.CommandHash = strings.Repeat("c", 64)
					case "invalid-response":
						p.RequestID = uuid.NewString()
					case "expired-response":
						<-call.Done()
					}
				}
				return p, nil
			})
			require.NoError(t, err)
			review, err := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, review.CanRelease)
			changed = true
			switch change {
			case "moved":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(ctx))
			case "ambiguous":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx))
			case "disabled":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetAgentStatus(agent.AgentStatusDisabled).Exec(ctx))
			case "scope-aba":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx))
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.otherSite).Exec(ctx))
			case "audit-attempt":
				_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_resolution_failure CHECK(action<>'inventory.netbird.resolution.attempt') NOT VALID`)
				require.NoError(t, err)
			}
			_, err = resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), review.Revision)
			require.Error(t, err)
			var count int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_resolutions`).Scan(&count))
			require.Zero(t, count)
			require.Nil(t, netbirdRead(t, f, s, r.ID).ReleasedAt)
		})
	}
}

func TestNetbirdResolutionIndividualCurrentIdentityAfterLostReply(t *testing.T) {
	for _, change := range []string{"renewed", "revoked", "expired", "consumer", "moved", "withdraw-renewed", "withdraw-revoked", "withdraw-expired", "withdraw-consumer", "withdraw-moved", "withdraw-retry-renewed"} {
		t.Run(change, func(t *testing.T) {
			withdrawal := strings.HasPrefix(change, "withdraw-")
			change = strings.TrimPrefix(change, "withdraw-")
			retry := strings.HasPrefix(change, "retry-")
			change = strings.TrimPrefix(change, "retry-")
			f, _ := netbirdFixture(t)
			ctx := t.Context()
			identities, err := registry.NewStore(f.db, strings.Repeat("r", 32))
			require.NoError(t, err)
			require.NoError(t, identities.Migrate(ctx))
			_, err = identities.EnsureAuthority(ctx, f.scope.TenantID, "Owned resolution fixture", "https://uem.example.test", "admin", nil, nil)
			require.NoError(t, err)
			invite, err := identities.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: f.scope.TenantID, SiteID: f.scope.SiteID}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
			require.NoError(t, err)
			keys, err := enrollment.GenerateKeys()
			require.NoError(t, err)
			defer keys.Broker.Wipe()
			claim, err := keys.Request(invite.URL[strings.LastIndex(invite.URL, "/")+1:], "windows", "amd64", "Owned resolution endpoint")
			require.NoError(t, err)
			response, err := identities.Claim(ctx, *claim)
			require.NoError(t, err)
			f.id = response.DeviceID
			require.NoError(t, f.client.Agent.Create().SetID(f.id).SetHostname("Owned resolution endpoint").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
			require.NoError(t, f.client.Netbird.Create().SetOwnerID(f.id).SetInstalled(true).Exec(ctx))
			_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1`, f.id)
			require.NoError(t, err)
			var command inventory.NetbirdOperationCommand
			s, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, true, func(_ context.Context, i netbirdcommand.Identity) (netbirdcommand.State, error) {
				if command.RequestID == "" || withdrawal {
					return netbirdReady(ctx, i)
				}
				hash, _ := command.Digest()
				return netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("e", 64), Remaining: 4095, PendingID: command.RequestID, PendingHash: hash, CanRelease: true}, nil
			}, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				command = c
				return nil, errors.New("owned loss")
			})
			require.NoError(t, err)
			r := netbirdRequest(t, f, s, "up", "")
			_, err = s.DispatchOne(ctx)
			require.NoError(t, err)
			releaseID := ""
			queries, controls := 0, 0
			certificate := ""
			resolver, err := inventory.NewNetbirdResolutionStore(s, func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				if c.Kind == "release" || c.Kind == "withdraw" {
					controls++
					require.Empty(t, releaseID)
					if !retry || controls > 1 {
						releaseID = c.RequestID
					}
					return nil, errors.New("owned lost reply")
				}
				queries++
				certificate = c.CertificateHash
				if withdrawal {
					if releaseID == "" {
						p, e := netbirdcommand.ControlResponseFor(c, "missing")
						return &p, e
					}
					require.Equal(t, r.Revision, c.Revision)
					require.Equal(t, r.Operation, c.Operation)
					return netbirdResolutionResponse(t, f, c, "withdrawn", releaseID), nil
				}
				return netbirdResolutionResponse(t, f, c, "unconfirmed", releaseID), nil
			})
			require.NoError(t, err)
			review, err := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			d, err := resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), review.Revision)
			require.NoError(t, err)
			require.Nil(t, d.ConfirmedAt)
			if retry {
				review, err = resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, err)
				require.True(t, review.CanRetry)
			}
			before := queries
			switch change {
			case "renewed":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('a',64) WHERE id=$1`, f.id)
			case "revoked":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "expired":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
			case "moved":
				err = f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(ctx)
			}
			require.NoError(t, err)
			if retry {
				_, err = resolver.Retry(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), review.Revision)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationChanged)
				require.Equal(t, 1, controls)
				fresh, e := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, e)
				_, err = resolver.Retry(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), fresh.Revision)
				require.NoError(t, err)
				require.Equal(t, 2, controls)
				var retainedCertificate string
				require.NoError(t, f.db.QueryRowContext(ctx, `SELECT control->>'certificate_hash' FROM uem_netbird_resolution_retries WHERE request_id=$1`, r.ID).Scan(&retainedCertificate))
				require.Equal(t, strings.Repeat("a", 64), retainedCertificate)
				before = queries
			}
			result, err := resolver.Reconcile(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID)
			if change == "renewed" {
				require.NoError(t, err)
				require.NotNil(t, result.ConfirmedAt)
				require.Equal(t, strings.Repeat("a", 64), certificate)
				require.Equal(t, before+1, queries)
			} else {
				require.Error(t, err)
				require.Equal(t, before, queries)
				require.Nil(t, netbirdRead(t, f, s, r.ID).ReleasedAt)
			}
		})
	}
}

func TestNetbirdResolutionHoldsCurrentAuthorityUntilEvidenceCommit(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s := netbirdStore(t, f, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		return nil, errors.New("owned loss")
	})
	r := netbirdRequest(t, f, s, "up", "")
	_, err := s.DispatchOne(ctx)
	require.NoError(t, err)
	started, finish := make(chan struct{}), make(chan struct{})
	pause := false
	resolver, err := inventory.NewNetbirdResolutionStore(s, func(call context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if pause {
			close(started)
			select {
			case <-finish:
			case <-call.Done():
				return nil, call.Err()
			}
		}
		return netbirdResolutionResponse(t, f, c, "completed", ""), nil
	})
	require.NoError(t, err)
	review, err := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	pause = true
	done := make(chan error, 1)
	go func() {
		_, e := resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), review.Revision)
		done <- e
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	moved, revoked := make(chan error, 1), make(chan error, 1)
	go func() { moved <- f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx) }()
	go func() { revoked <- f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", 1, nil) }()
	netbirdWaitForLocks(t, ctx, f, 2)
	close(finish)
	require.NoError(t, <-done)
	require.NoError(t, <-moved)
	require.NoError(t, <-revoked)
	require.NotNil(t, netbirdRead(t, f, s, r.ID).ReleasedAt)
}

func TestNetbirdResolutionMigrationGuards(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	for _, guard := range [][2]string{{"uem_netbird_resolutions", "uem_netbird_resolution_immutable"}, {"uem_netbird_resolution_evidence", "uem_netbird_resolution_evidence_immutable"}, {"uem_netbird_resolution_evidence", "uem_netbird_resolution_evidence_valid"}, {"uem_netbird_operations", "uem_netbird_resolution_required"}} {
		_, err := f.db.ExecContext(ctx, `ALTER TABLE `+guard[0]+` DISABLE TRIGGER `+guard[1])
		require.NoError(t, err)
		require.ErrorContains(t, inventory.Migrate(ctx, f.db), "NetBird operation protection")
		_, err = f.db.ExecContext(ctx, `ALTER TABLE `+guard[0]+` ENABLE TRIGGER `+guard[1])
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(ctx, f.db))
	s := netbirdStore(t, f, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		return nil, errors.New("owned loss")
	})
	r := netbirdRequest(t, f, s, "up", "")
	_, err := s.DispatchOne(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_operations SET released_at=clock_timestamp(),released_by='tag-admin' WHERE id=$1`, r.ID)
	require.Error(t, err)
	_, err = f.db.ExecContext(ctx, `INSERT INTO uem_netbird_resolution_evidence(request_id,resolution_id,actor,control,response) VALUES($1,$2,'tag-admin','{}','{}')`, r.ID, uuid.NewString())
	require.Error(t, err)
}

func TestNetbirdResolutionDirectReleaseAndCancellation(t *testing.T) {
	for _, mode := range []string{"direct", "cancelled", "unjoined", "other-pending"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := netbirdFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var command inventory.NetbirdOperationCommand
			s, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, false, func(_ context.Context, i netbirdcommand.Identity) (netbirdcommand.State, error) {
				if command.RequestID == "" {
					return netbirdReady(ctx, i)
				}
				hash, _ := command.Digest()
				state := netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("e", 64), Remaining: 4095, PendingID: command.RequestID, PendingHash: hash, CanRelease: mode != "unjoined"}
				if mode == "other-pending" {
					state.PendingID = uuid.NewString()
				}
				return state, nil
			}, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				command = c
				return nil, errors.New("owned loss")
			})
			require.NoError(t, err)
			r := netbirdRequest(t, f, s, "up", "")
			_, err = s.DispatchOne(ctx)
			require.NoError(t, err)
			releases := 0
			releaseID := ""
			resolver, err := inventory.NewNetbirdResolutionStore(s, func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				if c.Kind == "release" {
					releases++
					releaseID = c.RequestID
					if mode == "cancelled" {
						cancel()
					}
				}
				return netbirdResolutionResponse(t, f, c, "unconfirmed", releaseID), nil
			})
			require.NoError(t, err)
			review, err := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			if mode == "unjoined" || mode == "other-pending" {
				require.False(t, review.CanRelease)
				require.Equal(t, "waiting", review.Outcome)
				return
			}
			id := uuid.NewString()
			d, err := resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, id, review.Revision)
			if mode == "cancelled" {
				require.Error(t, err)
				d, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, review.Revision)
				require.NoError(t, err)
				require.Nil(t, d.ConfirmedAt)
				d, err = resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id)
			}
			require.NoError(t, err)
			require.NotNil(t, d.ConfirmedAt)
			require.Equal(t, 1, releases)
			require.NotNil(t, netbirdRead(t, f, s, r.ID).ReleasedAt)
		})
	}
}
