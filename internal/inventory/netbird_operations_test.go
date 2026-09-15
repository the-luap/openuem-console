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
	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/nats/netbirdstate"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/settings"
	"github.com/stretchr/testify/require"
)

func netbirdFixture(t *testing.T) (*refreshFixture, int) {
	t.Helper()
	f, _ := tagFixture(t)
	store, err := settings.NewNetbirdStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(t.Context()))
	provider, err := f.client.NetbirdSettings.Create().SetManagementURL("https://management.example.test").SetAccessToken("private-provider-token").Save(t.Context())
	require.NoError(t, err)
	require.NoError(t, f.client.Tenant.UpdateOneID(f.scope.TenantID).SetNetbirdID(provider.ID).Exec(t.Context()))
	profiles, err := netbirdstate.Encode(nats.Netbird{ProfileDetails: []nats.NetbirdProfile{{ID: "owned-id", Name: "Office, Berlin", Active: true}, {ID: "other-id", Name: "Office, Berlin"}}})
	require.NoError(t, err)
	require.NoError(t, f.client.Netbird.Create().SetOwnerID(f.id).SetInstalled(true).SetProfilesAvailable(profiles).Exec(t.Context()))
	return f, provider.ID
}

func netbirdSuccess(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
	digest, err := c.Digest()
	if err != nil {
		return nil, err
	}
	return &inventory.NetbirdOperationResult{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, Operation: c.Operation, Success: true, CommandHash: digest}, nil
}

func netbirdStore(t *testing.T, f *refreshFixture, execute inventory.NetbirdOperationExecutor) *inventory.NetbirdOperationStore {
	t.Helper()
	if execute == nil {
		execute = netbirdSuccess
	}
	s, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, false, netbirdReady, execute)
	require.NoError(t, err)
	return s
}

func netbirdReady(_ context.Context, identity netbirdcommand.Identity) (netbirdcommand.State, error) {
	return netbirdcommand.State{Status: "ready", Revision: strings.Repeat("d", 64), Remaining: netbirdcommand.MaxJournalAttempts}, nil
}

func netbirdRequest(t *testing.T, f *refreshFixture, s *inventory.NetbirdOperationStore, operation, profile string) *inventory.NetbirdOperation {
	t.Helper()
	review, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, operation, profile)
	require.NoError(t, err)
	r, err := s.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), operation, profile, review.Revision)
	require.NoError(t, err)
	return r
}

func netbirdRead(t *testing.T, f *refreshFixture, s *inventory.NetbirdOperationStore, id string) *inventory.NetbirdOperation {
	t.Helper()
	r, err := s.Read(t.Context(), "viewer", f.scope, f.id, id)
	require.NoError(t, err)
	return r
}

func TestNetbirdOperationsScopeReviewDispatchAndHistory(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	sent := 0
	s := netbirdStore(t, f, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		sent++
		require.Equal(t, f.id, c.DeviceID)
		require.Equal(t, 2*time.Minute, c.ExpiresAt.Sub(c.IssuedAt))
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.Equal(t, c.ExpiresAt, deadline)
		var attempts int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operation_attempts WHERE request_id=$1`, c.RequestID).Scan(&attempts))
		require.Equal(t, 1, attempts)
		var hash string
		var expiry time.Time
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT command_hash,command_expires_at FROM uem_netbird_operation_attempts WHERE request_id=$1`, c.RequestID).Scan(&hash, &expiry))
		expected, err := c.Digest()
		require.NoError(t, err)
		require.Equal(t, expected, hash)
		require.True(t, c.ExpiresAt.Equal(expiry))
		return netbirdSuccess(ctx, c)
	})
	for _, actor := range []string{"viewer", "operator", "tag-viewer", "tag-operator", "missing"} {
		_, err := s.Review(ctx, actor, f.scope, f.id, "up", "")
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, scope := range []access.Scope{{}, {TenantID: f.scope.TenantID}, {TenantID: f.scope.TenantID, SiteID: f.otherSite}} {
		_, err := s.Review(ctx, "admin", scope, f.id, "up", "")
		require.Error(t, err)
	}
	for _, input := range [][2]string{{"register", ""}, {"up", "unexpected"}, {"down", "unexpected"}, {"switchprofile", ""}, {"switchprofile", "\n"}, {"switchprofile", "Office, Berlin"}} {
		_, err := s.Review(ctx, "admin", f.scope, f.id, input[0], input[1])
		require.Error(t, err)
	}
	review, err := s.Review(ctx, "tag-admin", f.scope, f.id, "switchprofile", "other-id")
	require.NoError(t, err)
	require.Equal(t, "Office, Berlin", review.ProfileName)
	require.Len(t, review.Revision, 64)
	for _, input := range [][2]string{{"up", ""}, {"down", ""}, {"switchprofile", "other-id"}} {
		r := netbirdRequest(t, f, s, input[0], input[1])
		require.Equal(t, "queued", r.Status)
		again, err := s.Request(ctx, r.Actor, r.Scope, r.DeviceID, r.ID, r.Operation, r.Profile, r.Revision)
		require.NoError(t, err)
		require.Equal(t, r.ID, again.ID)
		_, err = s.Request(ctx, "admin", r.Scope, r.DeviceID, r.ID, r.Operation, r.Profile, r.Revision)
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		_, err = s.Request(ctx, r.Actor, r.Scope, r.DeviceID, uuid.NewString(), r.Operation, r.Profile, r.Revision)
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		worked, err := s.DispatchOne(ctx)
		require.NoError(t, err)
		require.True(t, worked)
		receipt := netbirdRead(t, f, s, r.ID)
		require.Equal(t, "completed", receipt.Status)
		require.NotNil(t, receipt.Result)
		require.NotNil(t, receipt.AttemptedAt)
		require.Equal(t, receipt.Result.CommandHash, receipt.CommandHash)
		require.NotNil(t, receipt.CommandExpiresAt)
		again, err = s.Request(ctx, r.Actor, r.Scope, r.DeviceID, r.ID, r.Operation, r.Profile, r.Revision)
		require.NoError(t, err)
		require.Equal(t, "completed", again.Status)
		require.ErrorIs(t, s.Cancel(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID), inventory.ErrNetbirdOperationConflict)
		require.ErrorIs(t, s.Release(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID), inventory.ErrNetbirdOperationConflict)
	}
	require.Equal(t, 3, sent)
	worked, err := s.DispatchOne(ctx)
	require.NoError(t, err)
	require.False(t, worked)
	history, err := s.History(ctx, "viewer", f.scope, f.id, "")
	require.NoError(t, err)
	require.Len(t, history, 3)
	rest, err := s.History(ctx, "viewer", f.scope, f.id, history[0].ID)
	require.NoError(t, err)
	require.Len(t, rest, 2)
	require.Equal(t, history[1].ID, rest[0].ID)
	_, err = s.Read(ctx, "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, history[0].ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.History(ctx, "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, history[0].ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	a, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	data, err := a.ExportJSON(ctx, "tag-admin", audit.Filter{Scope: f.scope, Source: "netbird-operations", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	require.Contains(t, string(data), "inventory.netbird.completed")
	require.Contains(t, string(data), history[0].ID)
	for _, secret := range []string{"private-provider-token", "management.example.test", "Office, Berlin", "other-id"} {
		require.NotContains(t, string(data), secret)
	}
	require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(ctx))
	retained := netbirdRead(t, f, s, history[0].ID)
	require.Equal(t, "completed", retained.Status)
	again, err := s.Request(ctx, retained.Actor, retained.Scope, retained.DeviceID, retained.ID, retained.Operation, retained.Profile, retained.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", again.Status)
}

func TestNetbirdOperationsUncertaintyBarrierAndExplicitRelease(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	for _, outcome := range []string{"error", "empty", "wrong-request", "wrong-device", "wrong-revision", "wrong-operation", "unsuccessful", "missing-hash", "wrong-hash"} {
		t.Run(outcome, func(t *testing.T) {
			sent := 0
			s := netbirdStore(t, f, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				sent++
				r, _ := netbirdSuccess(ctx, c)
				switch outcome {
				case "error":
					return nil, errors.New("private transport detail")
				case "empty":
					return nil, nil
				case "wrong-request":
					r.RequestID = uuid.NewString()
				case "wrong-device":
					r.DeviceID = "other-device"
				case "wrong-revision":
					r.Revision = strings.Repeat("b", 64)
				case "wrong-operation":
					r.Operation = "down"
				case "unsuccessful":
					r.Success = false
				case "missing-hash":
					r.CommandHash = ""
				case "wrong-hash":
					r.CommandHash = strings.Repeat("f", 64)
				}
				return r, nil
			})
			r := netbirdRequest(t, f, s, "up", "")
			_, err := s.DispatchOne(ctx)
			require.NoError(t, err)
			receipt := netbirdRead(t, f, s, r.ID)
			require.Equal(t, "unconfirmed", receipt.Status)
			require.Nil(t, receipt.Result)
			_, err = s.Request(ctx, r.Actor, r.Scope, r.DeviceID, uuid.NewString(), r.Operation, r.Profile, r.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			require.ErrorIs(t, s.Release(ctx, "viewer", r.Scope, r.DeviceID, r.ID), access.ErrDenied)
			require.NoError(t, netbirdReleaseCompleted(t, f, s, "tag-admin", r))
			require.NoError(t, s.Release(ctx, "admin", r.Scope, r.DeviceID, r.ID))
			receipt = netbirdRead(t, f, s, r.ID)
			require.Equal(t, "unconfirmed", receipt.Status)
			require.NotNil(t, receipt.ReleasedAt)
			require.Equal(t, "tag-admin", receipt.ReleasedBy)
			_, err = s.DispatchOne(ctx)
			require.NoError(t, err)
			require.Equal(t, 1, sent)
		})
	}
	r := netbirdRequest(t, f, netbirdStore(t, f, nil), "down", "")
	require.Equal(t, "queued", r.Status)
}

func TestNetbirdOperationsSourceGenerationRejectsABA(t *testing.T) {
	changes := []string{"membership", "eligibility", "platform", "provider", "provider-link", "site-tenant", "recreated-device", "installation"}
	for _, change := range changes {
		t.Run(change, func(t *testing.T) {
			f, providerID := netbirdFixture(t)
			ctx := t.Context()
			s := netbirdStore(t, f, nil)
			review, err := s.Review(ctx, "tag-admin", f.scope, f.id, "up", "")
			require.NoError(t, err)
			switch change {
			case "membership":
				_, err = f.db.ExecContext(ctx, `UPDATE site_agents SET site_id=$2 WHERE agent_id=$1`, f.id, f.otherSite)
				require.NoError(t, err)
				_, err = f.db.ExecContext(ctx, `UPDATE site_agents SET site_id=$2 WHERE agent_id=$1`, f.id, f.scope.SiteID)
				require.NoError(t, err)
			case "eligibility":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetAgentStatus(agent.AgentStatusDisabled).Exec(ctx))
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetAgentStatus(agent.AgentStatusEnabled).Exec(ctx))
			case "platform":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetOs("linux").Exec(ctx))
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetOs("windows").Exec(ctx))
			case "installation":
				_, err = f.db.ExecContext(ctx, `UPDATE netbirds SET installed=false WHERE agent_netbird=$1`, f.id)
				require.NoError(t, err)
				_, err = f.db.ExecContext(ctx, `UPDATE netbirds SET installed=true WHERE agent_netbird=$1`, f.id)
				require.NoError(t, err)
			case "provider":
				require.NoError(t, f.client.NetbirdSettings.UpdateOneID(providerID).SetAccessToken("changed-token").Exec(ctx))
				require.NoError(t, f.client.NetbirdSettings.UpdateOneID(providerID).SetAccessToken("private-provider-token").Exec(ctx))
			case "provider-link":
				p, err := f.client.NetbirdSettings.Create().SetManagementURL("https://other.example.test").Save(ctx)
				require.NoError(t, err)
				require.NoError(t, f.client.Tenant.UpdateOneID(f.scope.TenantID).SetNetbirdID(p.ID).Exec(ctx))
				require.NoError(t, f.client.Tenant.UpdateOneID(f.scope.TenantID).SetNetbirdID(providerID).Exec(ctx))
			case "site-tenant":
				tenant, err := f.client.Tenant.Create().SetDescription("Temporary owner").Save(ctx)
				require.NoError(t, err)
				require.NoError(t, f.client.Site.UpdateOneID(f.scope.SiteID).SetTenantID(tenant.ID).Exec(ctx))
				require.NoError(t, f.client.Site.UpdateOneID(f.scope.SiteID).SetTenantID(f.scope.TenantID).Exec(ctx))
			case "recreated-device":
				require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(ctx))
				require.NoError(t, f.client.Agent.Create().SetID(f.id).SetHostname("Recreated").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
				require.NoError(t, f.client.Netbird.Create().SetOwnerID(f.id).SetInstalled(true).Exec(ctx))
			}
			current, err := s.Review(ctx, "tag-admin", f.scope, f.id, "up", "")
			require.NoError(t, err)
			require.NotEqual(t, review.Revision, current.Revision)
			_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", review.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationChanged)
		})
	}
}

func TestNetbirdOperationsVolatileReportsAndSelectedProfile(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	s := netbirdStore(t, f, nil)
	review, err := s.Review(ctx, "tag-admin", f.scope, f.id, "switchprofile", "other-id")
	require.NoError(t, err)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetAgentStatus(agent.AgentStatusNoContact).SetHostname("Updated report name").Exec(ctx))
	profiles, err := netbirdstate.Encode(nats.Netbird{ProfileDetails: []nats.NetbirdProfile{{ID: "owned-id", Name: "Office, Berlin"}, {ID: "other-id", Name: "Office, Berlin", Active: true}}})
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `UPDATE netbirds SET profiles_available=$2 WHERE agent_netbird=$1`, f.id, profiles)
	require.NoError(t, err)
	current, err := s.Review(ctx, "tag-admin", f.scope, f.id, "switchprofile", "other-id")
	require.NoError(t, err)
	require.Equal(t, review.Revision, current.Revision)
	r, err := s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), "switchprofile", "other-id", review.Revision)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `UPDATE netbirds SET profiles_available='replacement' WHERE agent_netbird=$1`, f.id)
	require.NoError(t, err)
	_, err = s.DispatchOne(ctx)
	require.NoError(t, err)
	receipt := netbirdRead(t, f, s, r.ID)
	require.Equal(t, "stopped", receipt.Status)
	require.Equal(t, "source_changed", receipt.Reason)
	require.Nil(t, receipt.AttemptedAt)
}

func TestNetbirdOperationsConcurrentAdmission(t *testing.T) {
	f, _ := netbirdFixture(t)
	ctx := t.Context()
	s := netbirdStore(t, f, nil)
	review, err := s.Review(ctx, "tag-admin", f.scope, f.id, "up", "")
	require.NoError(t, err)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", review.Revision)
			if err == nil {
				accepted.Add(1)
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		}
	}
	require.Equal(t, int32(1), accepted.Load())
}
