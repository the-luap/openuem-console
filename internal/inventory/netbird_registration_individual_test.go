package inventory_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRegistrationIndividualIdentityAndEffectiveDeadline(t *testing.T) {
	for _, change := range []string{"ready", "short-certificate", "revoked", "renewed"} {
		t.Run(change, func(t *testing.T) {
			f, id := netbirdFixture(t)
			p := newRegistrationProvider(t, f, id)
			ctx := t.Context()
			identities, err := registry.NewStore(f.db, "owned-netbird-identity-master-key")
			require.NoError(t, err)
			require.NoError(t, identities.Migrate(ctx))
			_, err = identities.EnsureAuthority(ctx, f.scope.TenantID, "Owned registration fixture", "https://uem.example.test", "admin", nil, nil)
			require.NoError(t, err)
			invitation, err := identities.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: f.scope.TenantID, SiteID: f.scope.SiteID}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
			require.NoError(t, err)
			keys, err := enrollment.GenerateKeys()
			require.NoError(t, err)
			defer keys.Broker.Wipe()
			claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Owned registration endpoint")
			require.NoError(t, err)
			response, err := identities.Claim(ctx, *claim)
			require.NoError(t, err)
			f.id = response.DeviceID
			require.NoError(t, f.client.Agent.Create().SetID(f.id).SetHostname("Owned registration endpoint").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
			require.NoError(t, f.client.Netbird.Create().SetOwnerID(f.id).SetInstalled(true).Exec(ctx))
			_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1`, f.id)
			require.NoError(t, err)
			if change == "short-certificate" {
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '45 seconds' WHERE id=$1`, f.id)
				require.NoError(t, err)
			}
			sent := 0
			s, err := inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), p.server.Client().Transport, registrationControl, func(call context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				sent++
				require.True(t, c.Individual)
				require.NotEmpty(t, c.CertificateHash)
				if change == "short-certificate" {
					require.Less(t, time.Until(c.ExpiresAt), time.Minute)
				}
				deadline, ok := call.Deadline()
				require.True(t, ok)
				require.True(t, c.ExpiresAt.Equal(deadline))
				return netbirdSuccess(call, c)
			})
			require.NoError(t, err)
			r := registrationRequest(t, f, s)
			if change == "revoked" {
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
				require.NoError(t, err)
			}
			if change == "renewed" {
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('a',64) WHERE id=$1`, f.id)
				require.NoError(t, err)
			}
			_, err = s.DispatchOne(ctx)
			require.NoError(t, err)
			receipt := registrationRead(t, f, s, r.ID)
			p.mu.Lock()
			defer p.mu.Unlock()
			if change == "ready" || change == "short-certificate" {
				require.Equal(t, 1, sent)
				require.Equal(t, 1, p.creates)
				require.Equal(t, "completed", receipt.Status)
			} else {
				require.Zero(t, sent)
				require.Zero(t, p.creates)
				require.Equal(t, "stopped", receipt.Status)
			}
		})
	}
}

func TestNetbirdRegistrationCancellationRetainsDeliveryAttemptAndCleansOnce(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sent := 0
	s := registrationStore(t, f, p, nil, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		sent++
		cancel()
		return nil, context.Canceled
	})
	r := registrationRequest(t, f, s)
	_, err := s.DispatchOne(ctx)
	require.Error(t, err)
	pending := registrationRead(t, f, s, r.ID)
	require.Equal(t, "queued", pending.Status)
	require.Equal(t, []string{"create", "deliver"}, pending.Attempts)
	require.ErrorIs(t, s.Cancel(t.Context(), r.Actor, r.Scope, r.DeviceID, r.ID), inventory.ErrNetbirdOperationConflict)
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	receipt := registrationRead(t, f, s, r.ID)
	require.Equal(t, "unconfirmed", receipt.Status)
	require.True(t, receipt.KeyAbsent)
	require.Equal(t, 1, sent)
	p.mu.Lock()
	require.Equal(t, 1, p.creates)
	require.Equal(t, 1, p.deletes)
	p.mu.Unlock()
}
