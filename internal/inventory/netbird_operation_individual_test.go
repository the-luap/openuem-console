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

func TestNetbirdOperationsIndividualIdentityAndConsumer(t *testing.T) {
	for _, change := range []string{"ready", "revoked", "expired", "consumer", "scope", "inactive", "certificate", "consumer-recreated", "short-certificate"} {
		t.Run(change, func(t *testing.T) {
			f, _ := netbirdFixture(t)
			ctx := t.Context()
			identities, err := registry.NewStore(f.db, "owned-netbird-identity-master-key")
			require.NoError(t, err)
			require.NoError(t, identities.Migrate(ctx))
			_, err = identities.EnsureAuthority(ctx, f.scope.TenantID, "Owned NetBird fixture", "https://uem.example.test", "admin", nil, nil)
			require.NoError(t, err)
			invitation, err := identities.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: f.scope.TenantID, SiteID: f.scope.SiteID}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
			require.NoError(t, err)
			keys, err := enrollment.GenerateKeys()
			require.NoError(t, err)
			defer keys.Broker.Wipe()
			claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Owned NetBird endpoint")
			require.NoError(t, err)
			response, err := identities.Claim(ctx, *claim)
			require.NoError(t, err)
			f.id = response.DeviceID
			require.NoError(t, f.client.Agent.Create().SetID(f.id).SetHostname("Owned individual endpoint").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
			require.NoError(t, f.client.Netbird.Create().SetOwnerID(f.id).SetInstalled(true).Exec(ctx))
			calls := 0
			s, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, true, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				calls++
				if change == "short-certificate" {
					require.Less(t, time.Until(c.ExpiresAt), time.Minute)
					deadline, ok := ctx.Deadline()
					require.True(t, ok)
					require.Equal(t, c.ExpiresAt, deadline)
				}
				return netbirdSuccess(ctx, c)
			})
			require.NoError(t, err)
			_, err = s.Review(ctx, "admin", f.scope, f.id, "up", "")
			require.ErrorIs(t, err, inventory.ErrRefreshNotReady)
			_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1`, f.id)
			require.NoError(t, err)
			r := netbirdRequest(t, f, s, "up", "")
			switch change {
			case "revoked":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "expired":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET revision=revision+1 WHERE device_id=$1`, f.id)
			case "scope":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET site_id=$2 WHERE id=$1`, f.id, f.otherSite)
			case "inactive":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
			case "certificate":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('a',64) WHERE id=$1`, f.id)
			case "consumer-recreated":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET revision=revision+1,completed_revision=revision+1 WHERE device_id=$1`, f.id)
			case "short-certificate":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '45 seconds' WHERE id=$1`, f.id)
			}
			require.NoError(t, err)
			_, err = s.DispatchOne(ctx)
			require.NoError(t, err)
			receipt := netbirdRead(t, f, s, r.ID)
			if change == "ready" || change == "short-certificate" {
				require.Equal(t, 1, calls)
				require.Equal(t, "completed", receipt.Status)
			} else {
				require.Zero(t, calls)
				require.Equal(t, "stopped", receipt.Status)
				require.Equal(t, "source_changed", receipt.Reason)
				require.Nil(t, receipt.AttemptedAt)
			}
		})
	}
}
