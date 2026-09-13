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
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

func TestManualExecutionRequiresCurrentIndividualIdentityAndCommandConsumer(t *testing.T) {
	for _, change := range []string{"ready", "revoked", "expired", "consumer", "scope", "inactive"} {
		t.Run(change, func(t *testing.T) {
			f, _ := tagFixture(t)
			ctx := t.Context()
			identity, err := registry.NewStore(f.db, "owned-manual-identity-master-key")
			require.NoError(t, err)
			require.NoError(t, identity.Migrate(ctx))
			_, err = identity.EnsureAuthority(ctx, f.scope.TenantID, "Owned manual fixture", "https://uem.example.test", "admin", nil, nil)
			require.NoError(t, err)
			invitation, err := identity.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: f.scope.TenantID, SiteID: f.scope.SiteID}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
			require.NoError(t, err)
			keys, err := enrollment.GenerateKeys()
			require.NoError(t, err)
			defer keys.Broker.Wipe()
			claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Owned manual endpoint")
			require.NoError(t, err)
			response, err := identity.Claim(ctx, *claim)
			require.NoError(t, err)
			f.id = response.DeviceID
			require.NoError(t, f.client.Agent.Create().SetID(f.id).SetHostname("Owned individual endpoint").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
			_, taskID := manualTask(t, f, f.scope)
			calls := 0
			store, err := inventory.NewManualExecutionStore(f.db, f.permissions, true, strings.Repeat("k", 32), func(context.Context, string, string, *taskexecution.Payload) error { calls++; return nil })
			require.NoError(t, err)
			_, err = store.Review(ctx, "admin", f.scope, f.id, "task", int64(taskID))
			require.ErrorIs(t, err, inventory.ErrRefreshNotReady)
			_, err = f.db.ExecContext(ctx, "UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1", f.id)
			require.NoError(t, err)
			request := queueManual(t, f, store, "admin", taskID)
			switch change {
			case "revoked":
				_, err = f.db.ExecContext(ctx, "UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1", f.id)
			case "expired":
				_, err = f.db.ExecContext(ctx, "UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", f.id)
			case "consumer":
				_, err = f.db.ExecContext(ctx, "UPDATE uem_agent_command_consumers SET revision=revision+1 WHERE device_id=$1", f.id)
			case "scope":
				_, err = f.db.ExecContext(ctx, "UPDATE uem_agent_identities SET site_id=$2 WHERE id=$1", f.id, f.otherSite)
			case "inactive":
				_, err = f.db.ExecContext(ctx, "UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1", f.id)
			}
			require.NoError(t, err)
			_, err = store.DispatchOne(ctx)
			require.NoError(t, err)
			receipt, err := store.Read(ctx, "admin", f.scope, f.id, request.ID)
			require.NoError(t, err)
			if change == "ready" {
				require.Equal(t, 1, calls)
				require.Equal(t, "accepted", receipt.Status)
			} else {
				require.Zero(t, calls)
				require.Equal(t, "stopped", receipt.Status)
				require.Equal(t, "target_changed", receipt.Reason)
				require.Nil(t, receipt.AttemptedAt)
				_, err = store.Review(ctx, "admin", f.scope, f.id, "task", int64(taskID))
				require.ErrorIs(t, err, inventory.ErrRefreshNotReady)
			}
		})
	}
}
