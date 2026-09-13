package inventory_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRegistrationWithdrawalRequiresKeyAbsenceAndPermanentAgentProof(t *testing.T) {
	for _, mode := range []string{"delivered", "reply-lost", "request-lost", "cleanup-first", "late-completed", "late-unconfirmed"} {
		t.Run(mode, func(t *testing.T) {
			f, p, s, resolver, r, a := registrationResolutionFixture(t, "missing", mode != "cleanup-first")
			a.withdrawalSupport = true
			a.loseReply = mode == "reply-lost"
			a.dropRelease = mode == "request-lost"
			if mode == "late-completed" {
				a.onWithdraw = func() { a.status = "completed" }
			}
			if mode == "late-unconfirmed" {
				a.onWithdraw = func() { a.status = "unconfirmed" }
			}
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.Equal(t, "not-received", v.AgentState)
			require.True(t, v.CanResolve)
			d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.NoError(t, err)
			require.Equal(t, "withdraw", d.Kind)
			if mode == "delivered" || mode == "cleanup-first" {
				require.NotNil(t, d.ConfirmedAt)
			} else {
				require.Nil(t, d.ConfirmedAt)
			}
			require.Equal(t, 1, a.withdrawals)
			require.Zero(t, a.releases)
			before := a.queries
			_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, v.Revision)
			require.NoError(t, err)
			require.Equal(t, before, a.queries)
			result, err := resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID)
			require.NoError(t, err)
			retained := registrationRead(t, f, s, r.ID)
			require.Equal(t, "unconfirmed", retained.Status)
			require.True(t, retained.KeyAbsent)
			if mode == "request-lost" || mode == "late-unconfirmed" {
				require.Nil(t, result.ConfirmedAt)
				require.Nil(t, retained.ReleasedAt)
			} else {
				require.NotNil(t, result.ConfirmedAt)
				require.NotNil(t, retained.ReleasedAt)
				var control, proof string
				require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT control::text,response::text FROM uem_netbird_registration_resolution_evidence WHERE request_id=$1`, r.ID).Scan(&control, &proof))
				require.Contains(t, control, `"version": 2`)
				require.Contains(t, proof, `"operation": "register"`)
				if mode != "late-completed" {
					require.Contains(t, proof, `"status": "withdrawn"`)
					require.Contains(t, proof, d.ID)
				}
				require.NotContains(t, proof, "owned-private")
				require.NotContains(t, control, "setup_key")
			}
			require.Equal(t, 1, a.withdrawals)
			require.Equal(t, 1, a.deliveries)
			require.Zero(t, a.releases)
			p.mu.Lock()
			require.Equal(t, 1, p.creates)
			require.Equal(t, 1, p.deletes)
			p.mu.Unlock()
		})
	}
}

func TestNetbirdRegistrationWithdrawalAuditFailureRetainsIntentAndDenial(t *testing.T) {
	f, _, s, resolver, r, a := registrationResolutionFixture(t, "missing", true)
	a.withdrawalSupport = true
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_withdrawal_audit CHECK(action<>'inventory.netbird.release') NOT VALID`)
	require.NoError(t, err)
	id := uuid.NewString()
	_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
	require.Error(t, err)
	require.Equal(t, 1, a.withdrawals)
	require.Equal(t, id, a.withdrawalID)
	require.Nil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_withdrawal_audit`)
	require.NoError(t, err)
	result, err := resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id)
	require.NoError(t, err)
	require.NotNil(t, result.ConfirmedAt)
	require.Equal(t, 1, a.withdrawals)
	_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_registration_resolutions SET kind='acknowledge' WHERE request_id=$1`, r.ID)
	require.Error(t, err)
}

func TestNetbirdRegistrationWithdrawalNeverInfersProofFromMissingReceipt(t *testing.T) {
	for _, mode := range []string{"legacy", "foreign-withdrawal", "changed-key"} {
		t.Run(mode, func(t *testing.T) {
			_, p, _, resolver, r, a := registrationResolutionFixture(t, "missing", false)
			a.withdrawalSupport = mode != "legacy"
			switch mode {
			case "foreign-withdrawal":
				a.status = "withdrawn"
				a.withdrawalID = uuid.NewString()
			case "changed-key":
				p.mu.Lock()
				p.drift = true
				p.mu.Unlock()
			}
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.False(t, v.CanResolve)
			_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), strings.Repeat("a", 64))
			require.Error(t, err)
			require.Zero(t, a.withdrawals)
			require.Zero(t, a.releases)
		})
	}
}
