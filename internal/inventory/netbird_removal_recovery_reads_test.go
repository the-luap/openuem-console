package inventory_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRecoveryStatusAndHistoryRetainScopeWithoutLiveAuthority(t *testing.T) {
	var calls atomic.Int32
	x := recoveryFixture(t)
	f := x.f
	requests := recoveryStore(t, x, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		calls.Add(1)
		return recoveryControl(t, x)(ctx, c)
	})
	var ids []string
	for range 22 {
		r := recoveryRequest(t, x, requests, recoveryReview(t, x, requests))
		ids = append(ids, r.ID)
		_, err := requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
		require.NoError(t, err)
	}
	last := recoveryRequest(t, x, requests, recoveryReview(t, x, requests))
	ids = append(ids, last.ID)
	// Retained evidence requires no native query, even after enrollment can no
	// longer authorize new work.
	before := calls.Load()
	_, err := f.db.ExecContext(t.Context(), `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
	require.NoError(t, err)
	v, err := requests.Status(t.Context(), "viewer", f.scope, f.id, last.ID)
	require.NoError(t, err)
	require.Equal(t, "queued", v.State())
	require.Nil(t, v.Delivery)
	page, err := requests.History(t.Context(), "viewer", f.scope, f.id, "")
	require.NoError(t, err)
	require.Len(t, page.Requests, 20)
	require.NotEmpty(t, page.Next)
	require.Equal(t, last.ID, page.Requests[0].Request.ID)
	older, err := requests.History(t.Context(), "viewer", f.scope, f.id, page.Next)
	require.NoError(t, err)
	require.Len(t, older.Requests, 3)
	require.Empty(t, older.Next)
	seen := map[string]bool{}
	for _, group := range [][]*inventory.NetbirdRemovalRecoveryStatus{page.Requests, older.Requests} {
		for _, r := range group {
			require.False(t, seen[r.Request.ID])
			seen[r.Request.ID] = true
			if r.Request.ID != last.ID {
				require.Equal(t, "cancelled", r.State())
			}
		}
	}
	require.Len(t, seen, len(ids))
	data, err := json.Marshal([]any{v, page, older})
	require.NoError(t, err)
	require.NotContains(t, string(data), "owned-installation-source")
	require.NotContains(t, string(data), "Verification")
	hidden := access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}
	_, err = requests.Status(t.Context(), "admin", hidden, f.id, last.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = requests.History(t.Context(), "admin", hidden, f.id, last.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	empty, err := requests.History(t.Context(), "admin", hidden, f.id, "")
	require.NoError(t, err)
	require.Empty(t, empty.Requests)
	_, err = requests.History(t.Context(), "viewer", f.scope, f.id, " "+last.ID)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	require.Equal(t, before, calls.Load())
}

func TestNetbirdRecoveryStatusCombinesReleasedAndOriginalUnconfirmedEvidence(t *testing.T) {
	x := newRecoveryResolutionFixture(t, "unconfirmed")
	v := x.review(t)
	d := x.resolve(t, v)
	native, queries, mutations, inspections := x.native, x.queries, x.mutations, x.inspections
	status, err := x.s.Status(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
	require.NoError(t, err)
	require.Equal(t, "released", status.State())
	require.Equal(t, "unconfirmed", status.Delivery.OriginalOutcome)
	require.Equal(t, d.ID, status.Resolution.ID)
	require.NotNil(t, status.Request.ReleasedAt)
	require.Nil(t, status.Request.CompletedAt)
	page, err := x.s.History(t.Context(), "viewer", x.f.scope, x.f.id, "")
	require.NoError(t, err)
	require.Len(t, page.Requests, 1)
	require.Equal(t, status, page.Requests[0])
	require.Equal(t, native, x.native)
	require.Equal(t, queries, x.queries)
	require.Equal(t, mutations, x.mutations)
	require.Equal(t, inspections, x.inspections)
	_, err = x.s.Status(t.Context(), "viewer", x.f.scope, x.f.id, strings.ToUpper(x.r.ID))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
}

func TestNetbirdRecoveryLinkRequiresExactReleasedUnconfirmedOriginal(t *testing.T) {
	for _, state := range []string{"missing", "unconfirmed"} {
		t.Run(state, func(t *testing.T) {
			x := newRemovalResolutionFixture(t, state)
			before, err := x.s.Status(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
			require.NoError(t, err)
			require.False(t, before.CanReviewRecovery)
			x.resolve(t, x.review(t))
			inspections, queries, native := x.inspections, x.queries, x.native
			x.nativeAbsent = true
			_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64),revoked_at=clock_timestamp() WHERE id=$1`, x.f.id)
			require.NoError(t, err)
			after, err := x.s.Status(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
			require.NoError(t, err)
			require.Equal(t, state == "unconfirmed", after.CanReviewRecovery)
			require.Equal(t, inspections, x.inspections)
			require.Equal(t, queries, x.queries)
			require.Equal(t, native, x.native)
			if state == "unconfirmed" {
				_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_control_results DISABLE TRIGGER uem_netbird_removal_control_result_immutable`)
				require.NoError(t, err)
				_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_netbird_removal_control_results SET response=jsonb_set(response,'{receipt,status}','"withdrawn"'::jsonb)`)
				require.NoError(t, err)
				_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_control_results ENABLE TRIGGER uem_netbird_removal_control_result_immutable`)
				require.NoError(t, err)
				after, err = x.s.Status(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
				require.NoError(t, err)
				require.False(t, after.CanReviewRecovery)
				require.Equal(t, "released", after.State(), "ineligible proof must not erase original history")
			}
		})
	}
}
