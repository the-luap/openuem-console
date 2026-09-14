package inventory_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestNetbirdInstallationChoicesExposeOnlyMatchingApprovedMetadata(t *testing.T) {
	f, s, packages, pkg := installationFixture(t, func(context.Context, netbirdcommand.Identity) (netbirdcommand.State, error) {
		t.Fatal("listing package choices queried the agent")
		return netbirdcommand.State{}, nil
	})
	other := pkg
	other.ApprovalID = uuid.NewString()
	other.Architecture = "amd64"
	_, err := packages.Approve(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, other, "Owned private organization verification")
	require.NoError(t, err)
	revoked := pkg
	revoked.ApprovalID = uuid.NewString()
	p, err := packages.Approve(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, revoked, "Owned revoked package verification")
	require.NoError(t, err)
	_, err = packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, p.ID, p.Digest, uuid.NewString())
	require.NoError(t, err)
	choices, err := s.Choices(t.Context(), "operator", f.scope, f.id, "")
	require.NoError(t, err)
	require.Len(t, choices.Packages, 1)
	require.Equal(t, pkg.ApprovalID, choices.Packages[0].ID)
	require.Equal(t, "arm64", choices.Architecture)
	require.Equal(t, f.id, choices.Target.ID)
	data, err := json.Marshal(choices)
	require.NoError(t, err)
	for _, private := range []string{"verification", "owned-installation-source", "source_url", "certificate_hash", "broker_key"} {
		require.NotContains(t, string(data), private)
	}
	_, err = s.Choices(t.Context(), "viewer", f.scope, f.id, "")
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.Choices(t.Context(), "operator", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, "")
	require.Error(t, err)
	_, err = s.Choices(t.Context(), "operator", f.scope, f.id, other.ApprovalID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.Choices(t.Context(), "operator", f.scope, f.id, "not-a-cursor")
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	// A revoked last-row cursor remains usable without returning that package or
	// skipping the next matching immutable approval.
	for range 51 {
		additional := pkg
		additional.ApprovalID = uuid.NewString()
		_, err = packages.Approve(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, additional, "Owned paginated approval")
		require.NoError(t, err)
	}
	page, err := s.Choices(t.Context(), "operator", f.scope, f.id, "")
	require.NoError(t, err)
	require.Len(t, page.Packages, 50)
	require.Equal(t, page.Packages[49].ID, page.Next)
	cursor := page.Packages[49]
	_, err = packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, cursor.ID, cursor.Digest, uuid.NewString())
	require.NoError(t, err)
	next, err := s.Choices(t.Context(), "operator", f.scope, f.id, page.Next)
	require.NoError(t, err)
	require.Len(t, next.Packages, 2)
	require.Empty(t, next.Next)
	seen := map[string]bool{}
	for _, group := range [][]inventory.NetbirdInstallationPackage{page.Packages, next.Packages} {
		for _, item := range group {
			require.False(t, seen[item.ID])
			seen[item.ID] = true
		}
	}
	require.Len(t, seen, 52)
}

func TestNetbirdInstallationStatusAndHistoryRetainScopeWithoutLiveAuthority(t *testing.T) {
	f, requests, packages, pkg := installationFixture(t, nil)
	var ids []string
	for range 22 {
		r := installationRequest(t, f, requests, pkg)
		ids = append(ids, r.ID)
		_, err := requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
		require.NoError(t, err)
	}
	last := installationRequest(t, f, requests, pkg)
	ids = append(ids, last.ID)
	// The historical reader has no RPC callbacks. Enrollment and approval may no
	// longer permit new work, but immutable original evidence remains readable.
	_, err := packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, last.ApprovalID, last.ApprovalDigest, uuid.NewString())
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
	require.NoError(t, err)
	v, err := requests.Status(t.Context(), "viewer", f.scope, f.id, last.ID)
	require.NoError(t, err)
	require.Equal(t, "queued", v.State())
	require.Nil(t, v.Preparation)
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
	for _, group := range [][]*inventory.NetbirdInstallationStatus{page.Requests, older.Requests} {
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
}

func TestNetbirdInstallationStatusCombinesReleasedAndOriginalUnconfirmedEvidence(t *testing.T) {
	x := newInstallationResolutionFixture(t, "unconfirmed")
	v := x.review(t)
	d := x.resolve(t, v)
	native, queries, mutations := x.native, x.queries, x.mutations
	status, err := x.s.Status(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
	require.NoError(t, err)
	require.Equal(t, "released", status.State())
	require.Equal(t, "unconfirmed", status.Delivery.OriginalOutcome)
	require.Equal(t, d.ID, status.Resolution.ID)
	require.NotNil(t, status.Request.ReleasedAt)
	require.Nil(t, status.Request.CompletedAt)
	require.Equal(t, "prepared", status.Preparation.Outcome)
	page, err := x.s.History(t.Context(), "viewer", x.f.scope, x.f.id, "")
	require.NoError(t, err)
	require.Len(t, page.Requests, 1)
	require.Equal(t, status, page.Requests[0])
	require.Equal(t, native, x.native)
	require.Equal(t, queries, x.queries)
	require.Equal(t, mutations, x.mutations)
	_, err = x.s.Status(t.Context(), "viewer", x.f.scope, x.f.id, strings.ToUpper(x.r.ID))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
}
