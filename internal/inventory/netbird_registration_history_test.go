package inventory_test

import (
	"context"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRegistrationHistoryIsBoundedAndRetainedInOriginalScope(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	s := registrationStore(t, f, p, nil, nil)
	ids := []string{}
	for i := 0; i < 53; i++ {
		r := registrationRequest(t, f, s)
		ids = append(ids, r.ID)
		require.NoError(t, s.Cancel(t.Context(), r.Actor, r.Scope, r.DeviceID, r.ID))
	}
	first, err := s.History(t.Context(), "viewer", f.scope, f.id, "")
	require.NoError(t, err)
	require.Len(t, first, 50)
	require.Equal(t, ids[52], first[0].ID)
	require.Equal(t, ids[3], first[49].ID)
	next, err := s.History(t.Context(), "viewer", f.scope, f.id, first[49].ID)
	require.NoError(t, err)
	require.Len(t, next, 3)
	require.Equal(t, ids[2], next[0].ID)
	require.Equal(t, ids[0], next[2].ID)
	_, err = s.History(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, first[0].ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.History(t.Context(), "missing", f.scope, f.id, "")
	require.ErrorIs(t, err, access.ErrDenied)
	p.mu.Lock()
	before := len(p.tokens)
	require.Zero(t, p.creates)
	p.mu.Unlock()
	require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(t.Context()))
	retained, err := s.History(t.Context(), "viewer", f.scope, f.id, "")
	require.NoError(t, err)
	require.Len(t, retained, 50)
	p.mu.Lock()
	require.Len(t, p.tokens, before)
	p.mu.Unlock()
}

func TestNetbirdRegistrationRunCancelsAndJoinsActiveDispatch(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	started := make(chan struct{})
	joined := make(chan struct{})
	s := registrationStore(t, f, p, nil, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		close(started)
		<-ctx.Done()
		close(joined)
		return nil, ctx.Err()
	})
	r := registrationRequest(t, f, s)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx, nil) }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("registration dispatcher did not deliver its queued request")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("registration dispatcher did not join cancellation")
	}
	select {
	case <-joined:
	default:
		t.Fatal("registration executor was still active after Run returned")
	}
	receipt := registrationRead(t, f, s, r.ID)
	require.Contains(t, receipt.Attempts, "deliver")
}

func TestNetbirdRegistrationWithoutAdditionalGroupsPreservesEmptyPolicy(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	s := registrationStore(t, f, p, nil, nil)
	review, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, nil, false)
	require.NoError(t, err)
	require.Len(t, review.GroupChoices, 1)
	require.Empty(t, review.Groups)
	r, err := s.Request(t.Context(), "tag-admin", f.scope, f.id, "90000000-0000-4000-8000-000000000001", review.Revision, nil, false)
	require.NoError(t, err)
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	receipt := registrationRead(t, f, s, r.ID)
	require.Equal(t, "completed", receipt.Status)
	require.Empty(t, receipt.Key.Groups)
	require.False(t, receipt.Key.ExtraDNS)
}
