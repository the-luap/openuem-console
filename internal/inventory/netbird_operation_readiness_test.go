package inventory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestNetbirdOperationsLiveReadinessAndReviewChanges(t *testing.T) {
	f, _ := netbirdFixture(t)
	state, _ := netbirdReady(t.Context(), netbirdcommand.Identity{})
	var probeErr error
	probes, sent := 0, 0
	s, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, false, func(ctx context.Context, identity netbirdcommand.Identity) (netbirdcommand.State, error) {
		probes++
		require.Equal(t, netbirdcommand.Identity{DeviceID: f.id, TenantID: int64(f.scope.TenantID), SiteID: int64(f.scope.SiteID)}, identity)
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), 2*time.Second)
		return state, probeErr
	}, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		sent++
		return netbirdSuccess(ctx, c)
	})
	require.NoError(t, err)
	for _, scope := range []access.Scope{{}, {TenantID: f.scope.TenantID}, {TenantID: f.scope.TenantID, SiteID: f.otherSite}} {
		_, err = s.Review(t.Context(), "admin", scope, f.id, "up", "")
		require.Error(t, err)
	}
	_, err = s.Review(t.Context(), "viewer", f.scope, f.id, "up", "")
	require.ErrorIs(t, err, access.ErrDenied)
	require.Zero(t, probes, "unauthorized or foreign targets reached the broker")
	for _, status := range []string{"unavailable", "busy", "unconfirmed", "full", "malformed", "offline"} {
		state = netbirdcommand.State{Status: status}
		probeErr = nil
		if status == "offline" {
			state, _ = netbirdReady(t.Context(), netbirdcommand.Identity{})
			probeErr = errors.New("private broker detail")
		}
		_, err = s.Review(t.Context(), "tag-admin", f.scope, f.id, "up", "")
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationNotReady)
		require.NotContains(t, err.Error(), "private")
	}
	state, _ = netbirdReady(t.Context(), netbirdcommand.Identity{})
	probeErr = nil
	review, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, "up", "")
	require.NoError(t, err)
	state.Revision = strings.Repeat("e", 64)
	_, err = s.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationChanged)
	r := netbirdRequest(t, f, s, "up", "")
	state.Revision = strings.Repeat("f", 64)
	worked, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.True(t, worked)
	stopped := netbirdRead(t, f, s, r.ID)
	require.Equal(t, "stopped", stopped.Status)
	require.Equal(t, "source_changed", stopped.Reason)
	require.Nil(t, stopped.AttemptedAt)
	r = netbirdRequest(t, f, s, "up", "")
	probeErr = errors.New("owned no-responder fixture")
	worked, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.True(t, worked)
	stopped = netbirdRead(t, f, s, r.ID)
	require.Equal(t, "stopped", stopped.Status)
	require.Nil(t, stopped.AttemptedAt)
	var attempts int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_operation_attempts WHERE device_id=$1`, f.id).Scan(&attempts))
	require.Zero(t, attempts)
	require.Zero(t, sent)
}

func TestNetbirdOperationsWireReceiptDatabaseGuard(t *testing.T) {
	f, _ := netbirdFixture(t)
	s := netbirdStore(t, f, nil)
	r := netbirdRequest(t, f, s, "down", "")
	ctx := t.Context()
	_, err := f.db.ExecContext(ctx, `INSERT INTO uem_netbird_operation_attempts(request_id,device_id,tenant_id,site_id,actor,operation,revision,command_hash,command_expires_at) SELECT id,device_id,tenant_id,site_id,actor,operation,revision,$2,expires_at FROM uem_netbird_operations WHERE id=$1`, r.ID, strings.Repeat("a", 64))
	require.NoError(t, err)
	for _, hash := range []string{"", strings.Repeat("b", 64)} {
		_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_operations SET status='completed',finished_at=clock_timestamp(),result=jsonb_build_object('request_id',id::text,'device_id',device_id,'revision',revision,'operation',operation,'success',true) || CASE WHEN $2='' THEN '{}'::jsonb ELSE jsonb_build_object('command_hash',$2::text) END WHERE id=$1`, r.ID, hash)
		require.Error(t, err, "new completion lacked its actual wire digest")
	}
	_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_operations SET status='completed',finished_at=clock_timestamp(),result=jsonb_build_object('request_id',id::text,'device_id',device_id,'revision',revision,'operation',operation,'success',true,'command_hash',$2::text) WHERE id=$1`, r.ID, strings.Repeat("a", 64))
	require.NoError(t, err)
	read := netbirdRead(t, f, s, r.ID)
	require.Equal(t, strings.Repeat("a", 64), read.CommandHash)
	_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_operation_attempts SET command_hash=$2 WHERE request_id=$1`, r.ID, strings.Repeat("b", 64))
	require.Error(t, err, "wire evidence was replaceable")
}
