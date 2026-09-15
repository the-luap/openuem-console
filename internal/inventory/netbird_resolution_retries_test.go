package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRegistrationResolutionRetryRecoversMissingControlsAndExecutionRace(t *testing.T) {
	for _, mode := range []string{"release", "withdraw", "late-execution", "lost-retry-reply", "final-audit-rollback"} {
		t.Run(mode, func(t *testing.T) {
			status := "missing"
			if mode == "release" {
				status = "unconfirmed"
			}
			f, p, s, resolver, r, a := registrationResolutionFixture(t, status, true)
			a.withdrawalSupport = true
			a.dropRelease = true
			if mode == "late-execution" {
				a.onWithdraw = func() { a.status = "unconfirmed" }
			}
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.NoError(t, err)
			require.Nil(t, d.ConfirmedAt)
			_, err = resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID)
			require.NoError(t, err)
			require.Equal(t, 1, a.releases+a.withdrawals)
			v, err = resolver.Review(t.Context(), "admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, v.CanRetry)
			require.False(t, v.CanContinue)
			retryID := uuid.NewString()
			if mode == "final-audit-rollback" {
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_retry_final_audit CHECK(action<>'inventory.netbird.release') NOT VALID`)
				require.NoError(t, err)
			}
			a.dropRelease = false
			a.loseReply = mode == "lost-retry-reply"
			result, err := resolver.Retry(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID, retryID, v.Revision)
			if mode == "final-audit-rollback" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, retryID, result.LastRetry.ID)
				require.Equal(t, int64(1), result.LastRetry.Sequence)
				if a.loseReply {
					require.Nil(t, result.ConfirmedAt)
				} else {
					require.NotNil(t, result.ConfirmedAt)
				}
			}
			require.Equal(t, 2, a.releases+a.withdrawals)
			queries := a.queries
			_, err = resolver.Retry(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID, retryID, v.Revision)
			require.NoError(t, err)
			require.Equal(t, queries, a.queries)
			_, err = resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, retryID, v.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			if mode == "final-audit-rollback" {
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_retry_final_audit`)
				require.NoError(t, err)
			}
			result, err = resolver.Reconcile(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID)
			require.NoError(t, err)
			require.NotNil(t, result.ConfirmedAt)
			require.Equal(t, d.Kind, result.Kind)
			require.Equal(t, d.ID, result.ID)
			retained := registrationRead(t, f, s, r.ID)
			require.Equal(t, "unconfirmed", retained.Status)
			require.NotNil(t, retained.ReleasedAt)
			require.Equal(t, retryID, retained.Resolution.LastRetry.ID)
			require.Equal(t, 1, a.deliveries)
			p.mu.Lock()
			require.Equal(t, 1, p.creates)
			require.Equal(t, 1, p.deletes)
			p.mu.Unlock()
			for _, q := range []string{`DELETE FROM uem_netbird_resolution_retries`, `UPDATE uem_netbird_resolution_retries SET actor='admin'`} {
				_, err = f.db.ExecContext(t.Context(), q)
				require.Error(t, err)
			}
		})
	}
}

func TestNetbirdOperationResolutionRetryIsReviewedAndSerialized(t *testing.T) {
	f, _ := netbirdFixture(t)
	var command inventory.NetbirdOperationCommand
	inspect := func(ctx context.Context, _ netbirdcommand.Identity) (netbirdcommand.State, error) {
		if command.RequestID == "" {
			return netbirdReady(ctx, netbirdcommand.Identity{})
		}
		hash, _ := command.Digest()
		return netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("e", 64), Remaining: 4095, PendingID: command.RequestID, PendingHash: hash, CanRelease: true}, nil
	}
	operations, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, false, inspect, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		command = c
		return nil, errors.New("owned command response loss")
	})
	require.NoError(t, err)
	r := netbirdRequest(t, f, operations, "up", "")
	_, err = operations.DispatchOne(t.Context())
	require.NoError(t, err)
	var mu sync.Mutex
	calls, queries := 0, 0
	released := ""
	resolver, err := inventory.NewNetbirdResolutionStore(operations, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		if c.Kind == "release" {
			calls++
			if calls == 1 {
				return nil, errors.New("owned first control not delivered")
			}
			var n int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_resolution_retries WHERE family='operation' AND request_id=$1 AND resolution_id=$2`, r.ID, c.RequestID).Scan(&n))
			require.Equal(t, calls-1, n)
			if calls == 2 {
				return nil, errors.New("owned retry not delivered")
			}
			released = c.RequestID
		} else {
			queries++
		}
		return netbirdResolutionResponse(t, f, c, "unconfirmed", released), nil
	})
	require.NoError(t, err)
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	v, err = resolver.Review(t.Context(), "admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, v.CanRetry)
	_, err = resolver.Retry(t.Context(), "viewer", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, e := resolver.Retry(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
			outcomes <- e
		})
	}
	wg.Wait()
	close(outcomes)
	succeeded, stale := 0, 0
	for e := range outcomes {
		if e == nil {
			succeeded++
		} else {
			require.ErrorIs(t, e, inventory.ErrNetbirdOperationChanged)
			stale++
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, stale)
	require.Equal(t, 2, calls)
	next, err := resolver.Review(t.Context(), "admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.NotEqual(t, v.Revision, next.Revision)
	retryID := uuid.NewString()
	result, err := resolver.Retry(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID, retryID, next.Revision)
	require.NoError(t, err)
	require.NotNil(t, result.ConfirmedAt)
	require.Equal(t, int64(2), result.LastRetry.Sequence)
	before := queries
	_, err = resolver.Retry(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID, retryID, next.Revision)
	require.NoError(t, err)
	require.Equal(t, before, queries)
	require.Equal(t, 3, calls)
	require.Equal(t, "unconfirmed", netbirdRead(t, f, operations, r.ID).Status)
}

func TestNetbirdRegistrationResolutionRetryBeforeFirstAgentAttempt(t *testing.T) {
	f, _, s, resolver, r, a := registrationResolutionFixture(t, "missing", true)
	a.withdrawalSupport = true
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_first_control_failure CHECK(resource_id NOT LIKE '%/agent-resolution') NOT VALID`)
	require.NoError(t, err)
	id := uuid.NewString()
	_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
	require.Error(t, err)
	require.Zero(t, a.withdrawals)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_first_control_failure`)
	require.NoError(t, err)
	a.status = "unconfirmed"
	v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.Nil(t, v.Resolution.AgentAttemptedAt)
	require.True(t, v.CanRetry)
	require.False(t, v.CanContinue)
	require.Equal(t, "release", v.RetryKind)
	a.loseReply = true
	d, err := resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.Nil(t, d.ConfirmedAt)
	require.Nil(t, d.AgentAttemptedAt)
	d, err = resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id)
	require.NoError(t, err)
	require.NotNil(t, d.ConfirmedAt)
	require.Equal(t, "withdraw", d.Kind)
	require.Equal(t, 1, a.releases)
	require.Zero(t, a.withdrawals)
	require.NotNil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
}

func TestNetbirdRegistrationResolutionRetryRejectsChangedAuthorityAndEvidence(t *testing.T) {
	for _, change := range []string{"audit", "active", "foreign-release", "changed-review", "disabled", "moved", "missing-after-release"} {
		t.Run(change, func(t *testing.T) {
			f, _, s, resolver, r, a := registrationResolutionFixture(t, "unconfirmed", true)
			a.dropRelease = true
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.NoError(t, err)
			v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, v.CanRetry)
			switch change {
			case "audit":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_retry_attempt_audit CHECK(resource_id NOT LIKE '%/resolution-retry/%') NOT VALID`)
			case "active":
				a.canRelease = false
			case "foreign-release":
				a.release = uuid.NewString()
			case "changed-review":
				v.Revision = strings.Repeat("c", 64)
			case "disabled":
				err = f.client.Agent.UpdateOneID(r.DeviceID).SetAgentStatus(agent.AgentStatusDisabled).Exec(t.Context())
			case "moved":
				err = f.client.Agent.UpdateOneID(r.DeviceID).RemoveSiteIDs(r.Scope.SiteID).AddSiteIDs(f.otherSite).Exec(t.Context())
			case "missing-after-release":
				a.status = "missing"
				a.withdrawalSupport = true
			}
			require.NoError(t, err)
			_, err = resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
			require.Error(t, err)
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_resolution_retries WHERE request_id=$1`, r.ID).Scan(&count))
			require.Zero(t, count)
			require.Equal(t, 1, a.releases)
			require.Zero(t, a.withdrawals)
			require.Nil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
		})
	}
}

func TestNetbirdResolutionRetryDatabaseGuards(t *testing.T) {
	f, _, _, resolver, r, a := registrationResolutionFixture(t, "missing", true)
	a.withdrawalSupport = true
	a.dropRelease = true
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	var initial []byte
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT control FROM uem_netbird_registration_resolution_attempts WHERE request_id=$1`, r.ID).Scan(&initial))
	var query netbirdcommand.ControlRequest
	require.NoError(t, json.Unmarshal(initial, &query))
	query.Kind = "receipt"
	query.RequestID = uuid.NewString()
	query.IssuedAt = time.Now().UTC()
	query.ExpiresAt = query.IssuedAt.Add(time.Second)
	response, e := netbirdcommand.ControlResponseFor(query, "ok")
	require.NoError(t, e)
	response.Receipt, e = netbirdcommand.ReceiptFor(a.command, "unconfirmed")
	require.NoError(t, e)
	response.ReleaseID = d.ID
	controlWire, e := netbirdcommand.EncodeControl(query)
	require.NoError(t, e)
	proofWire, e := netbirdcommand.EncodeControlResponse(query, response)
	require.NoError(t, e)
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_registration_resolution_evidence(request_id,resolution_id,actor,control,response) VALUES($1,$2,'tag-admin',$3::jsonb,$4::jsonb)`, r.ID, d.ID, string(controlWire), string(proofWire))
	require.Error(t, err, "an unconfirmed receipt cannot replace withdrawal without a separately authorized release phase")
	a.status = "unconfirmed"
	v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	d, err = resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	var retainedControl []byte
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT control FROM uem_netbird_resolution_retries WHERE id=$1`, d.LastRetry.ID).Scan(&retainedControl))
	query = netbirdcommand.ControlRequest{}
	require.NoError(t, json.Unmarshal(retainedControl, &query))
	query.IssuedAt = query.IssuedAt.Add(time.Millisecond)
	query.ExpiresAt = query.ExpiresAt.Add(time.Millisecond)
	response, e = netbirdcommand.ControlResponseFor(query, "ok")
	require.NoError(t, e)
	response.Receipt, e = netbirdcommand.ReceiptFor(a.command, "unconfirmed")
	require.NoError(t, e)
	response.ReleaseID = d.ID
	controlWire, e = netbirdcommand.EncodeControl(query)
	require.NoError(t, e)
	proofWire, e = netbirdcommand.EncodeControlResponse(query, response)
	require.NoError(t, e)
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_registration_resolution_evidence(request_id,resolution_id,actor,control,response) VALUES($1,$2,'tag-admin',$3::jsonb,$4::jsonb)`, r.ID, d.ID, string(controlWire), string(proofWire))
	require.Error(t, err, "mutating proof must match the exact independently retained control")
	// Once execution is documented, a later missing receipt cannot restart withdrawal.
	a.status = "missing"
	v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.False(t, v.CanRetry)
	for _, alter := range []string{
		`control || '{"reference_id":"10000000-0000-4000-8000-000000000001"}'::jsonb`,
		`control || '{"request_id":"10000000-0000-4000-8000-000000000001"}'::jsonb`,
		`control || '{"command_hash":null}'::jsonb`,
		`control || '{"tenant_id":9000}'::jsonb`,
		`control || '{"version":2}'::jsonb`,
		`control || '{"setup_key":"injected"}'::jsonb`,
		`control || jsonb_build_object('expires_at',control->'issued_at')`,
	} {
		_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_resolution_retries(id,family,request_id,resolution_id,actor,revision,kind,sequence,control,control_hash) SELECT $1,family,request_id,resolution_id,actor,revision,kind,sequence+1,`+alter+`,control_hash FROM uem_netbird_resolution_retries WHERE id=$2`, uuid.NewString(), d.LastRetry.ID)
		require.Error(t, err, alter)
	}
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_resolution_retries(id,family,request_id,resolution_id,actor,revision,kind,sequence,control,control_hash) SELECT $1,family,request_id,resolution_id,actor,revision,'withdraw',sequence+1,control,control_hash FROM uem_netbird_resolution_retries WHERE id=$2`, uuid.NewString(), d.LastRetry.ID)
	require.Error(t, err)
	for _, guard := range []string{"uem_netbird_resolution_retry_valid", "uem_netbird_resolution_retry_immutable"} {
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_resolution_retries DISABLE TRIGGER `+guard)
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_resolution_retries ENABLE TRIGGER `+guard)
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}
