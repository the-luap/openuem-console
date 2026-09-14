package inventory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

type ownedRegistrationAgent struct {
	withdrawalSupport                  bool
	withdrawalID                       string
	withdrawals                        int
	onWithdraw                         func()
	command                            netbirdcommand.Command
	status, release                    string
	canRelease, loseReply, dropRelease bool
	deliveries, releases, queries      int
}

func registrationResolutionFixture(t *testing.T, status string, cleanup bool) (*refreshFixture, *ownedRegistrationProvider, *inventory.NetbirdRegistrationStore, *inventory.NetbirdRegistrationResolutionStore, *inventory.NetbirdRegistration, *ownedRegistrationAgent) {
	t.Helper()
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	p.failRead = !cleanup
	a := &ownedRegistrationAgent{status: status, canRelease: true}
	control := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		response, err := netbirdcommand.ControlResponseFor(c, "ok")
		require.NoError(t, err)
		if c.Kind == "registration-state" {
			response.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("d", 64), Remaining: 4096}
			if a.command.RequestID != "" && a.status == "unconfirmed" && a.release == "" {
				hash, err := a.command.Digest()
				require.NoError(t, err)
				response.State = netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("e", 64), Remaining: 4095, PendingID: a.command.RequestID, PendingHash: hash, CanRelease: a.canRelease}
			}
			return &response, nil
		}
		a.queries++
		if c.Version == netbirdcommand.RecoveryVersion && !a.withdrawalSupport {
			return nil, errors.New("owned older agent does not support withdrawal")
		}
		if c.Kind == "withdraw" {
			a.withdrawals++
			var attempts, absent int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM (SELECT 1 FROM uem_netbird_registration_resolution_attempts WHERE request_id=$1 AND resolution_id=$2 UNION ALL SELECT 1 FROM uem_netbird_resolution_retries WHERE family='registration' AND request_id=$1 AND resolution_id=$2) admitted),(SELECT count(*) FROM uem_netbird_registration_evidence WHERE request_id=$1 AND kind='absent')`, c.ReferenceID, c.RequestID).Scan(&attempts, &absent))
			require.Positive(t, attempts)
			require.Equal(t, 1, absent)
			if a.onWithdraw != nil {
				a.onWithdraw()
			}
			if a.status != "missing" {
				p, err := netbirdcommand.ControlResponseFor(c, "conflict")
				return &p, err
			}
			if a.dropRelease {
				return nil, errors.New("owned withdrawal was not delivered")
			}
			a.status = "withdrawn"
			a.withdrawalID = c.RequestID
			if a.loseReply {
				return nil, errors.New("owned withdrawal response lost")
			}
		}
		if a.status == "withdrawn" && c.Version != netbirdcommand.RecoveryVersion {
			p, err := netbirdcommand.ControlResponseFor(c, "conflict")
			return &p, err
		}
		if a.status == "missing" {
			r, err := netbirdcommand.ControlResponseFor(c, "missing")
			return &r, err
		}
		if c.Kind == "release" {
			a.releases++
			var attempts, absent int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM (SELECT 1 FROM uem_netbird_registration_resolution_attempts WHERE request_id=$1 AND resolution_id=$2 UNION ALL SELECT 1 FROM uem_netbird_resolution_retries WHERE family='registration' AND request_id=$1 AND resolution_id=$2) admitted),(SELECT count(*) FROM uem_netbird_registration_evidence WHERE request_id=$1 AND kind='absent')`, c.ReferenceID, c.RequestID).Scan(&attempts, &absent))
			require.Positive(t, attempts)
			require.Equal(t, 1, absent)
			if a.dropRelease {
				return nil, errors.New("owned request not delivered")
			}
			a.release = c.RequestID
			if a.loseReply {
				return nil, errors.New("owned reply lost")
			}
		}
		response.Receipt, err = netbirdcommand.ReceiptFor(a.command, a.status)
		require.NoError(t, err)
		response.ReleaseID = a.release
		if a.status == "withdrawn" {
			response.ReleaseID = a.withdrawalID
		}
		return &response, nil
	}
	s, err := inventory.NewNetbirdRegistrationStore(f.db, f.permissions, false, strings.Repeat("k", 32), p.server.Client().Transport, control, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		a.command = c
		a.deliveries++
		return nil, errors.New("owned execution reply lost")
	})
	require.NoError(t, err)
	r := registrationRequest(t, f, s)
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", registrationRead(t, f, s, r.ID).Status)
	resolver, err := inventory.NewNetbirdRegistrationResolutionStore(s, control)
	require.NoError(t, err)
	p.mu.Lock()
	p.failRead = false
	p.mu.Unlock()
	return f, p, s, resolver, r, a
}
func TestNetbirdRegistrationResolutionCombinesKeyAndAgentEvidence(t *testing.T) {
	for _, status := range []string{"completed", "unconfirmed"} {
		for _, cleanup := range []bool{true, false} {
			t.Run(status+"/"+map[bool]string{true: "already-cleaned", false: "cleanup-first"}[cleanup], func(t *testing.T) {
				f, p, s, resolver, r, a := registrationResolutionFixture(t, status, cleanup)
				_, err := f.db.ExecContext(t.Context(), `UPDATE uem_netbird_registrations SET released_at=clock_timestamp(),released_by='admin' WHERE id=$1`, r.ID)
				require.Error(t, err)
				v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, err)
				require.True(t, v.CanResolve)
				require.Equal(t, status, v.AgentState)
				require.Equal(t, !cleanup, v.CanCleanup)
				d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
				require.NoError(t, err)
				require.NotNil(t, d.ConfirmedAt)
				retained := registrationRead(t, f, s, r.ID)
				require.Equal(t, "unconfirmed", retained.Status)
				require.NotNil(t, retained.ReleasedAt)
				require.True(t, retained.KeyAbsent)
				require.Equal(t, "tag-admin", retained.ReleasedBy)
				if !cleanup {
					var actor string
					require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT actor FROM uem_netbird_operations_audit WHERE action='inventory.netbird.attempt' AND resource_id=$1 ORDER BY created_at DESC LIMIT 1`, r.ID+"/device/"+r.DeviceID+"/register/delete").Scan(&actor))
					require.Equal(t, "tag-admin", actor)
				}
				require.NotNil(t, retained.Resolution)
				again, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, v.Revision)
				require.NoError(t, err)
				require.Equal(t, d.ID, again.ID)
				require.Equal(t, 1, a.deliveries)
				if status == "unconfirmed" {
					require.Equal(t, 1, a.releases)
				} else {
					require.Zero(t, a.releases)
				}
				p.mu.Lock()
				require.Equal(t, 1, p.creates)
				require.Equal(t, 1, p.deletes)
				p.mu.Unlock()
				// Both request families now admit new reviewed work; old UUIDs stay reserved.
				operations := netbirdStore(t, f, nil)
				op := netbirdRequest(t, f, operations, "up", "")
				require.NoError(t, operations.Cancel(t.Context(), op.Actor, op.Scope, op.DeviceID, op.ID))
				require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(t.Context()))
				require.NotNil(t, registrationRead(t, f, s, r.ID).Resolution.ConfirmedAt)
			})
		}
	}
}
func TestNetbirdRegistrationResolutionLostReleaseReplyIsReadOnlyOnRecovery(t *testing.T) {
	for _, lost := range []string{"reply", "request"} {
		t.Run(lost, func(t *testing.T) {
			f, _, s, resolver, r, a := registrationResolutionFixture(t, "unconfirmed", true)
			a.loseReply = lost == "reply"
			a.dropRelease = lost == "request"
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.NoError(t, err)
			require.Nil(t, d.ConfirmedAt)
			require.NotNil(t, d.AgentAttemptedAt)
			_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, v.Revision)
			require.NoError(t, err)
			require.Equal(t, 1, a.releases)
			d, err = resolver.Reconcile(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID)
			require.NoError(t, err)
			require.Equal(t, 1, a.releases)
			if lost == "reply" {
				require.NotNil(t, d.ConfirmedAt)
				require.NotNil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
			} else {
				require.Nil(t, d.ConfirmedAt)
				require.Nil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
			}
		})
	}
}
func TestNetbirdRegistrationResolutionRequiresFreshContinuationAfterCleanup(t *testing.T) {
	f, p, s, resolver, r, a := registrationResolutionFixture(t, "unconfirmed", false)
	p.mu.Lock()
	p.retainDelete = true
	p.mu.Unlock()
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, v.CanResolve)
	d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.Nil(t, d.AgentAttemptedAt)
	require.Zero(t, a.releases)
	p.mu.Lock()
	p.absent = true
	p.mu.Unlock()
	d, err = resolver.Reconcile(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID)
	require.NoError(t, err)
	require.Nil(t, d.ConfirmedAt)
	require.Zero(t, a.releases)
	require.True(t, registrationRead(t, f, s, r.ID).KeyAbsent)
	next, err := resolver.Review(t.Context(), "admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, next.CanContinue)
	require.NotEqual(t, v.Revision, next.Revision)
	_, err = resolver.Continue(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID, v.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationChanged)
	d, err = resolver.Continue(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, d.ID, next.Revision)
	require.NoError(t, err)
	require.NotNil(t, d.ConfirmedAt)
	require.Equal(t, 1, a.releases)
	p.mu.Lock()
	require.Equal(t, 1, p.deletes)
	p.mu.Unlock()
}
func TestNetbirdRegistrationResolutionAuditRollbackRetainsControlAttempt(t *testing.T) {
	for _, stage := range []string{"resolution-intent", "agent-resolution", "release"} {
		t.Run(stage, func(t *testing.T) {
			f, _, s, resolver, r, a := registrationResolutionFixture(t, "unconfirmed", true)
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			clause := `resource_id NOT LIKE '%/register/` + stage + `'`
			if stage == "release" {
				clause = `action<>'inventory.netbird.release'`
			}
			_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_registration_resolution_failure CHECK(`+clause+`) NOT VALID`)
			require.NoError(t, err)
			id := uuid.NewString()
			_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			require.Error(t, err)
			require.Nil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
			_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_registration_resolution_failure`)
			require.NoError(t, err)
			next, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			var d *inventory.NetbirdRegistrationResolution
			switch stage {
			case "resolution-intent":
				require.Nil(t, next.Resolution)
				d, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, next.Revision)
			case "agent-resolution":
				require.NotNil(t, next.Resolution)
				require.True(t, next.CanContinue)
				require.Zero(t, a.releases)
				d, err = resolver.Continue(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, next.Revision)
			case "release":
				require.NotNil(t, next.Resolution.AgentAttemptedAt)
				require.False(t, next.CanContinue)
				require.Equal(t, 1, a.releases)
				d, err = resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id)
			}
			require.NoError(t, err)
			require.NotNil(t, d.ConfirmedAt)
			require.Equal(t, 1, a.releases)
			require.Equal(t, 1, a.deliveries)
		})
	}
}
func TestNetbirdRegistrationResolutionUnknownAndActiveExecutionStayBlocked(t *testing.T) {
	for _, mode := range []string{"missing", "active", "other-release", "provider-changed", "provider-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			status := "unconfirmed"
			if mode == "missing" {
				status = "missing"
			}
			_, p, _, resolver, r, a := registrationResolutionFixture(t, status, false)
			switch mode {
			case "active":
				a.canRelease = false
			case "other-release":
				a.release = uuid.NewString()
			case "provider-changed":
				p.mu.Lock()
				p.drift = true
				p.mu.Unlock()
			case "provider-unavailable":
				p.mu.Lock()
				p.failRead = true
				p.mu.Unlock()
			}
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.False(t, v.CanResolve)
			_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.Error(t, err)
			require.Zero(t, a.releases)
			p.mu.Lock()
			require.Zero(t, p.deletes)
			p.mu.Unlock()
		})
	}
}
func TestNetbirdRegistrationResolutionCurrentScopeAndImmutableRecords(t *testing.T) {
	f, _, s, resolver, r, _ := registrationResolutionFixture(t, "completed", true)
	_, err := resolver.Review(t.Context(), "viewer", r.Scope, r.DeviceID, r.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = resolver.Review(t.Context(), "admin", access.Scope{TenantID: r.Scope.TenantID, SiteID: f.otherSite}, r.DeviceID, r.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.NotNil(t, d.ConfirmedAt)
	for _, query := range []string{`DELETE FROM uem_netbird_registration_resolutions`, `DELETE FROM uem_netbird_registration_resolution_attempts`, `DELETE FROM uem_netbird_registration_resolution_evidence`, `UPDATE uem_netbird_registration_resolutions SET actor='admin'`, `UPDATE uem_netbird_registrations SET released_at=NULL,released_by=NULL`, `UPDATE uem_netbird_registrations SET status='completed',reason=''`} {
		_, err = f.db.ExecContext(t.Context(), query)
		require.Error(t, err)
	}
	require.Equal(t, "unconfirmed", registrationRead(t, f, s, r.ID).Status)
}

func TestNetbirdRegistrationResolutionNoDeliveryNeedsOnlyOwnedKeyAbsence(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	s := registrationStore(t, f, p, nil, nil)
	r := registrationRequest(t, f, s)
	_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_stop_delivery CHECK(resource_id NOT LIKE '%/register/deliver') NOT VALID`)
	require.NoError(t, err)
	_, err = s.DispatchOne(t.Context())
	require.Error(t, err)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_stop_delivery`)
	require.NoError(t, err)
	p.mu.Lock()
	p.failRead = true
	p.mu.Unlock()
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	p.mu.Lock()
	p.failRead = false
	p.mu.Unlock()
	resolver, err := inventory.NewNetbirdRegistrationResolutionStore(s, func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		t.Error("unattempted registration queried an agent receipt")
		return nil, errors.New("unexpected")
	})
	require.NoError(t, err)
	v, err := resolver.Review(t.Context(), "admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.Equal(t, "not-attempted", v.AgentState)
	require.True(t, v.CanResolve)
	d, err := resolver.Resolve(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.Equal(t, "not-delivered", d.Kind)
	require.NotNil(t, d.ConfirmedAt)
	require.Nil(t, d.AgentAttemptedAt)
	require.NotNil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
}

func TestNetbirdRegistrationResolutionMigrationGuards(t *testing.T) {
	f, _ := netbirdFixture(t)
	for _, guard := range [][2]string{{"uem_netbird_registration_resolutions", "uem_netbird_registration_intent_immutable"}, {"uem_netbird_registration_resolutions", "uem_netbird_registration_resolution_valid"}, {"uem_netbird_registration_resolution_attempts", "uem_netbird_registration_control_immutable"}, {"uem_netbird_registration_resolution_attempts", "uem_netbird_registration_control_valid"}, {"uem_netbird_registration_resolution_evidence", "uem_netbird_registration_proof_immutable"}, {"uem_netbird_registration_resolution_evidence", "uem_netbird_registration_proof_valid"}, {"uem_netbird_registrations", "uem_netbird_registration_release_required"}} {
		_, err := f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` DISABLE TRIGGER `+guard[1])
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` ENABLE TRIGGER `+guard[1])
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, inventory.Migrate(ctx, f.db))
}

func TestNetbirdRegistrationResolutionUsesCurrentIndividualIdentity(t *testing.T) {
	for _, change := range []string{"peer-renewed", "peer-revoked", "peer-expired", "peer-consumer", "peer-moved", "cleanup-renewed", "cleanup-revoked", "cleanup-expired", "cleanup-consumer", "cleanup-moved", "renewed", "withdraw-renewed", "retry-renewed", "retry-withdraw-renewed", "retry-revoked", "retry-expired", "retry-consumer", "retry-moved", "revoked", "expired", "consumer", "moved"} {
		t.Run(change, func(t *testing.T) {
			peerBinding := strings.HasPrefix(change, "peer-")
			change = strings.TrimPrefix(change, "peer-")
			cleanup := strings.HasPrefix(change, "cleanup-")
			change = strings.TrimPrefix(change, "cleanup-")
			retry := strings.HasPrefix(change, "retry-")
			change = strings.TrimPrefix(change, "retry-")
			withdrawal := change == "withdraw-renewed"
			f, id := netbirdFixture(t)
			p := newRegistrationProvider(t, f, id)
			p.retainDelete = cleanup
			ctx := t.Context()
			identities, err := registry.NewStore(f.db, strings.Repeat("r", 32))
			require.NoError(t, err)
			require.NoError(t, identities.Migrate(ctx))
			_, err = identities.EnsureAuthority(ctx, f.scope.TenantID, "Owned registration resolution fixture", "https://uem.example.test", "admin", nil, nil)
			require.NoError(t, err)
			invite, err := identities.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: f.scope.TenantID, SiteID: f.scope.SiteID}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
			require.NoError(t, err)
			keys, err := enrollment.GenerateKeys()
			require.NoError(t, err)
			defer keys.Broker.Wipe()
			claim, err := keys.Request(invite.URL[strings.LastIndex(invite.URL, "/")+1:], "windows", "amd64", "Owned registration resolution endpoint")
			require.NoError(t, err)
			response, err := identities.Claim(ctx, *claim)
			require.NoError(t, err)
			f.id = response.DeviceID
			require.NoError(t, f.client.Agent.Create().SetID(f.id).SetHostname("Owned registration resolution endpoint").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
			require.NoError(t, f.client.Netbird.Create().SetOwnerID(f.id).SetInstalled(true).Exec(ctx))
			_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1`, f.id)
			require.NoError(t, err)
			var command inventory.NetbirdOperationCommand
			releaseID, certificate := "", ""
			queries, releases := 0, 0
			control := func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				result, err := netbirdcommand.ControlResponseFor(c, "ok")
				require.NoError(t, err)
				if c.Kind == "registration-state" {
					result.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 4096}
					if command.RequestID != "" && releaseID == "" && !withdrawal {
						hash, err := command.Digest()
						require.NoError(t, err)
						result.State = netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("d", 64), Remaining: 4095, PendingID: command.RequestID, PendingHash: hash, CanRelease: true}
					}
					return &result, nil
				}
				if c.Kind == "release" || c.Kind == "withdraw" {
					releases++
					if !retry || releases > 1 {
						releaseID = c.RequestID
					}
					return nil, errors.New("owned release reply lost")
				}
				queries++
				certificate = c.CertificateHash
				require.True(t, c.Individual)
				if withdrawal && releaseID == "" {
					result.Outcome = "missing"
					return &result, nil
				}
				status := "unconfirmed"
				if withdrawal {
					status = "withdrawn"
				}
				result.Receipt, err = netbirdcommand.ReceiptFor(command, status)
				result.ReleaseID = releaseID
				return &result, err
			}
			s, err := inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), p.server.Client().Transport, control, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				command = c
				return nil, errors.New("owned registration reply lost")
			})
			require.NoError(t, err)
			r := registrationRequest(t, f, s)
			_, err = s.DispatchOne(ctx)
			require.NoError(t, err)
			if peerBinding {
				exerciseNetbirdPeerBindingIdentity(t, f, p, s, r, change)
				require.Zero(t, queries)
				require.Zero(t, releases)
				return
			}
			if cleanup {
				exerciseNetbirdCleanupIdentity(t, f, p, s, r, change)
				require.Zero(t, queries)
				require.Zero(t, releases)
				return
			}
			require.True(t, registrationRead(t, f, s, r.ID).KeyAbsent)
			resolver, err := inventory.NewNetbirdRegistrationResolutionStore(s, control)
			require.NoError(t, err)
			v, err := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			d, err := resolver.Resolve(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.NoError(t, err)
			require.Nil(t, d.ConfirmedAt)
			if retry {
				v, err = resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, err)
				require.True(t, v.CanRetry)
			}
			before := queries
			switch change {
			case "renewed", "withdraw-renewed":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('a',64) WHERE id=$1`, f.id)
			case "revoked":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "expired":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
			case "moved":
				err = f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(ctx)
			}
			require.NoError(t, err)
			if retry {
				_, err = resolver.Retry(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
				require.Error(t, err)
				require.Equal(t, 1, releases)
				if change == "renewed" || change == "withdraw-renewed" {
					fresh, e := resolver.Review(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID)
					require.NoError(t, e)
					require.NotEqual(t, v.Revision, fresh.Revision)
					retried, e := resolver.Retry(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), fresh.Revision)
					require.NoError(t, e)
					require.Nil(t, retried.ConfirmedAt)
					require.Equal(t, 2, releases)
					result, e := resolver.Reconcile(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID)
					require.NoError(t, e)
					require.NotNil(t, result.ConfirmedAt)
					require.Equal(t, strings.Repeat("a", 64), certificate)
					var hash string
					require.NoError(t, f.db.QueryRowContext(ctx, `SELECT control->>'certificate_hash' FROM uem_netbird_resolution_retries WHERE request_id=$1`, r.ID).Scan(&hash))
					require.Equal(t, certificate, hash)
				} else {
					require.Equal(t, before, queries)
				}
				return
			}
			result, err := resolver.Reconcile(ctx, "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID)
			if change == "renewed" || change == "withdraw-renewed" {
				require.NoError(t, err)
				require.NotNil(t, result.ConfirmedAt)
				require.Equal(t, strings.Repeat("a", 64), certificate)
				require.Equal(t, before+1, queries)
			} else {
				require.Error(t, err)
				require.Equal(t, before, queries)
				require.Nil(t, registrationRead(t, f, s, r.ID).ReleasedAt)
			}
			require.Equal(t, 1, releases)
			p.mu.Lock()
			require.Equal(t, 1, p.creates)
			require.Equal(t, 1, p.deletes)
			p.mu.Unlock()
		})
	}
}
