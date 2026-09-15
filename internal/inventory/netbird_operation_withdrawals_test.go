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
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/stretchr/testify/require"
)

type ownedConnectionWithdrawal struct {
	command                                                        netbirdcommand.Command
	status, release, withdrawal, journalRevision                   string
	supported, active, full, lostReply, lostRequest, legacyMissing bool
	queries, withdrawals, releases, deliveries                     int
	onWithdraw                                                     func()
}

func connectionWithdrawalFixture(t *testing.T, operation string) (*refreshFixture, *inventory.NetbirdOperationStore, *inventory.NetbirdResolutionStore, *inventory.NetbirdOperation, *ownedConnectionWithdrawal) {
	t.Helper()
	f, _ := netbirdFixture(t)
	a := &ownedConnectionWithdrawal{status: "missing", supported: true, journalRevision: strings.Repeat("b", 64)}
	s, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, false, func(ctx context.Context, _ netbirdcommand.Identity) (netbirdcommand.State, error) {
		if a.command.RequestID == "" {
			return netbirdReady(ctx, netbirdcommand.Identity{})
		}
		state := netbirdcommand.State{Status: "ready", Revision: a.journalRevision, Remaining: 4096}
		if a.full {
			state.Status = "full"
			state.Remaining = 0
		}
		if a.status == "unconfirmed" && a.release == "" {
			hash, _ := a.command.Digest()
			state = netbirdcommand.State{Status: "unconfirmed", Revision: a.journalRevision, Remaining: 4095, PendingID: a.command.RequestID, PendingHash: hash, CanRelease: !a.active}
		}
		return state, nil
	}, func(_ context.Context, c netbirdcommand.Command) (*inventory.NetbirdOperationResult, error) {
		a.command = c
		a.deliveries++
		return nil, errors.New("owned original command response loss")
	})
	require.NoError(t, err)
	profile := ""
	if operation == "switchprofile" {
		profile = "other-id"
	}
	r := netbirdRequest(t, f, s, operation, profile)
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	resolver, err := inventory.NewNetbirdResolutionStore(s, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		a.queries++
		if c.Version == netbirdcommand.RecoveryVersion && !a.supported {
			return nil, errors.New("owned legacy agent")
		}
		if c.Kind == "withdraw" || c.Kind == "release" {
			var n int
			digest, e := c.Digest()
			require.NoError(t, e)
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM uem_netbird_resolutions WHERE request_id=$1 AND id=$2 AND control_hash=$3)+(SELECT count(*) FROM uem_netbird_resolution_retries WHERE family='operation' AND request_id=$1 AND resolution_id=$2 AND control_hash=$3)`, r.ID, c.RequestID, digest).Scan(&n))
			require.Equal(t, 1, n, "the exact control must commit before transmission")
			if c.Kind == "withdraw" {
				a.withdrawals++
				require.Equal(t, r.Revision, c.Revision)
				require.Equal(t, operation, c.Operation)
				if a.onWithdraw != nil {
					a.onWithdraw()
				}
				if a.status != "missing" {
					p, e := netbirdcommand.ControlResponseFor(c, "conflict")
					return &p, e
				}
			} else {
				a.releases++
			}
			if a.lostRequest {
				return nil, errors.New("owned control was not delivered")
			}
			if c.Kind == "withdraw" {
				a.status = "withdrawn"
				a.withdrawal = c.RequestID
			} else {
				a.release = c.RequestID
			}
			if a.lostReply {
				return nil, errors.New("owned control reply lost")
			}
		}
		if a.status == "missing" || a.legacyMissing && c.Kind == "receipt" && c.Version == netbirdcommand.Version {
			p, e := netbirdcommand.ControlResponseFor(c, "missing")
			return &p, e
		}
		if a.status == "withdrawn" {
			// Construct withdrawal proof only on the recovery protocol.
			if c.Version != netbirdcommand.RecoveryVersion {
				response, e := netbirdcommand.ControlResponseFor(c, "conflict")
				return &response, e
			}
			response, e := netbirdcommand.ControlResponseFor(c, "ok")
			require.NoError(t, e)
			response.Receipt, e = netbirdcommand.ReceiptFor(a.command, "withdrawn")
			require.NoError(t, e)
			response.ReleaseID = a.withdrawal
			return &response, nil
		}
		return netbirdResolutionResponse(t, f, c, a.status, a.release), nil
	})
	require.NoError(t, err)
	return f, s, resolver, r, a
}

func TestNetbirdConnectionWithdrawalRetainsPermanentProofForEveryCommand(t *testing.T) {
	for _, operation := range []string{"up", "down", "switchprofile"} {
		for _, loss := range []string{"none", "reply", "request", "final-audit"} {
			t.Run(operation+"/"+loss, func(t *testing.T) {
				f, s, resolver, r, a := connectionWithdrawalFixture(t, operation)
				a.lostReply = loss == "reply"
				a.lostRequest = loss == "request"
				v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, err)
				require.True(t, v.CanWithdraw)
				require.False(t, v.CanRelease)
				require.Equal(t, "not-received", v.Outcome)
				if loss == "final-audit" {
					_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_connection_proof_failure CHECK(action<>'inventory.netbird.release') NOT VALID`)
					require.NoError(t, err)
				}
				id := uuid.NewString()
				d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
				if loss == "final-audit" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					if loss == "none" {
						require.NotNil(t, d.ConfirmedAt)
					} else {
						require.Nil(t, d.ConfirmedAt)
					}
				}
				require.Equal(t, 1, a.withdrawals)
				require.Zero(t, a.releases)
				before := a.queries
				d, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
				require.NoError(t, err)
				require.Equal(t, before, a.queries)
				require.Equal(t, "withdraw", d.Kind)
				if loss == "final-audit" {
					_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_connection_proof_failure`)
					require.NoError(t, err)
				}
				d, err = resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id)
				require.NoError(t, err)
				if loss == "request" {
					require.Nil(t, d.ConfirmedAt)
					v, err = resolver.Review(t.Context(), "admin", r.Scope, r.DeviceID, r.ID)
					require.NoError(t, err)
					require.True(t, v.CanRetry)
					require.Equal(t, "withdraw", v.RetryKind)
					a.lostRequest = false
					retry := uuid.NewString()
					d, err = resolver.Retry(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, id, retry, v.Revision)
					require.NoError(t, err)
					require.Equal(t, retry, d.LastRetry.ID)
					before = a.queries
					_, err = resolver.Retry(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, id, retry, v.Revision)
					require.NoError(t, err)
					require.Equal(t, before, a.queries)
				}
				require.NotNil(t, d.ConfirmedAt)
				retained := netbirdRead(t, f, s, r.ID)
				require.NotNil(t, retained.ReleasedAt)
				require.Equal(t, "unconfirmed", retained.Status)
				require.Nil(t, retained.Result)
				require.Equal(t, 1, a.deliveries)
				var control, proof string
				require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT control::text,response::text FROM uem_netbird_resolution_evidence WHERE request_id=$1`, r.ID).Scan(&control, &proof))
				require.Contains(t, control, `"version": 2`)
				require.Contains(t, proof, `"status": "withdrawn"`)
				require.NoError(t, f.client.Agent.DeleteOneID(r.DeviceID).Exec(t.Context()))
				require.NotNil(t, netbirdRead(t, f, s, r.ID).Resolution.ConfirmedAt)
			})
		}
	}
}

func TestNetbirdConnectionWithdrawalExecutionRaceNeedsMatchingRecovery(t *testing.T) {
	for _, status := range []string{"completed", "unconfirmed", "active"} {
		t.Run(status, func(t *testing.T) {
			f, s, resolver, r, a := connectionWithdrawalFixture(t, "down")
			a.onWithdraw = func() {
				a.status = status
				if status == "active" {
					a.status = "unconfirmed"
					a.active = true
				}
			}
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.NoError(t, err)
			require.Nil(t, d.ConfirmedAt)
			d, err = resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID)
			require.NoError(t, err)
			if status == "completed" {
				require.NotNil(t, d.ConfirmedAt)
				require.Zero(t, a.releases)
			} else {
				require.Nil(t, d.ConfirmedAt)
				v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, err)
				if status == "active" {
					require.False(t, v.CanRetry)
					a.active = false
					v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
					require.NoError(t, err)
				}
				require.True(t, v.CanRetry)
				require.Equal(t, "release", v.RetryKind)
				a.lostReply = true
				d, err = resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
				require.NoError(t, err)
				require.Nil(t, d.ConfirmedAt)
				d, err = resolver.Reconcile(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID)
				require.NoError(t, err)
				require.NotNil(t, d.ConfirmedAt)
				require.Equal(t, 1, a.releases)
			}
			require.Equal(t, "withdraw", d.Kind)
			require.Equal(t, 1, a.withdrawals)
			require.Equal(t, 1, a.deliveries)
			require.Equal(t, "unconfirmed", netbirdRead(t, f, s, r.ID).Status)
		})
	}
}

func TestNetbirdConnectionWithdrawalNeverInfersSupportOrUsesStaleReview(t *testing.T) {
	for _, change := range []string{"legacy", "full", "foreign-withdrawal", "changed-journal", "moved", "audit"} {
		t.Run(change, func(t *testing.T) {
			f, s, resolver, r, a := connectionWithdrawalFixture(t, "up")
			v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			switch change {
			case "legacy":
				a.supported = false
			case "full":
				a.full = true
			case "foreign-withdrawal":
				a.status = "withdrawn"
				a.withdrawal = uuid.NewString()
			case "changed-journal":
				a.journalRevision = strings.Repeat("c", 64)
			case "moved":
				err = f.client.Agent.UpdateOneID(r.DeviceID).RemoveSiteIDs(r.Scope.SiteID).AddSiteIDs(f.otherSite).Exec(t.Context())
				require.NoError(t, err)
			case "audit":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_connection_intent_failure CHECK(action<>'inventory.netbird.resolution.attempt') NOT VALID`)
				require.NoError(t, err)
			}
			_, err = resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.Error(t, err)
			require.Zero(t, a.withdrawals)
			require.Zero(t, a.releases)
			require.Nil(t, netbirdRead(t, f, s, r.ID).ReleasedAt)
		})
	}
}

func TestNetbirdConnectionWithdrawalConcurrentConfirmationSendsOnce(t *testing.T) {
	_, _, resolver, r, a := connectionWithdrawalFixture(t, "up")
	a.lostRequest = true
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	id := uuid.NewString()
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			_, e := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			require.NoError(t, e)
		})
	}
	wg.Wait()
	require.Equal(t, 1, a.withdrawals)
}

func TestNetbirdConnectionWithdrawalDatabaseGuards(t *testing.T) {
	f, _, resolver, r, a := connectionWithdrawalFixture(t, "switchprofile")
	a.lostRequest = true
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	var data []byte
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT control FROM uem_netbird_resolutions WHERE request_id=$1`, r.ID).Scan(&data))
	var c netbirdcommand.ControlRequest
	require.NoError(t, json.Unmarshal(data, &c))
	c.Kind = "receipt"
	c.RequestID = uuid.NewString()
	c.IssuedAt = time.Now().UTC()
	c.ExpiresAt = c.IssuedAt.Add(time.Second)
	p, e := netbirdcommand.ControlResponseFor(c, "ok")
	require.NoError(t, e)
	p.Receipt, e = netbirdcommand.ReceiptFor(a.command, "unconfirmed")
	require.NoError(t, e)
	p.ReleaseID = d.ID
	wire, e := netbirdcommand.EncodeControl(c)
	require.NoError(t, e)
	proof, e := netbirdcommand.EncodeControlResponse(c, p)
	require.NoError(t, e)
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_resolution_evidence(request_id,resolution_id,actor,control,response) VALUES($1,$2,'tag-admin',$3::jsonb,$4::jsonb)`, r.ID, d.ID, string(wire), string(proof))
	require.Error(t, err, "unconfirmed proof needs a separately admitted release phase")
	_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_resolutions SET kind='release' WHERE request_id=$1`, r.ID)
	require.Error(t, err)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_resolutions DISABLE TRIGGER uem_netbird_resolution_intent_valid`)
	require.NoError(t, err)
	require.Error(t, inventory.Migrate(t.Context(), f.db))
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_resolutions ENABLE TRIGGER uem_netbird_resolution_intent_valid`)
	require.NoError(t, err)
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}

func TestNetbirdRecoveryQueryCanAcknowledgeCompletionDuringCapabilityDiscovery(t *testing.T) {
	t.Run("connection", func(t *testing.T) {
		f, _, resolver, r, a := connectionWithdrawalFixture(t, "up")
		a.status = "completed"
		a.legacyMissing = true
		v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
		require.NoError(t, err)
		require.True(t, v.CanRelease)
		require.False(t, v.CanWithdraw)
		d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
		require.NoError(t, err)
		require.NotNil(t, d.ConfirmedAt)
		require.Equal(t, "acknowledge", d.Kind)
		require.Zero(t, a.withdrawals)
		require.Zero(t, a.releases)
		var version int
		require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT (control->>'version')::integer FROM uem_netbird_resolution_evidence WHERE request_id=$1`, r.ID).Scan(&version))
		require.Equal(t, 2, version)
	})
	t.Run("registration", func(t *testing.T) {
		f, _, s, _, r, a := registrationResolutionFixture(t, "completed", true)
		resolver, err := inventory.NewNetbirdRegistrationResolutionStore(s, func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
			outcome := "ok"
			if c.Version == netbirdcommand.Version {
				outcome = "missing"
			}
			p, e := netbirdcommand.ControlResponseFor(c, outcome)
			require.NoError(t, e)
			if outcome == "ok" {
				p.Receipt, e = netbirdcommand.ReceiptFor(a.command, "completed")
				require.NoError(t, e)
			}
			return &p, nil
		})
		require.NoError(t, err)
		v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
		require.NoError(t, err)
		require.Equal(t, "completed", v.AgentState)
		d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
		require.NoError(t, err)
		require.NotNil(t, d.ConfirmedAt)
		require.Equal(t, "acknowledge", d.Kind)
		var version int
		require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT (control->>'version')::integer FROM uem_netbird_registration_resolution_evidence WHERE request_id=$1`, r.ID).Scan(&version))
		require.Equal(t, 2, version)
	})
}

func TestNetbirdConnectionWithdrawalIntentRequiresOriginalMetadata(t *testing.T) {
	f, _, resolver, r, a := connectionWithdrawalFixture(t, "up")
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	hash, err := a.command.Digest()
	require.NoError(t, err)
	c := netbirdcommand.ControlRequest{Version: netbirdcommand.RecoveryVersion, Identity: a.command.Identity, RequestID: uuid.NewString(), Kind: "withdraw", ReferenceID: r.ID, Revision: r.Revision, Operation: r.Operation, CommandHash: hash, IssuedAt: time.Now().UTC()}
	c.ExpiresAt = c.IssuedAt.Add(time.Second)
	wire, err := netbirdcommand.EncodeControl(c)
	require.NoError(t, err)
	digest, err := c.Digest()
	require.NoError(t, err)
	for _, alter := range []string{"valid", "version", "revision", "operation", "reference", "unknown", "deadline"} {
		var fields map[string]any
		require.NoError(t, json.Unmarshal(wire, &fields))
		switch alter {
		case "version":
			fields["version"] = 1
		case "revision":
			fields["revision"] = strings.Repeat("e", 64)
		case "operation":
			fields["operation"] = "down"
		case "reference":
			fields["reference_id"] = uuid.NewString()
		case "unknown":
			fields["setup_key"] = "injected"
		case "deadline":
			fields["expires_at"] = fields["issued_at"]
		}
		changed, e := json.Marshal(fields)
		require.NoError(t, e)
		tx, e := f.db.BeginTx(t.Context(), nil)
		require.NoError(t, e)
		_, e = tx.ExecContext(t.Context(), `INSERT INTO uem_netbird_resolutions(request_id,id,device_id,tenant_id,site_id,actor,individual,command_hash,revision,kind,control,control_hash) VALUES($1,$2,$3,$4,$5,'tag-admin',false,$6,$7,'withdraw',$8::jsonb,$9)`, r.ID, c.RequestID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, hash, v.Revision, string(changed), digest)
		require.NoError(t, tx.Rollback())
		if alter == "valid" {
			require.NoError(t, e)
		} else {
			require.Error(t, e, alter)
		}
	}
	d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, c.RequestID, v.Revision)
	require.NoError(t, err)
	require.NotNil(t, d.ConfirmedAt)
}

func TestNetbirdConnectionWithdrawalCannotResumeAfterReleaseRecovery(t *testing.T) {
	_, _, resolver, r, a := connectionWithdrawalFixture(t, "down")
	a.onWithdraw = func() { a.status = "unconfirmed" }
	v, err := resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	d, err := resolver.Resolve(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	a.lostRequest = true
	d, err = resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.Nil(t, d.ConfirmedAt)
	a.status = "missing"
	v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.False(t, v.CanRetry)
	require.False(t, v.CanWithdraw)
	_, err = resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
	require.Error(t, err)
	require.Equal(t, 1, a.withdrawals)
	require.Equal(t, 1, a.releases)
	a.status = "unconfirmed"
	a.lostRequest = false
	v, err = resolver.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.Equal(t, "release", v.RetryKind)
	d, err = resolver.Retry(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, d.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.NotNil(t, d.ConfirmedAt)
	require.Equal(t, int64(2), d.LastRetry.Sequence)
}
