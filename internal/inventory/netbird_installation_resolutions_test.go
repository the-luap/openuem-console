package inventory_test

import (
	"context"
	"encoding/json"
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

type installationResolutionFixture struct {
	f                          *refreshFixture
	s, requests                *inventory.NetbirdInstallationStore
	packages                   *inventory.NetbirdPackageStore
	r                          *inventory.NetbirdInstallation
	command                    netbirdcommand.Command
	status, releaseID          string
	canRelease                 bool
	journalRevision            string
	mutations, native, queries int
	loseBefore, loseAfter      bool
	responseChange             func(*netbirdcommand.ControlResponse)
	beforeMutation             func(context.Context, netbirdcommand.ControlRequest)
}

func newInstallationResolutionFixture(t *testing.T, status string) *installationResolutionFixture {
	t.Helper()
	f, requests, packages, pkg := installationFixture(t, nil)
	x := &installationResolutionFixture{f: f, requests: requests, packages: packages, status: status, canRelease: true, journalRevision: strings.Repeat("a", 64)}
	x.r = installationRequest(t, f, requests, pkg)
	x.s = installationDeliveryStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if c.Kind == "preparation-state" || c.Kind == "installation-state" {
			return installationCapabilities(ctx, c)
		}
		if c.Kind == "state" {
			p, err := netbirdcommand.ControlResponseFor(c, "ok")
			p.State = netbirdcommand.State{Status: "ready", Revision: x.journalRevision, Remaining: 100}
			if x.status == "unconfirmed" {
				hash, e := x.command.Digest()
				require.NoError(t, e)
				p.State.Status = "unconfirmed"
				p.State.PendingID = x.r.ID
				p.State.PendingHash = hash
				p.State.CanRelease = x.canRelease
			}
			return &p, err
		}
		if c.Kind == "withdraw" || c.Kind == "release" {
			x.mutations++
			if x.beforeMutation != nil {
				x.beforeMutation(ctx, c)
			}
			if x.loseBefore {
				return nil, errors.New("owned unavailable control")
			}
			x.releaseID = c.RequestID
			if c.Kind == "withdraw" {
				x.status = "withdrawn"
			} else {
				x.status = "unconfirmed"
			}
			if x.loseAfter {
				return nil, errors.New("owned lost control reply")
			}
		} else {
			x.queries++
		}
		outcome := "ok"
		if x.status == "missing" {
			outcome = "missing"
		}
		p, err := netbirdcommand.ControlResponseFor(c, outcome)
		require.NoError(t, err)
		if outcome == "ok" {
			hash, e := x.command.Digest()
			require.NoError(t, e)
			p.Receipt = netbirdcommand.Receipt{Version: 1, RequestID: x.r.ID, DeviceID: f.id, Revision: x.r.Revision, CommandHash: hash, Operation: "install", Status: x.status}
			p.ReleaseID = x.releaseID
		}
		if x.responseChange != nil {
			x.responseChange(&p)
		}
		return &p, nil
	}, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		x.native++
		x.command = c
		return nil, errors.New("owned lost native result")
	})
	_, err := x.s.Prepare(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, x.r.Revision)
	require.NoError(t, err)
	_, err = x.s.Install(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, x.r.Revision)
	require.NoError(t, err)
	return x
}

func (x *installationResolutionFixture) review(t *testing.T) *inventory.NetbirdInstallationResolutionReview {
	t.Helper()
	v, err := x.s.ReviewInstallationResolution(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision)
	require.NoError(t, err)
	return v
}
func (x *installationResolutionFixture) resolve(t *testing.T, v *inventory.NetbirdInstallationResolutionReview) *inventory.NetbirdInstallationResolution {
	t.Helper()
	d, err := x.s.ResolveInstallation(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision, v.ResolutionID, v.Revision)
	require.NoError(t, err)
	return d
}
func (x *installationResolutionFixture) reconcile(t *testing.T, id string) *inventory.NetbirdInstallationResolution {
	t.Helper()
	d, err := x.s.ReconcileInstallationResolution(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision, id)
	require.NoError(t, err)
	return d
}

func TestNetbirdInstallationResolutionCommitsReviewedControlBeforeTransport(t *testing.T) {
	for _, status := range []string{"missing", "unconfirmed"} {
		t.Run(status, func(t *testing.T) {
			x := newInstallationResolutionFixture(t, status)
			v := x.review(t)
			kind := "withdraw"
			version := 2
			if status == "unconfirmed" {
				kind = "release"
				version = 1
			}
			require.Equal(t, kind, v.Kind)
			require.NotEmpty(t, v.Revision)
			require.NotNil(t, v.ExpiresAt)
			require.WithinDuration(t, time.Now().Add(2*time.Minute), *v.ExpiresAt, 5*time.Second)
			x.beforeMutation = func(ctx context.Context, c netbirdcommand.ControlRequest) {
				require.Equal(t, kind, c.Kind)
				require.Equal(t, version, c.Version)
				require.Equal(t, v.ResolutionID, c.RequestID)
				require.Equal(t, x.r.ID, c.ReferenceID)
				require.LessOrEqual(t, c.ExpiresAt.Sub(c.IssuedAt), 10*time.Second)
				var retained, hash string
				require.NoError(t, x.f.db.QueryRowContext(ctx, `SELECT control::text,control_hash FROM uem_netbird_installation_controls WHERE request_id=$1`, x.r.ID).Scan(&retained, &hash))
				decoded, err := netbirdcommand.DecodeControl([]byte(retained))
				require.NoError(t, err)
				require.Equal(t, c, decoded)
				actual, err := c.Digest()
				require.NoError(t, err)
				require.Equal(t, actual, hash)
				var audits int
				require.NoError(t, x.f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND action='inventory.netbird.resolution.attempt'`, x.r.ID).Scan(&audits))
				require.Equal(t, 1, audits)
				// Reading via another connection while delivering cannot wait on admission.
				read, err := x.s.ReadInstallationResolution(ctx, "viewer", x.f.scope, x.f.id, x.r.ID, x.r.Revision)
				require.NoError(t, err)
				require.Equal(t, "pending", read.LastAttempt.Outcome)
			}
			d := x.resolve(t, v)
			require.NotNil(t, d.ConfirmedAt)
			require.Nil(t, d.CompletedAt)
			require.Equal(t, "operator", d.ConfirmedBy)
			require.Equal(t, 1, d.LastAttempt.Sequence)
			replay := x.resolve(t, v)
			require.Equal(t, d, replay)
			require.Equal(t, 1, x.mutations)
			require.Equal(t, 1, x.native)
			delivery, err := x.s.ReadDelivery(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
			require.NoError(t, err)
			require.Equal(t, "released", delivery.Outcome)
			require.Equal(t, "unconfirmed", delivery.OriginalOutcome)
			require.Nil(t, delivery.CompletedAt)
			require.Equal(t, d.ConfirmedAt, delivery.ReleasedAt)
			queries := x.queries
			require.Equal(t, d, x.reconcile(t, d.ID))
			require.Equal(t, queries, x.queries)
			read, err := x.requests.Read(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
			require.NoError(t, err)
			require.Equal(t, d.ID, read.ResolutionID)
			_, err = x.requests.Cancel(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision, uuid.NewString())
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			data, err := json.Marshal([]any{d, delivery, read, v})
			require.NoError(t, err)
			require.NotContains(t, string(data), "certificate_hash")
			require.NotContains(t, string(data), "owned-installation-source")
			// Every device family shares the barrier; historic UUIDs remain reserved.
			insert := `INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,profile,revision,requested_at,expires_at) VALUES($1,$2,$3,$4,'operator',true,'up','',repeat('a',64),clock_timestamp(),clock_timestamp()+interval '1 minute')`
			_, err = x.f.db.ExecContext(t.Context(), insert, x.r.ID, x.f.id, x.f.scope.TenantID, x.f.scope.SiteID)
			require.Error(t, err)
			next := uuid.NewString()
			_, err = x.f.db.ExecContext(t.Context(), insert, next, x.f.id, x.f.scope.TenantID, x.f.scope.SiteID)
			require.NoError(t, err)
			ops, err := inventory.NewNetbirdOperationStore(x.f.db, x.f.permissions, true, netbirdReady, netbirdSuccess)
			require.NoError(t, err)
			require.NoError(t, ops.Cancel(t.Context(), "tag-admin", x.f.scope, x.f.id, next))
			// Exercise the installation partial unique index through normal admission.
			fresh, err := x.requests.Request(t.Context(), "tag-admin", x.f.scope, x.f.id, uuid.NewString(), x.r.ApprovalID, x.r.ApprovalDigest, x.r.Revision)
			require.NoError(t, err)
			require.NotEqual(t, x.r.ID, fresh.ID)
		})
	}
}

func TestNetbirdInstallationResolutionRecoversLostReplyUnderCurrentAuthority(t *testing.T) {
	for _, status := range []string{"missing", "unconfirmed"} {
		t.Run(status, func(t *testing.T) {
			x := newInstallationResolutionFixture(t, status)
			v := x.review(t)
			x.loseAfter = true
			d := x.resolve(t, v)
			require.Nil(t, d.ConfirmedAt)
			require.Equal(t, "unavailable", d.LastAttempt.Outcome)
			_, err := x.f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, x.f.id)
			require.NoError(t, err)
			_, err = x.packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: x.f.scope.TenantID}, x.r.ApprovalID, x.r.ApprovalDigest, uuid.NewString())
			require.NoError(t, err)
			// Ordinary observation cannot free an owned or foreign withdrawal by itself.
			observed, err := x.s.ObserveInstallation(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision)
			require.NoError(t, err)
			require.Nil(t, observed.ReleasedAt)
			require.Equal(t, "awaiting-confirmation", x.review(t).Outcome)
			x.responseChange = func(p *netbirdcommand.ControlResponse) { require.Equal(t, strings.Repeat("e", 64), p.CertificateHash) }
			confirmed := x.reconcile(t, d.ID)
			require.NotNil(t, confirmed.ConfirmedAt)
			require.Equal(t, 1, x.mutations)
			// Historical result survives, including the original uncertain native result.
			var outcome string
			require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT outcome FROM uem_netbird_installation_results WHERE request_id=$1`, x.r.ID).Scan(&outcome))
			require.Equal(t, "unconfirmed", outcome)
		})
	}
}

func TestNetbirdInstallationResolutionRetriesOnlyNewReviewedControl(t *testing.T) {
	for _, transition := range []string{"withdraw", "release", "withdraw-to-release"} {
		t.Run(transition, func(t *testing.T) {
			status := "missing"
			if transition == "release" {
				status = "unconfirmed"
			}
			x := newInstallationResolutionFixture(t, status)
			first := x.review(t)
			x.loseBefore = true
			d := x.resolve(t, first)
			require.Nil(t, d.ConfirmedAt)
			require.Equal(t, d, x.resolve(t, first))
			require.Equal(t, 1, x.mutations)
			if transition == "withdraw-to-release" {
				x.status = "unconfirmed"
			}
			second := x.review(t)
			require.Equal(t, first.ResolutionID, second.ResolutionID)
			require.NotEqual(t, first.Revision, second.Revision)
			x.loseBefore = false
			d = x.resolve(t, second)
			require.NotNil(t, d.ConfirmedAt)
			require.Equal(t, 2, d.LastAttempt.Sequence)
			require.Equal(t, 2, x.mutations)
			require.Equal(t, 1, x.native)
			require.Equal(t, d, x.resolve(t, first))
			require.Equal(t, 2, x.mutations)
		})
	}
}

func TestNetbirdInstallationResolutionRejectsChangedOrExpiredReview(t *testing.T) {
	for _, change := range []string{"certificate", "consumer", "permission", "scope", "revision", "journal", "receipt", "expiry", "audit"} {
		t.Run(change, func(t *testing.T) {
			x := newInstallationResolutionFixture(t, "missing")
			v := x.review(t)
			scope := x.f.scope
			revision := x.r.Revision
			var err error
			switch change {
			case "certificate":
				_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, x.f.id)
			case "consumer":
				_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, x.f.id)
			case "permission":
				p, e := x.f.permissions.Principal(t.Context(), "operator")
				require.NoError(t, e)
				err = x.f.permissions.ReplaceGrants(t.Context(), "admin", "operator", p.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: x.f.scope.TenantID}}})
			case "scope":
				scope.SiteID = x.f.otherSite
			case "revision":
				revision = strings.Repeat("e", 64)
			case "journal":
				x.journalRevision = strings.Repeat("e", 64)
			case "receipt":
				x.status = "unconfirmed"
			case "expiry":
				_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_installation_reviews DISABLE TRIGGER uem_netbird_installation_review_immutable`)
				require.NoError(t, err)
				_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_netbird_installation_reviews SET created_at=created_at-interval '3 minutes',expires_at=expires_at-interval '3 minutes'`)
			case "audit":
				_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_resolution_audit CHECK(action<>'inventory.netbird.resolution.attempt') NOT VALID`)
			}
			require.NoError(t, err)
			_, err = x.s.ResolveInstallation(t.Context(), "operator", scope, x.f.id, x.r.ID, revision, v.ResolutionID, v.Revision)
			require.Error(t, err)
			require.Zero(t, x.mutations)
			var n int
			require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_controls`).Scan(&n))
			require.Zero(t, n)
		})
	}
}

func TestNetbirdInstallationResolutionKeepsBarrierForUnownedOrIneligibleEvidence(t *testing.T) {
	for _, condition := range []string{"orphan", "foreign", "missing-after-release", "released-without-release-attempt", "wrong-operation", "wrong-hash", "wrong-query", "unavailable", "audit"} {
		t.Run(condition, func(t *testing.T) {
			x := newInstallationResolutionFixture(t, "unconfirmed")
			if condition == "orphan" {
				x.canRelease = false
				v := x.review(t)
				require.Empty(t, v.Revision)
				require.Equal(t, "waiting", v.Outcome)
				require.Zero(t, x.mutations)
				return
			}
			if condition == "released-without-release-attempt" {
				x.status = "missing"
			}
			first := x.review(t)
			x.loseBefore = true
			d := x.resolve(t, first)
			switch condition {
			case "foreign":
				x.releaseID = uuid.NewString()
			case "missing-after-release":
				x.status = "missing"
			case "released-without-release-attempt":
				x.status = "unconfirmed"
				x.releaseID = d.ID
			case "wrong-operation":
				x.responseChange = func(p *netbirdcommand.ControlResponse) { p.Receipt.Operation = "up" }
			case "wrong-hash":
				x.responseChange = func(p *netbirdcommand.ControlResponse) { p.Receipt.CommandHash = strings.Repeat("f", 64) }
			case "wrong-query":
				x.responseChange = func(p *netbirdcommand.ControlResponse) { p.RequestID = uuid.NewString() }
			case "unavailable":
				x.responseChange = func(p *netbirdcommand.ControlResponse) { p.Outcome = "unavailable" }
			case "audit":
				x.releaseID = d.ID
				_, err := x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_release_audit CHECK(action<>'inventory.netbird.release') NOT VALID`)
				require.NoError(t, err)
			}
			got, err := x.s.ReconcileInstallationResolution(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision, d.ID)
			if condition == "audit" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Nil(t, got.ConfirmedAt)
			}
			read, err := x.requests.Read(t.Context(), "viewer", x.f.scope, x.f.id, x.r.ID)
			require.NoError(t, err)
			require.Nil(t, read.ReleasedAt)
			require.Nil(t, read.CompletedAt)
			_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_netbird_installations SET released_at=clock_timestamp(),released_by='operator',resolution_id=$2 WHERE id=$1`, x.r.ID, d.ID)
			require.Error(t, err)
			require.Equal(t, 1, x.mutations)
		})
	}
}

func TestNetbirdInstallationResolutionRecoversCompletionAndAtomicAuditFailure(t *testing.T) {
	for _, completion := range []bool{false, true} {
		t.Run(map[bool]string{false: "release", true: "completion"}[completion], func(t *testing.T) {
			x := newInstallationResolutionFixture(t, "missing")
			v := x.review(t)
			if completion {
				x.loseBefore = true
			} else {
				_, err := x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_release_audit CHECK(action<>'inventory.netbird.release') NOT VALID`)
				require.NoError(t, err)
			}
			d, err := x.s.ResolveInstallation(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision, v.ResolutionID, v.Revision)
			if completion {
				require.NoError(t, err)
				x.status = "completed"
			} else {
				require.Error(t, err)
				require.Nil(t, d)
				var n int
				require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_control_results`).Scan(&n))
				require.Zero(t, n)
				_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_install_release_audit`)
				require.NoError(t, err)
			}
			d = x.reconcile(t, v.ResolutionID)
			if completion {
				require.NotNil(t, d.CompletedAt)
				require.Nil(t, d.ConfirmedAt)
			} else {
				require.NotNil(t, d.ConfirmedAt)
			}
			require.Equal(t, 1, x.mutations)
			require.Equal(t, 1, x.native)
		})
	}
}

func TestNetbirdInstallationResolutionIndependentSQLProofAndStartupGuards(t *testing.T) {
	x := newInstallationResolutionFixture(t, "unconfirmed")
	v := x.review(t)
	// Lose the database result after the separately committed control admission.
	_, err := x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_proof_audit CHECK(action<>'inventory.netbird.resolution.observe') NOT VALID`)
	require.NoError(t, err)
	_, err = x.s.ResolveInstallation(t.Context(), "operator", x.f.scope, x.f.id, x.r.ID, x.r.Revision, v.ResolutionID, v.Revision)
	require.Error(t, err)
	_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_install_proof_audit`)
	require.NoError(t, err)
	var wire []byte
	var attempt string
	require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT id::text,control FROM uem_netbird_installation_controls WHERE request_id=$1`, x.r.ID).Scan(&attempt, &wire))
	c, err := netbirdcommand.DecodeControl(wire)
	require.NoError(t, err)
	p, err := netbirdcommand.ControlResponseFor(c, "ok")
	require.NoError(t, err)
	p.Receipt = netbirdcommand.Receipt{Version: 1, RequestID: x.r.ID, DeviceID: x.f.id, Revision: x.r.Revision, CommandHash: c.CommandHash, Operation: "install", Status: "unconfirmed"}
	p.ReleaseID = v.ResolutionID
	encoded, err := netbirdcommand.EncodeControlResponse(c, p)
	require.NoError(t, err)
	for _, change := range []string{"status", "release", "revision", "certificate", "hash", "kind", "extra", "state", "missing-release"} {
		var raw map[string]any
		require.NoError(t, json.Unmarshal(encoded, &raw))
		switch change {
		case "status":
			raw["receipt"].(map[string]any)["status"] = "completed"
		case "release":
			raw["release_id"] = uuid.NewString()
		case "revision":
			raw["receipt"].(map[string]any)["revision"] = strings.Repeat("f", 64)
		case "certificate":
			raw["certificate_hash"] = strings.Repeat("f", 64)
		case "hash":
			raw["request_hash"] = strings.Repeat("f", 64)
		case "kind":
			raw["kind"] = "receipt"
		case "extra":
			raw["source"] = "https://owned.example.test/private"
		case "state":
			raw["state"].(map[string]any)["can_release"] = true
		case "missing-release":
			delete(raw, "release_id")
		}
		altered, e := json.Marshal(raw)
		require.NoError(t, e)
		_, err = x.f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_control_results(attempt_id,response) VALUES($1,$2::jsonb)`, attempt, string(altered))
		require.Error(t, err, change)
	}
	var n int
	require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_control_results`).Scan(&n))
	require.Zero(t, n)
	_, err = x.f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_control_results(attempt_id,response) VALUES($1,$2::jsonb)`, attempt, string(encoded))
	require.NoError(t, err)
	for _, resolution := range []string{uuid.NewString(), x.r.ID} {
		_, err = x.f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_release_proofs(request_id,resolution_id,actor,attempt_id) VALUES($1,$2,'operator',$3)`, x.r.ID, resolution, attempt)
		require.Error(t, err)
	}
	// The valid neighboring payload must be accepted; a duplicate PK cannot mask
	// the invalid JSON checks above. Only its exact actor/timestamp can end intent.
	var recorded time.Time
	require.NoError(t, x.f.db.QueryRowContext(t.Context(), `INSERT INTO uem_netbird_installation_release_proofs(request_id,resolution_id,actor,attempt_id) VALUES($1,$2,'operator',$3) RETURNING recorded_at`, x.r.ID, v.ResolutionID, attempt).Scan(&recorded))
	_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_netbird_installations SET released_at=$2,released_by='viewer',resolution_id=$3 WHERE id=$1`, x.r.ID, recorded, v.ResolutionID)
	require.Error(t, err)
	_, err = x.f.db.ExecContext(t.Context(), `UPDATE uem_netbird_installations SET released_at=$2,released_by='operator',resolution_id=$3 WHERE id=$1`, x.r.ID, recorded, v.ResolutionID)
	require.NoError(t, err)
	for _, pair := range [][2]string{{"reviews", "review"}, {"resolutions", "resolution"}, {"controls", "control"}, {"control_results", "control_result"}, {"release_proofs", "release_proof"}} {
		table := "uem_netbird_installation_" + pair[0]
		_, err = x.f.db.ExecContext(t.Context(), `DELETE FROM `+table)
		require.Error(t, err)
		_, err = x.f.db.ExecContext(t.Context(), `UPDATE `+table+` SET `+map[string]string{"reviews": "actor=actor", "resolutions": "actor=actor", "controls": "actor=actor", "control_results": "response=response", "release_proofs": "actor=actor"}[pair[0]])
		require.Error(t, err)
		for _, suffix := range []string{"immutable", "valid"} {
			guard := "uem_netbird_installation_" + pair[1] + "_" + suffix
			_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` DISABLE TRIGGER `+guard)
			require.NoError(t, err)
			require.Error(t, inventory.Migrate(t.Context(), x.f.db))
			_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` ENABLE TRIGGER `+guard)
			require.NoError(t, err)
		}
	}
	for _, q := range []string{`UPDATE uem_netbird_installations SET released_at=NULL,released_by=NULL,resolution_id=NULL`, `UPDATE uem_netbird_installations SET completed_at=clock_timestamp()`} {
		_, err = x.f.db.ExecContext(t.Context(), q)
		require.Error(t, err)
	}
	_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_installations DISABLE TRIGGER uem_netbird_installation_release_required`)
	require.NoError(t, err)
	require.Error(t, inventory.Migrate(t.Context(), x.f.db))
	_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_installations ENABLE TRIGGER uem_netbird_installation_release_required`)
	require.NoError(t, err)
	require.NoError(t, inventory.Migrate(t.Context(), x.f.db))
}

func TestNetbirdInstallationResolutionIndependentSQLControlAdmission(t *testing.T) {
	x := newInstallationResolutionFixture(t, "missing")
	v := x.review(t)
	var reviewID string
	require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT id::text FROM uem_netbird_installation_reviews WHERE revision=$1`, v.Revision).Scan(&reviewID))
	_, err := x.f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_resolutions(request_id,id,actor,review_id) VALUES($1,$2,'operator',$3)`, x.r.ID, v.ResolutionID, reviewID)
	require.NoError(t, err)
	var issued time.Time
	require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT clock_timestamp()`).Scan(&issued))
	hash, err := x.command.Digest()
	require.NoError(t, err)
	c := netbirdcommand.ControlRequest{Version: 2, Identity: x.command.Identity, RequestID: v.ResolutionID, Kind: "withdraw", ReferenceID: x.r.ID, CommandHash: hash, Revision: x.r.Revision, Operation: "install", IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Second)}
	wire, err := netbirdcommand.EncodeControl(c)
	require.NoError(t, err)
	digest, err := c.Digest()
	require.NoError(t, err)
	// Evidence observed before an owned control cannot retroactively prove it.
	query := c
	query.Kind, query.RequestID = "receipt", uuid.NewString()
	qwire, e := netbirdcommand.EncodeControl(query)
	require.NoError(t, e)
	qhash, e := query.Digest()
	require.NoError(t, e)
	response, e := netbirdcommand.ControlResponseFor(query, "ok")
	require.NoError(t, e)
	response.Receipt = netbirdcommand.Receipt{Version: 1, RequestID: x.r.ID, DeviceID: x.f.id, Revision: x.r.Revision, CommandHash: hash, Operation: "install", Status: "withdrawn"}
	response.ReleaseID = v.ResolutionID
	proof, e := netbirdcommand.EncodeControlResponse(query, response)
	require.NoError(t, e)
	_, err = x.f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_observations(id,request_id,actor,control_hash,control,response) VALUES($1,$2,'operator',$3,$4::jsonb,$5::jsonb)`, query.RequestID, x.r.ID, qhash, string(qwire), string(proof))
	require.NoError(t, err)
	insert := `INSERT INTO uem_netbird_installation_controls(id,request_id,resolution_id,review_id,actor,sequence,kind,control_hash,control) VALUES($1,$2,$3,$4,'operator',1,'withdraw',$5,$6::jsonb)`
	for _, change := range []string{"version", "kind", "reference", "operation", "revision", "certificate", "expiry", "extra", "missing-time", "release-id"} {
		var raw map[string]any
		require.NoError(t, json.Unmarshal(wire, &raw))
		switch change {
		case "version":
			raw["version"] = 1
		case "kind":
			raw["kind"] = "release"
		case "reference":
			raw["reference_id"] = uuid.NewString()
		case "operation":
			raw["operation"] = "register"
		case "revision":
			raw["revision"] = strings.Repeat("f", 64)
		case "certificate":
			raw["certificate_hash"] = strings.Repeat("f", 64)
		case "expiry":
			raw["expires_at"] = issued.Add(11 * time.Second)
		case "extra":
			raw["source"] = "owned private data"
		case "missing-time":
			delete(raw, "issued_at")
		case "release-id":
			raw["request_id"] = uuid.NewString()
		}
		altered, e := json.Marshal(raw)
		require.NoError(t, e)
		_, err = x.f.db.ExecContext(t.Context(), insert, uuid.NewString(), x.r.ID, v.ResolutionID, reviewID, digest, string(altered))
		require.Error(t, err, change)
	}
	var n int
	require.NoError(t, x.f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_controls`).Scan(&n))
	require.Zero(t, n)
	_, err = x.f.db.ExecContext(t.Context(), insert, uuid.NewString(), x.r.ID, v.ResolutionID, reviewID, digest, string(wire))
	require.NoError(t, err)
	_, err = x.f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_release_proofs(request_id,resolution_id,actor,observation_id) VALUES($1,$2,'operator',$3)`, x.r.ID, v.ResolutionID, query.RequestID)
	require.Error(t, err)
	require.Zero(t, x.mutations)
}
