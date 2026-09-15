package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func installationFixture(t *testing.T, inspect inventory.NetbirdOperationInspector) (*refreshFixture, *inventory.NetbirdInstallationStore, *inventory.NetbirdPackageStore, packageapi.Package) {
	t.Helper()
	f, scope := tagFixture(t)
	ctx := t.Context()
	identities, err := registry.NewStore(f.db, "owned-netbird-identity-master-key")
	require.NoError(t, err)
	require.NoError(t, identities.Migrate(ctx))
	_, err = identities.EnsureAuthority(ctx, scope.TenantID, "Owned installation fixture", "https://uem.example.test", "admin", nil, nil)
	require.NoError(t, err)
	invite, err := identities.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: scope.TenantID, SiteID: f.scope.SiteID}, Platform: "macos", Architecture: "arm64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	require.NoError(t, err)
	keys, err := enrollment.GenerateKeys()
	require.NoError(t, err)
	t.Cleanup(keys.Broker.Wipe)
	claim, err := keys.Request(invite.URL[strings.LastIndex(invite.URL, "/")+1:], "macos", "arm64", "Owned absent NetBird endpoint")
	require.NoError(t, err)
	identity, err := identities.Claim(ctx, *claim)
	require.NoError(t, err)
	f.id = identity.DeviceID
	require.NoError(t, f.client.Agent.Create().SetID(f.id).SetHostname("Owned absent NetBird endpoint").SetOs("macOS").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1`, f.id)
	require.NoError(t, err)
	p := ownedNetbirdPackage(scope)
	p.Platform, p.Architecture, p.Format, p.PackageID, p.URL = "macos", "arm64", "pkg", "io.netbird.client", "https://packages.example.test/netbird.pkg?private=owned-installation-source"
	packages, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	_, err = packages.Approve(ctx, "tag-admin", scope, p, "Owned installation publisher review")
	require.NoError(t, err)
	if inspect == nil {
		inspect = netbirdReady
	}
	store, err := inventory.NewNetbirdInstallationStore(f.db, f.permissions, true, strings.Repeat("k", 32), inspect)
	require.NoError(t, err)
	return f, store, packages, p
}

func installationReview(t *testing.T, f *refreshFixture, s *inventory.NetbirdInstallationStore, p packageapi.Package) *inventory.NetbirdInstallationReview {
	t.Helper()
	digest, err := p.Digest()
	require.NoError(t, err)
	r, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, p.ApprovalID, digest)
	require.NoError(t, err)
	return r
}

func installationRequest(t *testing.T, f *refreshFixture, s *inventory.NetbirdInstallationStore, p packageapi.Package) *inventory.NetbirdInstallation {
	t.Helper()
	review := installationReview(t, f, s, p)
	r, err := s.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), p.ApprovalID, review.Approval.Digest, review.Revision)
	require.NoError(t, err)
	return r
}

func TestNetbirdInstallationAbsentClientScopeReplayPrivacyAndCancellation(t *testing.T) {
	var calls atomic.Int32
	f, s, packages, p := installationFixture(t, func(ctx context.Context, i netbirdcommand.Identity) (netbirdcommand.State, error) {
		calls.Add(1)
		require.True(t, i.Individual)
		return netbirdReady(ctx, i)
	})
	ctx := t.Context()
	digest, _ := p.Digest()
	for _, actor := range []string{"tag-viewer", "viewer", "missing"} {
		_, err := s.Review(ctx, actor, f.scope, f.id, p.ApprovalID, digest)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, actor := range []string{"tag-operator", "operator"} {
		_, err := s.Review(ctx, actor, f.scope, f.id, p.ApprovalID, digest)
		require.NoError(t, err, "software assignment should use the existing scoped operator capability")
	}
	var rows int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM netbirds WHERE agent_netbird=$1`, f.id).Scan(&rows))
	require.Zero(t, rows)
	review := installationReview(t, f, s, p)
	require.Equal(t, "macos", review.Target.Platform)
	data, err := json.Marshal(review)
	require.NoError(t, err)
	require.NotContains(t, string(data), "owned-installation-source")
	require.NotContains(t, string(data), "Owned installation publisher review")
	require.NotContains(t, string(data), "tag-admin")
	id := uuid.NewString()
	r, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, digest, review.Revision)
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, r.ExpiresAt.Sub(r.RequestedAt))
	before := calls.Load()
	got, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, digest, review.Revision)
	require.NoError(t, err)
	require.Equal(t, r, got)
	require.Equal(t, before, calls.Load())
	_, err = s.Request(ctx, "admin", f.scope, f.id, id, p.ApprovalID, digest, review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, digest, strings.Repeat("a", 64))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	got, err = s.Read(ctx, "viewer", f.scope, f.id, id)
	require.NoError(t, err)
	require.Equal(t, r, got)
	data, err = json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(data), "owned-installation-source")
	_, err = s.Read(ctx, "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.Cancel(ctx, "viewer", f.scope, f.id, id, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, access.ErrDenied)
	cancelID := uuid.NewString()
	cancelled, err := s.Cancel(ctx, "tag-admin", f.scope, f.id, id, r.Revision, cancelID)
	require.NoError(t, err)
	require.NotNil(t, cancelled.CancelledAt)
	got, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, r.Revision, cancelID)
	require.NoError(t, err)
	require.Equal(t, cancelled, got)
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	operatorRequest, err := s.Request(ctx, "operator", f.scope, f.id, uuid.NewString(), p.ApprovalID, digest, review.Revision)
	require.NoError(t, err)
	_, err = s.Cancel(ctx, "operator", f.scope, f.id, operatorRequest.ID, operatorRequest.Revision, uuid.NewString())
	require.NoError(t, err)
	_, err = packages.Revoke(ctx, "tag-admin", access.Scope{TenantID: f.scope.TenantID}, p.ApprovalID, digest, uuid.NewString())
	require.NoError(t, err)
	got, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, digest, r.Revision)
	require.NoError(t, err)
	require.Equal(t, cancelled, got)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), p.ApprovalID, digest, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageConflict)
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND action='inventory.netbird.request'`, id).Scan(&rows))
	require.Equal(t, 1, rows)
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND action='inventory.netbird.stopped'`, id).Scan(&rows))
	require.Equal(t, 1, rows)
}

func TestNetbirdInstallationRechecksApprovalRecipientAndJournal(t *testing.T) {
	for _, change := range []string{"mode", "certificate", "expired", "revoked", "consumer", "native-architecture", "reported-platform", "journal", "package-revoked", "key", "ciphertext", "metadata"} {
		t.Run(change, func(t *testing.T) {
			var changed atomic.Bool
			f, s, packages, p := installationFixture(t, func(ctx context.Context, i netbirdcommand.Identity) (netbirdcommand.State, error) {
				r, err := netbirdReady(ctx, i)
				if changed.Load() {
					r.Revision = strings.Repeat("e", 64)
				}
				return r, err
			})
			review := installationReview(t, f, s, p)
			ctx := t.Context()
			var err error
			switch change {
			case "mode":
				s, err = inventory.NewNetbirdInstallationStore(f.db, f.permissions, false, strings.Repeat("k", 32), netbirdReady)
			case "certificate":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
			case "expired":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
			case "revoked":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET revision=revision+1 WHERE device_id=$1`, f.id)
			case "native-architecture":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET architecture='amd64' WHERE id=$1`, f.id)
			case "reported-platform":
				_, err = f.db.ExecContext(ctx, `UPDATE agents SET os='windows' WHERE oid=$1`, f.id)
			case "journal":
				changed.Store(true)
			case "package-revoked":
				_, err = packages.Revoke(ctx, "tag-admin", access.Scope{TenantID: f.scope.TenantID}, p.ApprovalID, review.Approval.Digest, uuid.NewString())
			case "key":
				s, err = inventory.NewNetbirdInstallationStore(f.db, f.permissions, true, strings.Repeat("z", 32), netbirdReady)
			case "ciphertext", "metadata":
				_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_packages DISABLE TRIGGER uem_netbird_package_immutable`)
				require.NoError(t, err)
				query := `UPDATE uem_netbird_packages SET version='0.78.2' WHERE id=$1`
				if change == "ciphertext" {
					query = `UPDATE uem_netbird_packages SET encrypted_descriptor=decode(repeat('61',64),'hex') WHERE id=$1`
				}
				_, err = f.db.ExecContext(ctx, query, p.ApprovalID)
			}
			require.NoError(t, err)
			_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), p.ApprovalID, review.Approval.Digest, review.Revision)
			require.Error(t, err)
			var count int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_installations`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdInstallationCommonBarrierAndPermanentSQLGuards(t *testing.T) {
	f, s, _, p := installationFixture(t, nil)
	ctx := t.Context()
	r := installationRequest(t, f, s, p)
	operations, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, true, netbirdReady, netbirdSuccess)
	require.NoError(t, err)
	registrations, err := inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), nil, func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		return nil, fmt.Errorf("unexpected provider access")
	}, netbirdSuccess)
	require.NoError(t, err)
	_, err = operations.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", strings.Repeat("a", 64))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = registrations.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), strings.Repeat("a", 64), nil, false)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	for _, query := range []string{`DELETE FROM uem_netbird_installations`, `UPDATE uem_netbird_installations SET revision=repeat('f',64)`, `UPDATE uem_netbird_installations SET approval_digest=repeat('f',64)`} {
		_, err = f.db.ExecContext(ctx, query)
		require.Error(t, err)
	}
	insertOperation := `INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,profile,revision,requested_at,expires_at) VALUES($1,$2,$3,$4,'tag-admin',true,'up','',repeat('a',64),clock_timestamp(),clock_timestamp()+interval '1 minute')`
	_, err = f.db.ExecContext(ctx, insertOperation, uuid.NewString(), f.id, f.scope.TenantID, f.scope.SiteID)
	require.Error(t, err, "direct SQL bypassed the shared barrier")
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, insertOperation, r.ID, f.id, f.scope.TenantID, f.scope.SiteID)
	require.Error(t, err, "cancelled installation UUID was reused")
	opID := uuid.NewString()
	_, err = f.db.ExecContext(ctx, insertOperation, opID, f.id, f.scope.TenantID, f.scope.SiteID)
	require.NoError(t, err)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), p.ApprovalID, r.ApprovalDigest, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.NoError(t, operations.Cancel(ctx, "tag-admin", f.scope, f.id, opID))
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, opID, p.ApprovalID, r.ApprovalDigest, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.NoError(t, inventory.Migrate(ctx, f.db))
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_installations DISABLE TRIGGER uem_netbird_installation_approval_valid`)
	require.NoError(t, err)
	require.Error(t, inventory.Migrate(ctx, f.db))
}

func TestNetbirdInstallationConcurrentReplayAndAuditRollback(t *testing.T) {
	f, s, _, p := installationFixture(t, nil)
	ctx := t.Context()
	review := installationReview(t, f, s, p)
	id := uuid.NewString()
	_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_request_failure CHECK(action<>'inventory.netbird.request') NOT VALID`)
	require.NoError(t, err)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, review.Approval.Digest, review.Revision)
	require.Error(t, err)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_installations`).Scan(&count))
	require.Zero(t, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_install_request_failure`)
	require.NoError(t, err)
	errors := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, review.Approval.Digest, review.Revision)
			errors <- err
		}()
	}
	for range 8 {
		require.NoError(t, <-errors)
	}
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE action='inventory.netbird.request' AND request_id=$1`, id).Scan(&count))
	require.Equal(t, 1, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_cancel_failure CHECK(action<>'inventory.netbird.stopped') NOT VALID`)
	require.NoError(t, err)
	cancelID := uuid.NewString()
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, review.Revision, cancelID)
	require.Error(t, err)
	r, err := s.Read(ctx, "viewer", f.scope, f.id, id)
	require.NoError(t, err)
	require.Nil(t, r.CancelledAt)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_install_cancel_failure`)
	require.NoError(t, err)
	for range 8 {
		go func() {
			_, err := s.Cancel(ctx, "tag-admin", f.scope, f.id, id, review.Revision, cancelID)
			errors <- err
		}()
	}
	for range 8 {
		require.NoError(t, <-errors)
	}
	var success, conflict atomic.Int32
	var work sync.WaitGroup
	for range 8 {
		work.Go(func() {
			_, err := s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), p.ApprovalID, review.Approval.Digest, review.Revision)
			if err == nil {
				success.Add(1)
			} else if err == inventory.ErrNetbirdOperationConflict {
				conflict.Add(1)
			} else {
				t.Errorf("unexpected admission failure: %v", err)
			}
		})
	}
	work.Wait()
	require.EqualValues(t, 1, success.Load())
	require.EqualValues(t, 7, conflict.Load())
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_installations WHERE cancelled_at IS NULL`).Scan(&count))
	require.Equal(t, 1, count)
}

func TestNetbirdInstallationHoldsRecipientPermissionAndRevocationThroughCommit(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f, s, packages, p := installationFixture(t, func(ctx context.Context, i netbirdcommand.Identity) (netbirdcommand.State, error) {
		if hold.Load() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return netbirdcommand.State{}, ctx.Err()
			}
		}
		return netbirdReady(ctx, i)
	})
	ctx := t.Context()
	review := installationReview(t, f, s, p)
	hold.Store(true)
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	id := uuid.NewString()
	done := make(chan error, 1)
	go func() {
		_, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, review.Approval.Digest, review.Revision)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not enter live inspection")
	}
	for _, check := range []string{"revoke", "certificate", "permission"} {
		bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		switch check {
		case "revoke":
			_, err = f.db.ExecContext(bounded, `INSERT INTO uem_netbird_package_revocations(approval_id,id,actor,digest) VALUES($1,$2,'tag-admin',$3)`, p.ApprovalID, uuid.NewString(), review.Approval.Digest)
		case "certificate":
			_, err = f.db.ExecContext(bounded, `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
		case "permission":
			err = f.permissions.ReplaceGrants(bounded, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
		}
		require.Error(t, err, "%s changed while admission held its current authority", check)
		cancel()
	}
	unblock()
	require.NoError(t, <-done)
	hold.Store(false)
	_, err = packages.Revoke(ctx, "tag-admin", access.Scope{TenantID: f.scope.TenantID}, p.ApprovalID, review.Approval.Digest, uuid.NewString())
	require.NoError(t, err)
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, review.Revision, uuid.NewString())
	require.NoError(t, err)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), p.ApprovalID, review.Approval.Digest, review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageConflict)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, p.ApprovalID, review.Approval.Digest, review.Revision)
	require.ErrorIs(t, err, access.ErrDenied, "replay bypassed current permission")
}

func TestNetbirdInstallationSeesRevocationAfterWaitingForApprovalLock(t *testing.T) {
	f, s, packages, p := installationFixture(t, nil)
	ctx := t.Context()
	review := installationReview(t, f, s, p)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_package_revocations(approval_id,id,actor,digest) VALUES($1,$2,'tag-admin',$3)`, p.ApprovalID, uuid.NewString(), review.Approval.Digest)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), p.ApprovalID, review.Approval.Digest, review.Revision)
		done <- err
	}()
	replayed := make(chan *inventory.NetbirdPackageApproval, 1)
	go func() {
		result, err := packages.Approve(ctx, "tag-admin", access.Scope{TenantID: f.scope.TenantID}, p, "Owned installation publisher review")
		if err != nil {
			t.Errorf("exact approval replay failed: %v", err)
		}
		replayed <- result
	}()
	netbirdWaitForLocks(t, ctx, f, 2)
	require.NoError(t, tx.Commit())
	require.ErrorIs(t, <-done, inventory.ErrNetbirdPackageConflict)
	result := <-replayed
	require.NotNil(t, result)
	require.NotNil(t, result.RevokedAt, "approval replay retained a stale join snapshot")
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_installations`).Scan(&count))
	require.Zero(t, count)
}

func TestNetbirdInstallationBoundsRecipientLifetimeAndRetainsHistory(t *testing.T) {
	f, s, _, p := installationFixture(t, nil)
	ctx := t.Context()
	_, err := f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '45 seconds' WHERE id=$1`, f.id)
	require.NoError(t, err)
	r := installationRequest(t, f, s, p)
	require.Less(t, time.Until(r.ExpiresAt), time.Minute)
	s, err = inventory.NewNetbirdInstallationStore(f.db, f.permissions, false, strings.Repeat("k", 32), netbirdReady)
	require.NoError(t, err)
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.NoError(t, err)
	require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(ctx))
	retained, err := s.Read(ctx, "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, r.ApprovalDigest, retained.ApprovalDigest)
	require.NotNil(t, retained.CancelledAt)
}
