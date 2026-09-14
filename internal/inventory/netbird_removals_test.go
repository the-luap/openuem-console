package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedRemovalDescriptor() packageapi.Removal {
	return packageapi.Removal{Schema: 1, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("f", 64)}
}

func removalControl(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
	if ctx.Err() != nil || c.Version != netbirdcommand.RemovalInspectionVersion || c.Kind != "removal-state" || !c.Individual || !c.Executable(c.Identity, time.Now()) {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	r, err := netbirdcommand.ControlResponseFor(c, "ok")
	if err != nil {
		return nil, err
	}
	r.State, _ = netbirdReady(ctx, c.Identity)
	r.Removal = ownedRemovalDescriptor()
	return &r, nil
}

func removalFixture(t *testing.T, control inventory.NetbirdOperationControl) (*refreshFixture, *inventory.NetbirdRemovalStore) {
	t.Helper()
	f, _, _, _ := installationFixture(t, nil)
	if control == nil {
		control = removalControl
	}
	s, err := inventory.NewNetbirdRemovalStore(f.db, f.permissions, true, control)
	require.NoError(t, err)
	return f, s
}

func removalReview(t *testing.T, f *refreshFixture, s *inventory.NetbirdRemovalStore) *inventory.NetbirdRemovalReview {
	t.Helper()
	r, err := s.Review(t.Context(), "tag-admin", f.scope, f.id)
	require.NoError(t, err)
	return r
}

func TestNetbirdRemovalReviewRequestReplayScopeAndCancellation(t *testing.T) {
	var calls atomic.Int32
	f, s := removalFixture(t, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		calls.Add(1)
		return removalControl(ctx, c)
	})
	ctx := t.Context()
	for _, actor := range []string{"viewer", "tag-viewer", "missing"} {
		_, err := s.Review(ctx, actor, f.scope, f.id)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, actor := range []string{"operator", "tag-operator"} {
		_, err := s.Review(ctx, actor, f.scope, f.id)
		require.NoError(t, err)
	}
	_, err := s.Review(ctx, "admin", access.Scope{TenantID: f.scope.TenantID}, f.id)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	_, err = s.Review(ctx, "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	review := removalReview(t, f, s)
	require.Equal(t, ownedRemovalDescriptor(), review.Descriptor)
	require.False(t, review.Absent)
	id := uuid.NewString()
	r, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, r.ExpiresAt.Sub(r.RequestedAt))
	require.Equal(t, review.Descriptor, r.Descriptor)
	before := calls.Load()
	again, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
	require.NoError(t, err)
	require.Equal(t, r, again)
	require.Equal(t, before, calls.Load())
	_, err = s.Request(ctx, "admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, strings.Repeat("a", 64), review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, strings.Repeat("a", 64))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	read, err := s.Read(ctx, "viewer", f.scope, f.id, id)
	require.NoError(t, err)
	require.Equal(t, r, read)
	require.Equal(t, before, calls.Load())
	data, err := json.Marshal(read)
	require.NoError(t, err)
	for _, private := range []string{"certificate_hash", "broker_key", "https://", "owned-installation-source", "encrypted", "ManagementURL", "AccessToken"} {
		require.NotContains(t, string(data), private)
	}
	_, err = s.Read(ctx, "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.Cancel(ctx, "viewer", f.scope, f.id, id, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, access.ErrDenied)
	cancelID := uuid.NewString()
	cancelled, err := s.Cancel(ctx, "tag-admin", f.scope, f.id, id, r.Revision, cancelID)
	require.NoError(t, err)
	require.NotNil(t, cancelled.CancelledAt)
	again, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, r.Revision, cancelID)
	require.NoError(t, err)
	require.Equal(t, cancelled, again)
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
	require.NoError(t, err)
	again, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
	require.NoError(t, err)
	require.Equal(t, cancelled, again)
	require.Equal(t, before, calls.Load())
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND action='inventory.netbird.request'`, id).Scan(&count))
	require.Equal(t, 1, count)
}

func TestNetbirdRemovalRequiresCompleteMatchingNativeInspection(t *testing.T) {
	for _, kind := range []string{"absent", "unavailable", "wrong-certificate", "wrong-hash", "wrong-architecture", "wrong-platform", "invalid-descriptor", "busy", "cancelled", "error"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f, s := removalFixture(t, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				r, err := removalControl(ctx, c)
				if err != nil {
					return nil, err
				}
				switch kind {
				case "absent":
					r.Outcome = "absent"
					r.Removal = packageapi.Removal{}
				case "unavailable":
					r.Outcome = "unavailable"
					r.State = netbirdcommand.State{}
					r.Removal = packageapi.Removal{}
				case "wrong-certificate":
					r.CertificateHash = strings.Repeat("a", 64)
				case "wrong-hash":
					r.RequestHash = strings.Repeat("a", 64)
				case "wrong-architecture":
					r.Removal.Architecture = "amd64"
				case "wrong-platform":
					r.Removal.Platform, r.Removal.Format, r.Removal.PackageID = "linux", "deb", "netbird"
				case "invalid-descriptor":
					r.Removal.StateDigest = ""
				case "busy":
					r.State = netbirdcommand.State{Status: "busy", Revision: strings.Repeat("d", 64), PendingID: uuid.NewString(), PendingHash: strings.Repeat("e", 64), Remaining: 100}
				case "cancelled":
					cancel()
				case "error":
					return nil, errors.New("owned unavailable evidence")
				}
				return r, nil
			})
			r, err := s.Review(ctx, "tag-admin", f.scope, f.id)
			if kind == "absent" {
				require.NoError(t, err)
				require.True(t, r.Absent)
				require.Empty(t, r.DescriptorDigest)
				require.Equal(t, packageapi.Removal{}, r.Descriptor)
				_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), strings.Repeat("f", 64), r.Revision)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationChanged)
			} else {
				require.Error(t, err)
				require.Nil(t, r)
			}
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_removals`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdRemovalRechecksNativeStateIdentityAndAuthority(t *testing.T) {
	for _, kind := range []string{"state", "version", "journal", "certificate", "expired", "revoked", "consumer", "architecture", "reported-platform", "binding", "scope", "permission", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			var changed atomic.Bool
			control := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				r, err := removalControl(ctx, c)
				if err != nil {
					return nil, err
				}
				if changed.Load() {
					switch kind {
					case "state":
						r.Removal.StateDigest = strings.Repeat("e", 64)
					case "version":
						r.Removal.Version = "0.78.2"
					case "journal":
						r.State.Revision = strings.Repeat("a", 64)
					}
				}
				return r, nil
			}
			f, s := removalFixture(t, control)
			review := removalReview(t, f, s)
			ctx := t.Context()
			var err error
			switch kind {
			case "state", "version", "journal":
				changed.Store(true)
			case "certificate":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
			case "expired":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
			case "revoked":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET revision=revision+1 WHERE device_id=$1`, f.id)
			case "architecture":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET architecture='amd64' WHERE id=$1`, f.id)
			case "reported-platform":
				_, err = f.db.ExecContext(ctx, `UPDATE agents SET os='windows' WHERE oid=$1`, f.id)
			case "binding":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_device_bindings SET revision=$2 WHERE device_id=$1`, f.id, uuid.NewString())
			case "scope":
				_, err = f.db.ExecContext(ctx, `UPDATE site_agents SET site_id=$2 WHERE agent_id=$1`, f.id, f.otherSite)
			case "permission":
				p, e := f.permissions.Principal(ctx, "tag-admin")
				require.NoError(t, e)
				err = f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", p.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
			case "legacy":
				s, err = inventory.NewNetbirdRemovalStore(f.db, f.permissions, false, control)
			}
			require.NoError(t, err)
			_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), review.DescriptorDigest, review.Revision)
			require.Error(t, err)
			var count int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_removals`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdRemovalCommonBarrierAndPermanentSQLGuards(t *testing.T) {
	f, s := removalFixture(t, nil)
	review := removalReview(t, f, s)
	ctx := t.Context()
	r, err := s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), review.DescriptorDigest, review.Revision)
	require.NoError(t, err)
	operations, err := inventory.NewNetbirdOperationStore(f.db, f.permissions, true, netbirdReady, netbirdSuccess)
	require.NoError(t, err)
	registrations, err := inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), nil, removalControl, netbirdSuccess)
	require.NoError(t, err)
	installations, err := inventory.NewNetbirdInstallationStore(f.db, f.permissions, true, strings.Repeat("k", 32), netbirdReady)
	require.NoError(t, err)
	_, err = operations.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", strings.Repeat("a", 64))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = registrations.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), strings.Repeat("a", 64), nil, false)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	_, err = installations.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), uuid.NewString(), strings.Repeat("a", 64), strings.Repeat("a", 64))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	for _, query := range []string{`DELETE FROM uem_netbird_removals`, `UPDATE uem_netbird_removals SET revision=repeat('a',64)`, `UPDATE uem_netbird_removals SET descriptor=descriptor||'{"version":"0.78.2"}'::jsonb`, `UPDATE uem_netbird_removals SET expires_at=expires_at+interval '1 second'`} {
		_, err = f.db.ExecContext(ctx, query)
		require.Error(t, err)
	}
	insertOperation := `INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,profile,revision,requested_at,expires_at) VALUES($1,$2,$3,$4,'tag-admin',true,'up','',repeat('a',64),clock_timestamp(),clock_timestamp()+interval '1 minute')`
	_, err = f.db.ExecContext(ctx, insertOperation, uuid.NewString(), f.id, f.scope.TenantID, f.scope.SiteID)
	require.Error(t, err, "direct connection bypassed removal exclusion")
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, insertOperation, r.ID, f.id, f.scope.TenantID, f.scope.SiteID)
	require.Error(t, err, "cancelled removal UUID was reused")
	opID := uuid.NewString()
	_, err = f.db.ExecContext(ctx, insertOperation, opID, f.id, f.scope.TenantID, f.scope.SiteID)
	require.NoError(t, err)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), review.DescriptorDigest, review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
}

func TestNetbirdRemovalConcurrentRequestsAndAuditRollback(t *testing.T) {
	f, s := removalFixture(t, nil)
	review := removalReview(t, f, s)
	ctx := t.Context()
	id := uuid.NewString()
	_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_request_failure CHECK(action<>'inventory.netbird.request') NOT VALID`)
	require.NoError(t, err)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
	require.Error(t, err)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_removals`).Scan(&count))
	require.Zero(t, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_removal_request_failure`)
	require.NoError(t, err)
	results := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
			results <- err
		}()
	}
	for range 8 {
		require.NoError(t, <-results)
	}
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND action='inventory.netbird.request'`, id).Scan(&count))
	require.Equal(t, 1, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_removal_cancel_failure CHECK(action<>'inventory.netbird.stopped') NOT VALID`)
	require.NoError(t, err)
	cancelID := uuid.NewString()
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, review.Revision, cancelID)
	require.Error(t, err)
	r, err := s.Read(ctx, "viewer", f.scope, f.id, id)
	require.NoError(t, err)
	require.Nil(t, r.CancelledAt)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_removal_cancel_failure`)
	require.NoError(t, err)
	for range 8 {
		go func() {
			_, err := s.Cancel(ctx, "tag-admin", f.scope, f.id, id, review.Revision, cancelID)
			results <- err
		}()
	}
	for range 8 {
		require.NoError(t, <-results)
	}
	var success, conflict atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			_, err := s.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), review.DescriptorDigest, review.Revision)
			if err == nil {
				success.Add(1)
			} else if errors.Is(err, inventory.ErrNetbirdOperationConflict) {
				conflict.Add(1)
			} else {
				t.Errorf("unexpected admission result: %v", err)
			}
		})
	}
	group.Wait()
	require.EqualValues(t, 1, success.Load())
	require.EqualValues(t, 7, conflict.Load())
}

func TestNetbirdRemovalSQLRejectsMalformedOrSourceBearingDescriptors(t *testing.T) {
	f, s := removalFixture(t, nil)
	review := removalReview(t, f, s)
	ctx := t.Context()
	base := map[string]any{}
	encoded, _ := packageapi.EncodeRemoval(review.Descriptor)
	require.NoError(t, json.Unmarshal(encoded, &base))
	for _, kind := range []string{"null-platform", "missing-state", "numeric-architecture", "url", "wrong-package", "duplicate-shape", "fractional-schema", "empty-version", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			copy := map[string]any{}
			for key, value := range base {
				copy[key] = value
			}
			switch kind {
			case "null-platform":
				copy["platform"] = nil
			case "missing-state":
				delete(copy, "state_digest")
			case "numeric-architecture":
				copy["platform"], copy["format"], copy["package_id"], copy["architecture"] = "linux", "deb", "netbird", 386
			case "url":
				copy["url"] = "https://owned.example.test/private"
			case "wrong-package":
				copy["package_id"] = "other"
			case "duplicate-shape":
				copy["schema"] = 2
			case "fractional-schema":
				copy["schema"] = json.Number("1.0")
			case "empty-version":
				copy["version"] = ""
			}
			data, err := json.Marshal(copy)
			require.NoError(t, err)
			var cancelID, actor, at any
			if kind == "cancelled" {
				cancelID, actor, at = uuid.NewString(), "tag-admin", time.Now().Add(time.Second)
			}
			_, err = f.db.ExecContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removals(id,device_id,tenant_id,site_id,actor,revision,journal_revision,descriptor_digest,descriptor,requested_at,expires_at,cancellation_id,cancelled_by,cancelled_at) SELECT $1,$2,$3,$4,'tag-admin',$5,$6,$7,$8,at,at+interval '10 minutes',$9,$10,$11 FROM stamp`, uuid.NewString(), f.id, f.scope.TenantID, f.scope.SiteID, review.Revision, review.Journal.Revision, review.DescriptorDigest, string(data), cancelID, actor, at)
			require.Error(t, err)
		})
	}
}

func TestNetbirdRemovalHoldsCurrentIdentityAndPermissionUntilCommit(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f, s := removalFixture(t, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if hold.Load() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return removalControl(ctx, c)
	})
	review := removalReview(t, f, s)
	hold.Store(true)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	done := make(chan error, 1)
	id := uuid.NewString()
	go func() {
		_, err := s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native inspection not reached")
	}
	for _, kind := range []string{"certificate", "permission"} {
		bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		if kind == "certificate" {
			_, err = f.db.ExecContext(bounded, `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
		} else {
			err = f.permissions.ReplaceGrants(bounded, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
		}
		cancel()
		require.Error(t, err)
	}
	unblock()
	require.NoError(t, <-done)
	hold.Store(false)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, id, review.DescriptorDigest, review.Revision)
	require.ErrorIs(t, err, access.ErrDenied, "replay bypassed revoked permission")
}
