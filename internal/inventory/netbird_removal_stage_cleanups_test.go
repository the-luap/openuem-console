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
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func stageCleanupControl(t *testing.T, x *removalResolutionFixture) inventory.NetbirdOperationControl {
	t.Helper()
	return func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if ctx.Err() != nil || c.Version != netbirdcommand.RemovalStageCleanupInspectionVersion || c.Kind != "removal-stage-cleanup-state" || !c.Executable(c.Identity, time.Now()) {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
		hash, err := x.command.Digest()
		require.NoError(t, err)
		require.Equal(t, netbirdcommand.RemovalStageCleanupReference{RequestID: x.r.ID, CommandHash: hash, Revision: x.r.Revision, ReleaseID: x.releaseID}, c.RemovalStageCleanupOriginal)
		p, err := netbirdcommand.ControlResponseFor(c, "ok")
		p.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("c", 64), Remaining: 100}
		p.RemovalStageCleanup = netbirdcommand.RemovalStageCleanup{Original: c.RemovalStageCleanupOriginal, Profile: netbirdcommand.RemovalStageCleanupProfile, DirectoryCount: 7, ManifestPresent: true, ManifestBytes: 128, JournalRevision: p.State.Revision, StateDigest: strings.Repeat("d", 64)}
		return &p, err
	}
}

func stageCleanupStore(t *testing.T, x *removalResolutionFixture, control inventory.NetbirdOperationControl) *inventory.NetbirdRemovalStageCleanupStore {
	t.Helper()
	if control == nil {
		control = stageCleanupControl(t, x)
	}
	s, err := inventory.NewNetbirdRemovalStageCleanupStore(x.f.db, x.f.permissions, true, control)
	require.NoError(t, err)
	return s
}
func stageCleanupFixture(t *testing.T) *removalResolutionFixture {
	t.Helper()
	x := newRemovalResolutionFixture(t, "unconfirmed")
	d := x.resolve(t, x.review(t))
	require.NotNil(t, d.ConfirmedAt)
	return x
}
func stageCleanupReview(t *testing.T, x *removalResolutionFixture, s *inventory.NetbirdRemovalStageCleanupStore) *inventory.NetbirdRemovalStageCleanupReview {
	t.Helper()
	v, err := s.Review(t.Context(), "tag-admin", x.f.scope, x.f.id, x.r.ID)
	require.NoError(t, err)
	return v
}
func stageCleanupRequest(t *testing.T, x *removalResolutionFixture, s *inventory.NetbirdRemovalStageCleanupStore, v *inventory.NetbirdRemovalStageCleanupReview) *inventory.NetbirdRemovalStageCleanup {
	t.Helper()
	r, err := s.Request(t.Context(), "tag-admin", x.f.scope, x.f.id, x.r.ID, uuid.NewString(), v.StageCleanupDigest, v.Revision)
	require.NoError(t, err)
	return r
}

func TestNetbirdStageCleanupRequestsRetainExactOriginalAndCurrentReview(t *testing.T) {
	x := stageCleanupFixture(t)
	f := x.f
	var calls atomic.Int32
	control := stageCleanupControl(t, x)
	s := stageCleanupStore(t, x, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		calls.Add(1)
		return control(ctx, c)
	})
	for _, actor := range []string{"viewer", "tag-viewer", "missing"} {
		_, err := s.Review(t.Context(), actor, f.scope, f.id, x.r.ID)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	require.Zero(t, calls.Load())
	_, err := s.Review(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID}, f.id, x.r.ID)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationInvalid)
	_, err = s.Review(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, x.r.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	v := stageCleanupReview(t, x, s)
	require.NotEqual(t, v.Revision, v.Journal.Revision)
	require.Equal(t, v.Journal.Revision, v.StageCleanup.JournalRevision)
	r := stageCleanupRequest(t, x, s, v)
	require.Equal(t, x.r.ID, r.OriginalID)
	require.Equal(t, v.StageCleanup, r.StageCleanup)
	require.Equal(t, 2*time.Minute, r.ExpiresAt.Sub(r.RequestedAt))
	before := calls.Load()
	again, err := s.Request(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, r.ID, v.StageCleanupDigest, v.Revision)
	require.NoError(t, err)
	require.Equal(t, r, again)
	require.Equal(t, before, calls.Load())
	read, err := s.Read(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.Equal(t, r, read)
	for _, value := range []any{v, r} {
		data, err := json.Marshal(value)
		require.NoError(t, err)
		for _, private := range []string{"certificate_hash", "broker_key", "https://", "ManagementURL", "AccessToken", "SetupKey"} {
			require.NotContains(t, string(data), private)
		}
		require.Contains(t, string(data), x.r.ID)
		require.Contains(t, string(data), x.releaseID)
	}
	for _, change := range []string{"actor", "original", "review", "digest"} {
		actor, original, revision, digest := "tag-admin", x.r.ID, v.Revision, v.StageCleanupDigest
		switch change {
		case "actor":
			actor = "admin"
		case "original":
			original = uuid.NewString()
		case "review":
			revision = strings.Repeat("e", 64)
		case "digest":
			digest = strings.Repeat("e", 64)
		}
		_, err := s.Request(t.Context(), actor, f.scope, f.id, original, r.ID, digest, revision)
		require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	}
	_, err = s.Cancel(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, access.ErrDenied)
	cancellation := uuid.NewString()
	cancelled, err := s.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, cancellation)
	require.NoError(t, err)
	require.NotNil(t, cancelled.CancelledAt)
	again, err = s.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, cancellation)
	require.NoError(t, err)
	require.Equal(t, cancelled, again)
	_, err = s.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.Equal(t, before, calls.Load(), "history and cancellation must not inspect or mutate the agent")
	old, err := x.requests.Read(t.Context(), "viewer", f.scope, f.id, x.r.ID)
	require.NoError(t, err)
	require.NotNil(t, old.ReleasedAt)
	require.Nil(t, old.CompletedAt)
	require.Equal(t, x.releaseID, old.ResolutionID)
	require.Equal(t, 1, x.native, "request store must never redeliver the original native command")
}

func TestNetbirdStageCleanupRequiresOwnedUnconfirmedReleaseIncludingReconciliation(t *testing.T) {
	for _, kind := range []string{"unreleased", "withdrawn", "completed", "missing", "lost-release", "renewed"} {
		t.Run(kind, func(t *testing.T) {
			status := "unconfirmed"
			if kind == "withdrawn" {
				status = "missing"
			}
			if kind == "completed" {
				status = "completed"
			}
			x := newRemovalResolutionFixture(t, status)
			if kind == "lost-release" {
				x.loseAfter = true
			}
			if kind != "unreleased" && kind != "completed" && kind != "missing" {
				d := x.resolve(t, x.review(t))
				if kind == "lost-release" {
					require.Nil(t, d.ConfirmedAt)
					d = x.reconcile(t, d.ID)
				}
				require.NotNil(t, d.ConfirmedAt)
			}
			if kind == "completed" {
				_ = x.review(t)
			}
			if kind == "renewed" {
				_, err := x.f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, x.f.id)
				require.NoError(t, err)
			}
			var calls atomic.Int32
			control := stageCleanupControl(t, x)
			s := stageCleanupStore(t, x, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				calls.Add(1)
				if kind == "renewed" {
					require.Equal(t, strings.Repeat("e", 64), c.CertificateHash)
				}
				return control(ctx, c)
			})
			id := x.r.ID
			if kind == "missing" {
				id = uuid.NewString()
			}
			v, err := s.Review(t.Context(), "tag-admin", x.f.scope, x.f.id, id)
			if kind == "lost-release" || kind == "renewed" {
				require.NoError(t, err)
				require.Equal(t, x.releaseID, v.StageCleanup.Original.ReleaseID)
				require.EqualValues(t, 1, calls.Load())
			} else {
				require.Error(t, err)
				require.Nil(t, v)
				require.Zero(t, calls.Load())
			}
		})
	}
}

func TestNetbirdStageCleanupRequestRechecksCurrentAuthorityAndNativeEvidence(t *testing.T) {
	for _, kind := range []string{"native", "directory-count", "manifest-bytes", "manifest-presence", "journal", "reference", "release", "certificate", "binding", "consumer", "architecture", "revoked", "expired", "scope", "permission", "legacy", "cancelled", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			x := stageCleanupFixture(t)
			f := x.f
			var changed atomic.Bool
			control := stageCleanupControl(t, x)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			probe := func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				p, err := control(ctx, c)
				if err != nil {
					return nil, err
				}
				if changed.Load() {
					switch kind {
					case "native":
						p.RemovalStageCleanup.StateDigest = strings.Repeat("e", 64)
					case "directory-count":
						p.RemovalStageCleanup.DirectoryCount--
					case "manifest-bytes":
						p.RemovalStageCleanup.ManifestBytes++
					case "manifest-presence":
						p.RemovalStageCleanup.ManifestPresent = false
						p.RemovalStageCleanup.ManifestBytes = 0
					case "journal":
						p.State.Revision = strings.Repeat("e", 64)
						p.RemovalStageCleanup.JournalRevision = p.State.Revision
					case "reference":
						p.RemovalStageCleanup.Original.CommandHash = strings.Repeat("e", 64)
					case "release":
						p.RemovalStageCleanup.Original.ReleaseID = uuid.NewString()
					case "cancelled":
						cancel()
					case "unavailable":
						return nil, errors.New("owned unavailable inspection")
					}
				}
				return p, nil
			}
			s := stageCleanupStore(t, x, probe)
			v := stageCleanupReview(t, x, s)
			changed.Store(true)
			var err error
			switch kind {
			case "certificate":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
			case "binding":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_device_bindings SET revision=$2 WHERE device_id=$1`, f.id, uuid.NewString())
			case "consumer":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET revision=revision+1 WHERE device_id=$1`, f.id)
			case "architecture":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET architecture='amd64' WHERE id=$1`, f.id)
			case "revoked":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "expired":
				_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
			case "scope":
				_, err = f.db.ExecContext(ctx, `UPDATE site_agents SET site_id=$2 WHERE agent_id=$1`, f.id, f.otherSite)
			case "permission":
				p, e := f.permissions.Principal(ctx, "tag-admin")
				require.NoError(t, e)
				err = f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", p.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
			case "legacy":
				s, err = inventory.NewNetbirdRemovalStageCleanupStore(f.db, f.permissions, false, probe)
			}
			require.NoError(t, err)
			_, err = s.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), v.StageCleanupDigest, v.Revision)
			require.Error(t, err)
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_removal_stage_cleanups`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestNetbirdStageCleanupSharesAllRequestBarriersAndPermanentUUIDs(t *testing.T) {
	x := stageCleanupFixture(t)
	f := x.f
	s := stageCleanupStore(t, x, nil)
	v := stageCleanupReview(t, x, s)
	r := stageCleanupRequest(t, x, s, v)
	ctx := t.Context()
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
	_, err = x.requests.Request(ctx, "tag-admin", f.scope, f.id, uuid.NewString(), x.r.DescriptorDigest, x.r.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	manifest := recoveryStore(t, x, nil)
	mv := recoveryReview(t, x, manifest)
	_, err = manifest.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), mv.RecoveryDigest, mv.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	absence := absenceStore(t, x, nil)
	av := absenceReview(t, x, absence)
	_, err = absence.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), av.AbsenceDigest, av.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	insertOperation := `INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,profile,revision,requested_at,expires_at) VALUES($1,$2,$3,$4,'tag-admin',true,'up','',repeat('a',64),clock_timestamp(),clock_timestamp()+interval '1 minute')`
	_, err = f.db.ExecContext(ctx, insertOperation, uuid.NewString(), f.id, f.scope.TenantID, f.scope.SiteID)
	require.Error(t, err)
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, insertOperation, r.ID, f.id, f.scope.TenantID, f.scope.SiteID)
	require.Error(t, err, "cancelled stage_cleanup UUID must remain reserved")
	_, err = f.db.ExecContext(ctx, insertOperation, uuid.NewString(), f.id, f.scope.TenantID, f.scope.SiteID)
	require.NoError(t, err)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), v.StageCleanupDigest, v.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
}

func TestNetbirdStageCleanupSQLRequiresExactOwnedOriginalAndImmutableIntent(t *testing.T) {
	x := stageCleanupFixture(t)
	f := x.f
	s := stageCleanupStore(t, x, nil)
	v := stageCleanupReview(t, x, s)
	for _, kind := range []string{"original", "release", "command", "original-review", "descriptor", "mode", "profile", "count-missing", "count-zero", "count-excess", "count-type", "manifest-missing", "manifest-null", "manifest-type", "bytes-missing", "bytes-null", "bytes-negative", "bytes-excess", "bytes-type", "missing-with-bytes", "journal", "missing", "null", "unknown", "source", "cancelled", "original-id", "release-id", "scope"} {
		t.Run(kind, func(t *testing.T) {
			data, err := netbirdcommand.EncodeRemovalStageCleanup(v.StageCleanup)
			require.NoError(t, err)
			var doc map[string]any
			require.NoError(t, json.Unmarshal(data, &doc))
			original := doc["original"].(map[string]any)
			id := uuid.NewString()
			site := f.scope.SiteID
			var cancelID, actor, at any
			switch kind {
			case "original":
				original["request_id"] = uuid.NewString()
			case "release":
				original["release_id"] = uuid.NewString()
			case "command":
				original["command_hash"] = strings.Repeat("e", 64)
			case "original-review":
				original["revision"] = strings.Repeat("e", 64)
			case "descriptor":
				original["removal"] = map[string]any{"version": "0.78.2"}
			case "mode":
				doc["mode"] = "absent"
			case "profile":
				doc["profile"] = "unreviewed-package"
			case "count-missing":
				delete(doc, "directory_count")
			case "count-zero":
				doc["directory_count"] = 0
			case "count-excess":
				doc["directory_count"] = 8
			case "count-type":
				doc["directory_count"] = "1"
			case "manifest-missing":
				delete(doc, "manifest_present")
			case "manifest-null":
				doc["manifest_present"] = nil
			case "manifest-type":
				doc["manifest_present"] = "true"
			case "bytes-missing":
				delete(doc, "manifest_bytes")
			case "bytes-null":
				doc["manifest_bytes"] = nil
			case "bytes-negative":
				doc["manifest_bytes"] = -1
			case "bytes-excess":
				doc["manifest_bytes"] = (2 << 20) + 1
			case "bytes-type":
				doc["manifest_bytes"] = "0"
			case "missing-with-bytes":
				doc["manifest_present"] = false
			case "journal":
				doc["journal_revision"] = strings.Repeat("e", 64)
			case "missing":
				delete(doc, "state_digest")
			case "null":
				doc["state_digest"] = nil
			case "unknown":
				doc["extra"] = true
			case "source":
				doc["source_url"] = "https://owned.test/private"
			case "cancelled":
				cancelID, actor, at = uuid.NewString(), "tag-admin", time.Now().Add(time.Second)
			case "original-id":
				id = x.r.ID
			case "release-id":
				id = x.releaseID
			case "scope":
				site = f.otherSite
			}
			data, err = json.Marshal(doc)
			require.NoError(t, err)
			_, err = f.db.ExecContext(t.Context(), `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removal_stage_cleanups(id,original_id,device_id,tenant_id,site_id,actor,revision,journal_revision,stage_cleanup_digest,stage_cleanup,requested_at,expires_at,cancellation_id,cancelled_by,cancelled_at) SELECT $1,$2,$3,$4,$5,'tag-admin',$6,$7,$8,$9,at,at+interval '2 minutes',$10,$11,$12 FROM stamp`, id, x.r.ID, f.id, f.scope.TenantID, site, v.Revision, v.Journal.Revision, v.StageCleanupDigest, string(data), cancelID, actor, at)
			require.Error(t, err)
		})
	}
	r := stageCleanupRequest(t, x, s, v)
	for _, query := range []string{`DELETE FROM uem_netbird_removal_stage_cleanups`, `UPDATE uem_netbird_removal_stage_cleanups SET original_id=gen_random_uuid()`, `UPDATE uem_netbird_removal_stage_cleanups SET revision=repeat('e',64)`, `UPDATE uem_netbird_removal_stage_cleanups SET stage_cleanup=stage_cleanup||'{"mode":"absent"}'::jsonb`, `UPDATE uem_netbird_removal_stage_cleanups SET expires_at=expires_at+interval '1 second'`} {
		_, err := f.db.ExecContext(t.Context(), query)
		require.Error(t, err)
	}
	_, err := s.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_removal_stage_cleanups SET cancellation_id=NULL,cancelled_by=NULL,cancelled_at=NULL`)
	require.Error(t, err)
	for _, guard := range []string{"uem_netbird_removal_stage_cleanup_initial", "uem_netbird_removal_stage_cleanup_immutable", "uem_netbird_registration_admission"} {
		_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanups DISABLE TRIGGER `+guard)
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_removal_stage_cleanups ENABLE TRIGGER `+guard)
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}

func TestNetbirdStageCleanupConcurrentRequestsAndAuditRollback(t *testing.T) {
	x := stageCleanupFixture(t)
	f := x.f
	s := stageCleanupStore(t, x, nil)
	v := stageCleanupReview(t, x, s)
	ctx := t.Context()
	id := uuid.NewString()
	_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_stage_cleanup_request_failure CHECK(action<>'inventory.netbird.request') NOT VALID`)
	require.NoError(t, err)
	_, err = s.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, id, v.StageCleanupDigest, v.Revision)
	require.Error(t, err)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_removal_stage_cleanups`).Scan(&count))
	require.Zero(t, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_stage_cleanup_request_failure`)
	require.NoError(t, err)
	results := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := s.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, id, v.StageCleanupDigest, v.Revision)
			results <- err
		}()
	}
	for range 8 {
		require.NoError(t, <-results)
	}
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_operations_audit WHERE request_id=$1 AND action='inventory.netbird.request'`, id).Scan(&count))
	require.Equal(t, 1, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_stage_cleanup_cancel_failure CHECK(action<>'inventory.netbird.stopped') NOT VALID`)
	require.NoError(t, err)
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, v.Revision, uuid.NewString())
	require.Error(t, err)
	r, err := s.Read(ctx, "viewer", f.scope, f.id, id)
	require.NoError(t, err)
	require.Nil(t, r.CancelledAt)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_stage_cleanup_cancel_failure`)
	require.NoError(t, err)
	_, err = s.Cancel(ctx, "tag-admin", f.scope, f.id, id, v.Revision, uuid.NewString())
	require.NoError(t, err)
	var success, conflict atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			_, err := s.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, uuid.NewString(), v.StageCleanupDigest, v.Revision)
			if err == nil {
				success.Add(1)
			} else if errors.Is(err, inventory.ErrNetbirdOperationConflict) {
				conflict.Add(1)
			} else {
				t.Errorf("unexpected admission: %v", err)
			}
		})
	}
	group.Wait()
	require.EqualValues(t, 1, success.Load())
	require.EqualValues(t, 7, conflict.Load())
}

func TestNetbirdStageCleanupRejectsCorruptedRetainedProofBeforeNativeInspection(t *testing.T) {
	for _, kind := range []string{"command-hash", "certificate", "control-hash", "response-hash", "release", "withdrawn"} {
		t.Run(kind, func(t *testing.T) {
			x := stageCleanupFixture(t)
			var table, trigger, query string
			switch kind {
			case "command-hash", "certificate":
				table, trigger = "uem_netbird_removal_attempts", "uem_netbird_removal_attempt_immutable"
				query = `UPDATE uem_netbird_removal_attempts SET command_hash=repeat('e',64)`
				if kind == "certificate" {
					query = `UPDATE uem_netbird_removal_attempts SET certificate_hash=repeat('e',64)`
				}
			case "control-hash":
				table, trigger = "uem_netbird_removal_controls", "uem_netbird_removal_control_immutable"
				query = `UPDATE uem_netbird_removal_controls SET control_hash=repeat('e',64)`
			default:
				table, trigger = "uem_netbird_removal_control_results", "uem_netbird_removal_control_result_immutable"
				query = `UPDATE uem_netbird_removal_control_results SET response=jsonb_set(response,'{request_hash}',to_jsonb(repeat('e',64)))`
				if kind == "release" {
					query = `UPDATE uem_netbird_removal_control_results SET response=jsonb_set(response,'{release_id}',to_jsonb(gen_random_uuid()::text))`
				}
				if kind == "withdrawn" {
					query = `UPDATE uem_netbird_removal_control_results SET response=jsonb_set(response,'{receipt,status}','"withdrawn"'::jsonb)`
				}
			}
			// Simulate corrupted retained data only in this disposable fixture.
			_, err := x.f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` DISABLE TRIGGER `+trigger)
			require.NoError(t, err)
			_, err = x.f.db.ExecContext(t.Context(), query)
			require.NoError(t, err)
			_, err = x.f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` ENABLE TRIGGER `+trigger)
			require.NoError(t, err)
			var calls atomic.Int32
			s := stageCleanupStore(t, x, func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				calls.Add(1)
				return nil, errors.New("unexpected native inspection")
			})
			_, err = s.Review(t.Context(), "tag-admin", x.f.scope, x.f.id, x.r.ID)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			require.Zero(t, calls.Load())
		})
	}
}

func TestNetbirdStageCleanupDirectInsertCannotUseWithdrawnOriginal(t *testing.T) {
	x := newRemovalResolutionFixture(t, "missing")
	d := x.resolve(t, x.review(t))
	require.NotNil(t, d.ConfirmedAt)
	hash, err := x.command.Digest()
	require.NoError(t, err)
	stage_cleanup := netbirdcommand.RemovalStageCleanup{Original: netbirdcommand.RemovalStageCleanupReference{RequestID: x.r.ID, CommandHash: hash, Revision: x.r.Revision, ReleaseID: x.releaseID}, Profile: netbirdcommand.RemovalStageCleanupProfile, DirectoryCount: 7, ManifestPresent: true, ManifestBytes: 128, JournalRevision: strings.Repeat("c", 64), StateDigest: strings.Repeat("d", 64)}
	data, err := netbirdcommand.EncodeRemovalStageCleanup(stage_cleanup)
	require.NoError(t, err)
	_, err = x.f.db.ExecContext(t.Context(), `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_removal_stage_cleanups(id,original_id,device_id,tenant_id,site_id,actor,revision,journal_revision,stage_cleanup_digest,stage_cleanup,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,'tag-admin',repeat('e',64),$6,repeat('f',64),$7,at,at+interval '2 minutes' FROM stamp`, uuid.NewString(), x.r.ID, x.f.id, x.f.scope.TenantID, x.f.scope.SiteID, stage_cleanup.JournalRevision, string(data))
	require.Error(t, err)
}

func TestNetbirdStageCleanupHoldsCurrentIdentityAndPermissionUntilRequestCommit(t *testing.T) {
	x := stageCleanupFixture(t)
	f := x.f
	entered, release := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	control := stageCleanupControl(t, x)
	s := stageCleanupStore(t, x, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if hold.Load() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return control(ctx, c)
	})
	v := stageCleanupReview(t, x, s)
	hold.Store(true)
	principal, err := f.permissions.Principal(t.Context(), "tag-admin")
	require.NoError(t, err)
	done := make(chan error, 1)
	id := uuid.NewString()
	go func() {
		_, err := s.Request(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, id, v.StageCleanupDigest, v.Revision)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("stage_cleanup inspection not reached")
	}
	for _, kind := range []string{"certificate", "permission", "membership"} {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Millisecond)
		switch kind {
		case "certificate":
			_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
		case "membership":
			_, err = f.db.ExecContext(ctx, `UPDATE site_agents SET site_id=$2 WHERE agent_id=$1`, f.id, f.otherSite)
		case "permission":
			err = f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}})
		}
		cancel()
		require.Error(t, err)
	}
	unblock()
	require.NoError(t, <-done)
	hold.Store(false)
	require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	_, err = s.Request(t.Context(), "tag-admin", f.scope, f.id, x.r.ID, id, v.StageCleanupDigest, v.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
}

// Both routes reserve the same endpoint and UUID namespace even though their
// agent inspections and descriptors deliberately have different semantics.
func TestNetbirdStageCleanupAndManifestRecoveryShareSQLAndConcurrentAdmission(t *testing.T) {
	for _, first := range []string{"stage_cleanup", "manifest", "concurrent"} {
		t.Run(first, func(t *testing.T) {
			x := stageCleanupFixture(t)
			f, ctx := x.f, t.Context()
			a, m := stageCleanupStore(t, x, nil), recoveryStore(t, x, nil)
			av, mv := stageCleanupReview(t, x, a), recoveryReview(t, x, m)
			aid, mid := uuid.NewString(), uuid.NewString()
			admitA := func() error {
				_, err := a.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, aid, av.StageCleanupDigest, av.Revision)
				return err
			}
			admitM := func() error {
				_, err := m.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, mid, mv.RecoveryDigest, mv.Revision)
				return err
			}
			if first == "concurrent" {
				start, results := make(chan struct{}), make(chan error, 2)
				go func() { <-start; results <- admitA() }()
				go func() { <-start; results <- admitM() }()
				close(start)
				success, conflicts := 0, 0
				for range 2 {
					err := <-results
					if err == nil {
						success++
					} else {
						require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
						conflicts++
					}
				}
				require.Equal(t, 1, success)
				require.Equal(t, 1, conflicts)
				return
			}
			var table, column, digest, revision, journal, reserved string
			var data []byte
			var err error
			if first == "stage_cleanup" {
				require.NoError(t, admitA())
				require.ErrorIs(t, admitM(), inventory.ErrNetbirdOperationConflict)
				table, column, digest, revision, journal, reserved = "uem_netbird_removal_recoveries", "recovery", mv.RecoveryDigest, mv.Revision, mv.Journal.Revision, aid
				data, err = netbirdcommand.EncodeRemovalRecovery(mv.Recovery)
			} else {
				require.NoError(t, admitM())
				require.ErrorIs(t, admitA(), inventory.ErrNetbirdOperationConflict)
				table, column, digest, revision, journal, reserved = "uem_netbird_removal_stage_cleanups", "stage_cleanup", av.StageCleanupDigest, av.Revision, av.Journal.Revision, mid
				data, err = netbirdcommand.EncodeRemovalStageCleanup(av.StageCleanup)
			}
			require.NoError(t, err)
			// Bypass Go admission to prove the shared SQL guard enforces both directions.
			query := `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO ` + table + `(id,original_id,device_id,tenant_id,site_id,actor,revision,journal_revision,` + column + `_digest,` + column + `,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,'tag-admin',$6,$7,$8,$9,at,at+interval '2 minutes' FROM stamp`
			insert := func(id string) error {
				_, err := f.db.ExecContext(ctx, query, id, x.r.ID, f.id, f.scope.TenantID, f.scope.SiteID, revision, journal, digest, string(data))
				return err
			}
			require.Error(t, insert(uuid.NewString()), "unresolved other family must hold the device")
			if first == "stage_cleanup" {
				_, err = a.Cancel(ctx, "tag-admin", f.scope, f.id, aid, av.Revision, uuid.NewString())
			} else {
				_, err = m.Cancel(ctx, "tag-admin", f.scope, f.id, mid, mv.Revision, uuid.NewString())
			}
			require.NoError(t, err)
			require.Error(t, insert(reserved), "cancelled other family keeps the original UUID")
			require.NoError(t, insert(uuid.NewString()), "cancellation opens the device for a new independent UUID")
		})
	}
}

func TestNetbirdStageCleanupRetainsEmptyAndMaximumReviewedMetadata(t *testing.T) {
	for _, kind := range []string{"no-manifest", "empty-manifest", "maximum-manifest"} {
		t.Run(kind, func(t *testing.T) {
			x := stageCleanupFixture(t)
			control := stageCleanupControl(t, x)
			s := stageCleanupStore(t, x, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				p, err := control(ctx, c)
				if err != nil {
					return nil, err
				}
				p.RemovalStageCleanup.ManifestBytes = 0
				if kind == "no-manifest" {
					p.RemovalStageCleanup.ManifestPresent = false
					p.RemovalStageCleanup.DirectoryCount = 1
				}
				if kind == "maximum-manifest" {
					p.RemovalStageCleanup.ManifestBytes = 2 << 20
				}
				return p, nil
			})
			v := stageCleanupReview(t, x, s)
			r := stageCleanupRequest(t, x, s, v)
			retained, err := s.Read(t.Context(), "viewer", x.f.scope, x.f.id, r.ID)
			require.NoError(t, err)
			require.Equal(t, v.StageCleanup, retained.StageCleanup)
		})
	}
}

func TestNetbirdStageCleanupAndAbsenceShareSQLAndConcurrentAdmission(t *testing.T) {
	for _, first := range []string{"stage_cleanup", "absence", "concurrent"} {
		t.Run(first, func(t *testing.T) {
			x := stageCleanupFixture(t)
			f, ctx := x.f, t.Context()
			a, m := stageCleanupStore(t, x, nil), absenceStore(t, x, nil)
			av, mv := stageCleanupReview(t, x, a), absenceReview(t, x, m)
			aid, mid := uuid.NewString(), uuid.NewString()
			admitA := func() error {
				_, err := a.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, aid, av.StageCleanupDigest, av.Revision)
				return err
			}
			admitM := func() error {
				_, err := m.Request(ctx, "tag-admin", f.scope, f.id, x.r.ID, mid, mv.AbsenceDigest, mv.Revision)
				return err
			}
			if first == "concurrent" {
				start, results := make(chan struct{}), make(chan error, 2)
				go func() { <-start; results <- admitA() }()
				go func() { <-start; results <- admitM() }()
				close(start)
				success, conflicts := 0, 0
				for range 2 {
					err := <-results
					if err == nil {
						success++
					} else {
						require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
						conflicts++
					}
				}
				require.Equal(t, 1, success)
				require.Equal(t, 1, conflicts)
				return
			}
			var table, column, digest, revision, journal, reserved string
			var data []byte
			var err error
			if first == "stage_cleanup" {
				require.NoError(t, admitA())
				require.ErrorIs(t, admitM(), inventory.ErrNetbirdOperationConflict)
				table, column, digest, revision, journal, reserved = "uem_netbird_removal_absences", "absence", mv.AbsenceDigest, mv.Revision, mv.Journal.Revision, aid
				data, err = netbirdcommand.EncodeRemovalAbsence(mv.Absence)
			} else {
				require.NoError(t, admitM())
				require.ErrorIs(t, admitA(), inventory.ErrNetbirdOperationConflict)
				table, column, digest, revision, journal, reserved = "uem_netbird_removal_stage_cleanups", "stage_cleanup", av.StageCleanupDigest, av.Revision, av.Journal.Revision, mid
				data, err = netbirdcommand.EncodeRemovalStageCleanup(av.StageCleanup)
			}
			require.NoError(t, err)
			// Bypass Go admission to prove the shared SQL guard enforces both directions.
			query := `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO ` + table + `(id,original_id,device_id,tenant_id,site_id,actor,revision,journal_revision,` + column + `_digest,` + column + `,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,'tag-admin',$6,$7,$8,$9,at,at+interval '2 minutes' FROM stamp`
			insert := func(id string) error {
				_, err := f.db.ExecContext(ctx, query, id, x.r.ID, f.id, f.scope.TenantID, f.scope.SiteID, revision, journal, digest, string(data))
				return err
			}
			require.Error(t, insert(uuid.NewString()), "unresolved other family must hold the device")
			if first == "stage_cleanup" {
				_, err = a.Cancel(ctx, "tag-admin", f.scope, f.id, aid, av.Revision, uuid.NewString())
			} else {
				_, err = m.Cancel(ctx, "tag-admin", f.scope, f.id, mid, mv.Revision, uuid.NewString())
			}
			require.NoError(t, err)
			require.Error(t, insert(reserved), "cancelled other family keeps the original UUID")
			require.NoError(t, insert(uuid.NewString()), "cancellation opens the device for a new independent UUID")
		})
	}
}
