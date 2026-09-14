package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

type ownedRegistrationProvider struct {
	mu                                                    sync.Mutex
	server                                                *httptest.Server
	creates, deletes, reads                               int
	key                                                   map[string]any
	absent                                                bool
	failCreate, failDelete, retainDelete, failRead, drift bool
	tokens                                                []string
	onDelete                                              func()
	events                                                []map[string]any
	peer                                                  map[string]any
	eventReads, peerReads, eventsStatus, peerStatus       int
}

func newRegistrationProvider(t *testing.T, f *refreshFixture, providerID int) *ownedRegistrationProvider {
	t.Helper()
	p := &ownedRegistrationProvider{}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.tokens = append(p.tokens, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/events/audit":
			p.eventReads++
			if p.eventsStatus != 0 {
				w.WriteHeader(p.eventsStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(p.events)
		case r.Method == "GET" && r.URL.Path == "/api/peers/owned-peer":
			p.peerReads++
			if p.peerStatus != 0 {
				w.WriteHeader(p.peerStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(p.peer)
		case r.Method == "GET" && r.URL.Path == "/api/groups":
			_, _ = w.Write([]byte(`[{"id":"owned-group","name":"Owned group","peers_count":0}]`))
		case r.Method == "POST" && r.URL.Path == "/api/setup-keys":
			p.creates++
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			p.key = map[string]any{"id": "12345", "key": "owned-private-setup-key", "name": body["name"], "type": body["type"], "expires": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano), "auto_groups": body["auto_groups"], "usage_limit": body["usage_limit"], "used_times": 0, "allow_extra_dns_labels": body["allow_extra_dns_labels"], "ephemeral": body["ephemeral"], "valid": true, "revoked": false}
			if p.failCreate {
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(p.key)
		case r.Method == "GET" && r.URL.Path == "/api/setup-keys/12345":
			p.reads++
			if p.failRead {
				w.WriteHeader(500)
				return
			}
			if p.absent {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			key := map[string]any{}
			for field, value := range p.key {
				key[field] = value
			}
			key["key"] = "masked-*****"
			key["used_times"] = 1
			if p.drift {
				key["name"] = "another registration"
			}
			_ = json.NewEncoder(w).Encode(key)
		case r.Method == "DELETE" && r.URL.Path == "/api/setup-keys/12345":
			p.deletes++
			if p.onDelete != nil {
				p.onDelete()
			}
			if !p.retainDelete {
				p.absent = true
			}
			if p.failDelete {
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(p.server.Close)
	require.NoError(t, f.client.NetbirdSettings.UpdateOneID(providerID).SetManagementURL(p.server.URL).Exec(t.Context()))
	return p
}
func registrationControl(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
	if c.Kind != "registration-state" {
		return nil, errors.New("registration capability was not requested")
	}
	hash, err := c.Digest()
	if err != nil {
		return nil, err
	}
	return &netbirdcommand.ControlResponse{Version: netbirdcommand.Version, Identity: c.Identity, RequestID: c.RequestID, RequestHash: hash, Kind: c.Kind, Outcome: "ok", State: netbirdcommand.State{Status: "ready", Revision: strings.Repeat("d", 64), Remaining: netbirdcommand.MaxJournalAttempts}}, nil
}
func registrationStore(t *testing.T, f *refreshFixture, p *ownedRegistrationProvider, control inventory.NetbirdOperationControl, execute inventory.NetbirdOperationExecutor) *inventory.NetbirdRegistrationStore {
	t.Helper()
	if control == nil {
		control = registrationControl
	}
	if execute == nil {
		execute = netbirdSuccess
	}
	s, err := inventory.NewNetbirdRegistrationStore(f.db, f.permissions, false, strings.Repeat("k", 32), p.server.Client().Transport, control, execute)
	require.NoError(t, err)
	return s
}
func registrationRequest(t *testing.T, f *refreshFixture, s *inventory.NetbirdRegistrationStore) *inventory.NetbirdRegistration {
	t.Helper()
	review, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, []string{"owned-group"}, true)
	require.NoError(t, err)
	r, err := s.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), review.Revision, review.Groups, review.ExtraDNS)
	require.NoError(t, err)
	return r
}
func registrationRead(t *testing.T, f *refreshFixture, s *inventory.NetbirdRegistrationStore, id string) *inventory.NetbirdRegistration {
	t.Helper()
	r, err := s.Read(t.Context(), "viewer", f.scope, f.id, id)
	require.NoError(t, err)
	return r
}
func TestNetbirdRegistrationStagedDeliveryCleanupScopeAndSecrets(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	sent := 0
	s := registrationStore(t, f, p, nil, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		sent++
		require.Equal(t, netbirdcommand.RegistrationVersion, c.Version)
		require.Equal(t, "register", c.Operation)
		require.Equal(t, "owned-private-setup-key", c.SetupKey)
		var stages, keys int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM uem_netbird_registration_attempts WHERE request_id=$1),(SELECT count(*) FROM uem_netbird_registration_evidence WHERE request_id=$1 AND kind='key')`, c.RequestID).Scan(&stages, &keys))
		require.Equal(t, 2, stages)
		require.Equal(t, 1, keys)
		return netbirdSuccess(ctx, c)
	})
	for _, actor := range []string{"viewer", "operator", "missing"} {
		_, err := s.Review(t.Context(), actor, f.scope, f.id, nil, false)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	_, err := s.Review(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, nil, false)
	require.Error(t, err)
	_, err = s.Review(t.Context(), "tag-admin", f.scope, f.id, []string{"unknown-group"}, false)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationChanged)
	r := registrationRequest(t, f, s)
	ops := netbirdStore(t, f, nil)
	review, err := ops.Review(t.Context(), "tag-admin", f.scope, f.id, "up", "")
	require.NoError(t, err)
	_, err = ops.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", review.Revision)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	worked, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.True(t, worked)
	receipt := registrationRead(t, f, s, r.ID)
	require.Equal(t, "completed", receipt.Status)
	require.True(t, receipt.KeyAbsent)
	require.NotNil(t, receipt.Delivered)
	require.NotNil(t, receipt.Key)
	require.Equal(t, []string{"create", "deliver", "delete"}, receipt.Attempts)
	require.Equal(t, 1, sent)
	again, err := s.Request(t.Context(), r.Actor, r.Scope, r.DeviceID, r.ID, r.Revision, r.Groups, r.ExtraDNS)
	require.NoError(t, err)
	require.Equal(t, "completed", again.Status)
	_, err = s.Request(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, r.Revision, r.Groups, r.ExtraDNS)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.ErrorIs(t, s.Cancel(t.Context(), r.Actor, r.Scope, r.DeviceID, r.ID), inventory.ErrNetbirdOperationConflict)
	var retained string
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT row_to_json(r)::text || coalesce((SELECT jsonb_agg(e)::text FROM uem_netbird_registration_evidence e WHERE request_id=r.id),'') FROM uem_netbird_registrations r WHERE id=$1`, r.ID).Scan(&retained))
	a, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	exported, err := a.ExportJSON(t.Context(), "tag-admin", audit.Filter{Scope: f.scope, Source: "netbird-operations", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	public, _ := json.Marshal(receipt)
	for _, secret := range []string{"private-provider-token", "owned-private-setup-key"} {
		require.NotContains(t, retained, secret)
		require.NotContains(t, string(public), secret)
		require.NotContains(t, string(exported), secret)
		require.NotContains(t, fmt.Sprintf("%+v %#v", receipt, receipt), secret)
	}
	p.mu.Lock()
	require.Equal(t, 1, p.creates)
	require.Equal(t, 1, p.deletes)
	p.mu.Unlock()
	require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(t.Context()))
	require.Equal(t, "completed", registrationRead(t, f, s, r.ID).Status)
}

func TestNetbirdRegistrationUncertaintyNeverRepeatsExternalSteps(t *testing.T) {
	for _, mode := range []string{"lost-create", "lost-delivery", "lost-delete", "delete-retained", "observe-error", "ownership-drift"} {
		t.Run(mode, func(t *testing.T) {
			f, id := netbirdFixture(t)
			p := newRegistrationProvider(t, f, id)
			p.failCreate = mode == "lost-create"
			p.failDelete = mode == "lost-delete"
			p.retainDelete = mode == "delete-retained"
			p.failRead = mode == "observe-error"
			p.drift = mode == "ownership-drift"
			sent := 0
			s := registrationStore(t, f, p, nil, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				sent++
				if mode == "lost-delivery" {
					return nil, errors.New("owned lost reply")
				}
				return netbirdSuccess(ctx, c)
			})
			r := registrationRequest(t, f, s)
			_, err := s.DispatchOne(t.Context())
			require.NoError(t, err)
			receipt := registrationRead(t, f, s, r.ID)
			if mode == "lost-delete" {
				require.Equal(t, "completed", receipt.Status)
			} else {
				require.Equal(t, "unconfirmed", receipt.Status)
			}
			restarted := registrationStore(t, f, p, nil, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				t.Error("registration repeated")
				return nil, errors.New("unexpected")
			})
			worked, err := restarted.DispatchOne(t.Context())
			require.NoError(t, err)
			require.False(t, worked)
			p.mu.Lock()
			require.Equal(t, 1, p.creates)
			require.LessOrEqual(t, p.deletes, 1)
			p.mu.Unlock()
			if mode == "lost-create" {
				require.Zero(t, sent)
				require.Nil(t, receipt.Key)
			} else {
				require.Equal(t, 1, sent)
			}
			if mode != "lost-delete" {
				_, err = s.Request(t.Context(), r.Actor, r.Scope, r.DeviceID, uuid.NewString(), r.Revision, r.Groups, r.ExtraDNS)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			}
		})
	}
}

func TestNetbirdRegistrationRecoveryAfterEvidenceOrFinalAuditFailure(t *testing.T) {
	for _, failure := range []string{"create", "evidence-key", "deliver", "evidence-delivered", "delete", "evidence-absent", "completed"} {
		t.Run(failure, func(t *testing.T) {
			f, id := netbirdFixture(t)
			p := newRegistrationProvider(t, f, id)
			sent := 0
			s := registrationStore(t, f, p, nil, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				sent++
				return netbirdSuccess(ctx, c)
			})
			r := registrationRequest(t, f, s)
			condition := `resource_id NOT LIKE '%/register/` + failure + `'`
			if failure == "completed" {
				condition = `action<>'inventory.netbird.completed'`
			}
			_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_registration_failure CHECK(`+condition+`) NOT VALID`)
			require.NoError(t, err)
			_, err = s.DispatchOne(t.Context())
			// A failed cleanup is itself uncertain; earlier immutable evidence stays.
			if failure == "delete" || failure == "evidence-absent" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			before := registrationRead(t, f, s, r.ID)
			_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_registration_failure`)
			require.NoError(t, err)
			restarted := registrationStore(t, f, p, nil, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
				sent++
				return netbirdSuccess(ctx, c)
			})
			_, err = restarted.DispatchOne(t.Context())
			require.NoError(t, err)
			after := registrationRead(t, f, restarted, r.ID)
			if failure == "create" {
				require.Equal(t, "completed", after.Status)
			} else if failure == "completed" {
				require.Equal(t, "completed", after.Status)
				require.NotNil(t, before.Delivered)
			} else if failure == "deliver" {
				require.Equal(t, "stopped", after.Status)
				require.True(t, after.KeyAbsent)
			} else {
				require.Equal(t, "unconfirmed", after.Status)
			}
			p.mu.Lock()
			require.Equal(t, 1, p.creates)
			require.LessOrEqual(t, p.deletes, 1)
			p.mu.Unlock()
			require.LessOrEqual(t, sent, 1)
		})
	}
}

func TestNetbirdRegistrationCapabilityAndSourceChangesPrecedeCreation(t *testing.T) {
	for _, mode := range []string{"legacy", "denied", "provider-rotation", "scope-change", "mode-change"} {
		t.Run(mode, func(t *testing.T) {
			f, id := netbirdFixture(t)
			p := newRegistrationProvider(t, f, id)
			control := registrationControl
			if mode == "legacy" {
				control = func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
					return nil, errors.New("old agent")
				}
			}
			s := registrationStore(t, f, p, control, nil)
			if mode == "legacy" {
				_, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, nil, false)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationNotReady)
				p.mu.Lock()
				require.Empty(t, p.tokens)
				p.mu.Unlock()
				return
			}
			r := registrationRequest(t, f, s)
			switch mode {
			case "denied":
				require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", "tag-admin", 1, nil))
			case "provider-rotation":
				require.NoError(t, f.client.NetbirdSettings.UpdateOneID(id).SetAccessToken("new-owned-provider-token").Exec(t.Context()))
			case "scope-change":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(t.Context()))
			case "mode-change":
				var err error
				s, err = inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), p.server.Client().Transport, registrationControl, netbirdSuccess)
				require.NoError(t, err)
			}
			_, err := s.DispatchOne(t.Context())
			require.NoError(t, err)
			require.Equal(t, "stopped", registrationRead(t, f, s, r.ID).Status)
			p.mu.Lock()
			require.Zero(t, p.creates)
			p.mu.Unlock()
		})
	}
}

func TestNetbirdRegistrationReadOnlyCleanupUsesOriginalProviderAndKeepsBarrier(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	p.retainDelete = true
	s := registrationStore(t, f, p, nil, nil)
	r := registrationRequest(t, f, s)
	_, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", registrationRead(t, f, s, r.ID).Status)
	require.NoError(t, f.client.NetbirdSettings.UpdateOneID(id).SetAccessToken("replacement-owned-provider-token").SetManagementURL("https://other-owned-provider.example.test").Exec(t.Context()))
	_, err = s.ReconcileCleanup(t.Context(), "viewer", f.scope, f.id, r.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	receipt, err := s.ReconcileCleanup(t.Context(), "admin", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.False(t, receipt.KeyAbsent)
	p.mu.Lock()
	p.absent = true
	p.mu.Unlock()
	receipt, err = s.ReconcileCleanup(t.Context(), "admin", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.True(t, receipt.KeyAbsent)
	require.Equal(t, "unconfirmed", receipt.Status)
	receipt, err = s.ReconcileCleanup(t.Context(), "admin", f.scope, f.id, r.ID)
	require.NoError(t, err)
	require.True(t, receipt.KeyAbsent)
	p.mu.Lock()
	require.Equal(t, 1, p.creates)
	require.Equal(t, 1, p.deletes)
	for _, token := range p.tokens {
		require.Contains(t, token, "private-provider-token")
		require.NotContains(t, token, "replacement-owned-provider-token")
	}
	p.mu.Unlock()
	_, err = s.Request(t.Context(), r.Actor, r.Scope, r.DeviceID, uuid.NewString(), r.Revision, r.Groups, r.ExtraDNS)
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	var actor string
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT actor FROM uem_netbird_operations_audit WHERE resource_id LIKE '%/register/cleanup-evidence' ORDER BY id DESC LIMIT 1`).Scan(&actor))
	require.Equal(t, "admin", actor)
}

func TestNetbirdRegistrationPermanentEvidenceAndMigrationGuards(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	s := registrationStore(t, f, p, nil, nil)
	r := registrationRequest(t, f, s)
	_, err := f.db.ExecContext(t.Context(), `UPDATE uem_netbird_registrations SET status='completed',finished_at=clock_timestamp() WHERE id=$1`, r.ID)
	require.Error(t, err)
	_, err = s.DispatchOne(t.Context())
	require.NoError(t, err)
	for _, query := range []string{
		`DELETE FROM uem_netbird_registrations`,
		`DELETE FROM uem_netbird_registration_attempts`,
		`DELETE FROM uem_netbird_registration_evidence`,
		`UPDATE uem_netbird_registration_attempts SET digest=repeat('f',64)`,
		`UPDATE uem_netbird_registration_evidence SET data='{}'`,
		`UPDATE uem_netbird_registrations SET snapshot='openuem:netbird-registration:v1:substitute'`,
		`UPDATE uem_netbird_registrations SET status='queued',finished_at=NULL`,
	} {
		_, err = f.db.ExecContext(t.Context(), query)
		require.Error(t, err, query)
	}
	for _, guard := range [][2]string{
		{"uem_netbird_registrations", "uem_netbird_registration_immutable"},
		{"uem_netbird_registration_attempts", "uem_netbird_registration_attempt_immutable"},
		{"uem_netbird_registration_attempts", "uem_netbird_registration_attempt_valid"},
		{"uem_netbird_registration_evidence", "uem_netbird_registration_evidence_immutable"},
		{"uem_netbird_registration_evidence", "uem_netbird_registration_evidence_valid"},
		{"uem_netbird_registrations", "uem_netbird_registration_admission"},
		{"uem_netbird_operations", "uem_netbird_registration_admission"},
	} {
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` DISABLE TRIGGER `+guard[1])
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+guard[0]+` ENABLE TRIGGER `+guard[1])
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}

func TestNetbirdRegistrationConcurrentAdmissionAcrossRequestFamilies(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	s := registrationStore(t, f, p, nil, nil)
	ops := netbirdStore(t, f, nil)
	reg, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, []string{"owned-group"}, true)
	require.NoError(t, err)
	op, err := ops.Review(t.Context(), "tag-admin", f.scope, f.id, "up", "")
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, e := s.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), reg.Revision, reg.Groups, reg.ExtraDNS)
		results <- e
	}()
	go func() {
		<-start
		_, e := ops.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), "up", "", op.Revision)
		results <- e
	}()
	close(start)
	first, second := <-results, <-results
	if first == nil {
		require.ErrorIs(t, second, inventory.ErrNetbirdOperationConflict)
	} else {
		require.ErrorIs(t, first, inventory.ErrNetbirdOperationConflict)
		require.NoError(t, second)
	}
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM uem_netbird_registrations)+(SELECT count(*) FROM uem_netbird_operations)`).Scan(&count))
	require.Equal(t, 1, count)
	p.mu.Lock()
	require.Zero(t, p.creates)
	p.mu.Unlock()
}

func TestNetbirdRegistrationRecoveryCleanupDoesNotAdoptRotatedCredentials(t *testing.T) {
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	s := registrationStore(t, f, p, nil, nil)
	r := registrationRequest(t, f, s)
	_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_delivery_failure CHECK(resource_id NOT LIKE '%/register/deliver') NOT VALID`)
	require.NoError(t, err)
	_, err = s.DispatchOne(t.Context())
	require.Error(t, err)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_delivery_failure`)
	require.NoError(t, err)
	require.NoError(t, f.client.NetbirdSettings.UpdateOneID(id).SetAccessToken("new-owned-provider-token").SetManagementURL("https://other-owned-provider.example.test").Exec(t.Context()))
	restarted := registrationStore(t, f, p, nil, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		t.Error("recovery delivered registration")
		return nil, errors.New("unexpected")
	})
	_, err = restarted.DispatchOne(t.Context())
	require.NoError(t, err)
	receipt := registrationRead(t, f, restarted, r.ID)
	require.Equal(t, "stopped", receipt.Status)
	require.True(t, receipt.KeyAbsent)
	require.Nil(t, receipt.Delivered)
	p.mu.Lock()
	require.Equal(t, 1, p.creates)
	require.Equal(t, 1, p.deletes)
	for _, token := range p.tokens {
		require.NotContains(t, token, "new-owned-provider-token")
	}
	p.mu.Unlock()
}

func TestNetbirdRegistrationIDsCannotBeReusedAcrossOperationFamilies(t *testing.T) {
	for _, first := range []string{"registration", "connection"} {
		t.Run(first, func(t *testing.T) {
			f, id := netbirdFixture(t)
			p := newRegistrationProvider(t, f, id)
			s := registrationStore(t, f, p, nil, nil)
			ops := netbirdStore(t, f, nil)
			if first == "registration" {
				r := registrationRequest(t, f, s)
				_, err := s.DispatchOne(t.Context())
				require.NoError(t, err)
				review, err := ops.Review(t.Context(), "tag-admin", f.scope, f.id, "up", "")
				require.NoError(t, err)
				_, err = ops.Request(t.Context(), "tag-admin", f.scope, f.id, r.ID, "up", "", review.Revision)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
				_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,revision) VALUES($1,'other-device',$2,$3,'admin',false,'up',$4)`, r.ID, f.scope.TenantID, f.scope.SiteID, review.Revision)
				require.Error(t, err)
			} else {
				r := netbirdRequest(t, f, ops, "up", "")
				_, err := ops.DispatchOne(t.Context())
				require.NoError(t, err)
				review, err := s.Review(t.Context(), "tag-admin", f.scope, f.id, []string{"owned-group"}, true)
				require.NoError(t, err)
				_, err = s.Request(t.Context(), "tag-admin", f.scope, f.id, r.ID, review.Revision, review.Groups, review.ExtraDNS)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			}
		})
	}
}
