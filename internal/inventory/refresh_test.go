package inventory_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
)

type refreshFixture struct {
	db          *sql.DB
	client      *ent.Client
	permissions *access.Store
	store       *inventory.RefreshStore
	scope       access.Scope
	otherSite   int
	id          string
}

func newRefreshFixture(t *testing.T, publish inventory.ReportPublisher) *refreshFixture {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for inventory refresh integration")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "inventory_refresh_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("application_name", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(8)
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() {
		client.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	ctx := t.Context()
	if err = client.Schema.Create(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"admin", "operator", "viewer"} {
		if err = client.User.Create().SetID(id).SetName(id).SetEmail(id + "@example.test").SetUse2fa(false).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := client.Tenant.Create().SetDescription("Refresh fixture").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	site, err := client.Site.Create().SetDescription("Visible site").SetTenantID(tenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := client.Site.Create().SetDescription("Hidden site").SetTenantID(tenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	scope := access.Scope{TenantID: tenant.ID, SiteID: site.ID}
	for actor, role := range map[string]access.Role{"operator": access.Operator, "viewer": access.Viewer} {
		if err = permissions.ReplaceGrants(ctx, "admin", actor, 0, []access.Grant{{Role: role, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
	}
	id := uuid.NewString()
	if err = client.Agent.Create().SetID(id).SetHostname("Refresh report").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if publish == nil {
		publish = func(context.Context, string, string) error { return nil }
	}
	store, err := inventory.NewRefreshStore(db, permissions, false, publish)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx); err != nil {
		t.Fatal("non-idempotent migration", err)
	}
	return &refreshFixture{db: db, client: client, permissions: permissions, store: store, scope: scope, otherSite: other.ID, id: id}
}

func (f *refreshFixture) request(t *testing.T) *inventory.RefreshRequest {
	t.Helper()
	r, err := f.store.Request(t.Context(), "operator", f.scope, f.id, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *refreshFixture) latest(t *testing.T) *inventory.RefreshRequest {
	t.Helper()
	r, err := f.store.Latest(t.Context(), "operator", f.scope, f.id)
	if err != nil || r == nil {
		t.Fatal("refresh status unavailable", r, err)
	}
	return r
}

func (f *refreshFixture) due(t *testing.T) {
	t.Helper()
	if _, err := f.db.Exec(`UPDATE uem_inventory_refresh SET next_attempt_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshAdmissionAndCommittedAttemptEvidence(t *testing.T) {
	var f *refreshFixture
	var calls int
	f = newRefreshFixture(t, func(ctx context.Context, device, request string) error {
		calls++
		if device != f.id {
			t.Error("publisher received another device")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Error("unbounded publisher")
		}
		var count int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_refresh_audit WHERE request_id=$1 AND action='inventory.refresh.attempt'`, request).Scan(&count); err != nil || count != 1 {
			t.Error("attempt was not committed before publication", count, err)
		}
		return nil
	})
	r := f.request(t)
	if r.Status != "queued" || r.Attempts != 0 {
		t.Fatal("request claimed delivery before publication", r)
	}
	if again, err := f.store.Request(t.Context(), "operator", f.scope, f.id, r.ID); err != nil || again.ID != r.ID {
		t.Fatal("exact request retry failed", again, err)
	}
	if _, err := f.store.Request(t.Context(), "operator", f.scope, f.id, uuid.NewString()); !errors.Is(err, inventory.ErrRefreshConflict) {
		t.Fatal("duplicate pending request admitted", err)
	}
	if found, err := f.store.DispatchOne(t.Context()); !found || err != nil {
		t.Fatal("dispatch failed", found, err)
	}
	status := f.latest(t)
	if calls != 1 || status.Status != "accepted" || status.Attempts != 1 || status.FinishedAt == nil {
		t.Fatal("broker acceptance evidence missing", calls, status)
	}
	if _, err := f.store.Request(t.Context(), "operator", f.scope, f.id, r.ID); err != nil {
		t.Fatal("accepted request was not idempotent", err)
	}
	if found, err := f.store.DispatchOne(t.Context()); found || err != nil || calls != 1 {
		t.Fatal("accepted command was republished", found, err)
	}
	if _, err := f.store.Request(t.Context(), "operator", f.scope, f.id, uuid.NewString()); !errors.Is(err, inventory.ErrRefreshRecent) {
		t.Fatal("request cooldown bypassed", err)
	}
}

func TestRefreshRejectsInvalidAuthorityAndMembership(t *testing.T) {
	f := newRefreshFixture(t, nil)
	for _, id := range []string{"", "agent.*", "agent.>", "agent.report.other", "agent\nother", strings.Repeat("x", 256)} {
		if _, err := f.store.Request(t.Context(), "operator", f.scope, id, uuid.NewString()); !errors.Is(err, inventory.ErrRefreshInvalid) {
			t.Error("unsafe broker ID accepted", id, err)
		}
	}
	if _, err := f.store.Request(t.Context(), "viewer", f.scope, f.id, uuid.NewString()); !errors.Is(err, access.ErrDenied) {
		t.Fatal("viewer can request inventory", err)
	}
	if _, err := f.store.Request(t.Context(), "operator", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, uuid.NewString()); !errors.Is(err, access.ErrDenied) {
		t.Fatal("foreign site authority accepted", err)
	}
	if _, err := f.store.Request(t.Context(), "operator", f.scope, uuid.NewString(), uuid.NewString()); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("missing device disclosed", err)
	}
	if err := f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Request(t.Context(), "operator", f.scope, f.id, uuid.NewString()); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("ambiguous membership accepted", err)
	}
	if err := f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.otherSite).SetAgentStatus(agent.AgentStatusDisabled).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Request(t.Context(), "operator", f.scope, f.id, uuid.NewString()); !errors.Is(err, inventory.ErrRefreshNotReady) {
		t.Fatal("disabled agent accepted", err)
	}
}

func TestRefreshAuditFailuresDoNotLosePublicationUncertainty(t *testing.T) {
	var calls int
	var ids []string
	f := newRefreshFixture(t, func(_ context.Context, _, id string) error { calls++; ids = append(ids, id); return nil })
	addFailure := func(action string) {
		t.Helper()
		if _, err := f.db.Exec(`ALTER TABLE uem_inventory_refresh_audit ADD CONSTRAINT refresh_test_failure CHECK(action<>'inventory.refresh.` + action + `') NOT VALID`); err != nil {
			t.Fatal(err)
		}
	}
	removeFailure := func() {
		t.Helper()
		if _, err := f.db.Exec(`ALTER TABLE uem_inventory_refresh_audit DROP CONSTRAINT refresh_test_failure`); err != nil {
			t.Fatal(err)
		}
	}
	addFailure("request")
	if _, err := f.store.Request(t.Context(), "operator", f.scope, f.id, uuid.NewString()); err == nil {
		t.Fatal("unaudited request accepted")
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM uem_inventory_refresh`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed admission retained a request", count, err)
	}
	removeFailure()
	r := f.request(t)
	addFailure("attempt")
	if _, err := f.store.DispatchOne(t.Context()); err == nil || calls != 0 {
		t.Fatal("publication preceded durable intent", calls, err)
	}
	removeFailure()
	addFailure("accepted")
	if _, err := f.store.DispatchOne(t.Context()); err == nil || calls != 1 {
		t.Fatal("completion failure was hidden", calls, err)
	}
	status := f.latest(t)
	if status.Status != "queued" || status.Attempts != 1 {
		t.Fatal("rollback lost prior handoff evidence", status)
	}
	removeFailure()
	if _, err := f.store.DispatchOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	status = f.latest(t)
	if status.Status != "accepted" || status.Attempts != 2 || len(ids) != 2 || ids[0] != r.ID || ids[1] != r.ID {
		t.Fatal("retry lost stable broker identity", status, ids)
	}
}

func TestRefreshRechecksQueuedAuthorityAndAssignment(t *testing.T) {
	for _, change := range []string{"permission", "membership", "disabled", "expiry", "mode"} {
		t.Run(change, func(t *testing.T) {
			var calls int
			publish := func(context.Context, string, string) error { calls++; return nil }
			f := newRefreshFixture(t, publish)
			f.request(t)
			var err error
			switch change {
			case "permission":
				err = f.permissions.ReplaceGrants(t.Context(), "admin", "operator", 1, nil)
			case "membership":
				err = f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(t.Context())
			case "disabled":
				err = f.client.Agent.UpdateOneID(f.id).SetAgentStatus(agent.AgentStatusDisabled).Exec(t.Context())
			case "expiry":
				_, err = f.db.Exec(`UPDATE uem_inventory_refresh SET expires_at=clock_timestamp()-interval '1 second'`)
			case "mode":
				f.store, err = inventory.NewRefreshStore(f.db, f.permissions, true, publish)
			}
			if err != nil {
				t.Fatal(err)
			}
			if found, err := f.store.DispatchOne(t.Context()); !found || err != nil || calls != 0 {
				t.Fatal("ineligible queued command published", found, calls, err)
			}
			var state string
			if err = f.db.QueryRow(`SELECT status FROM uem_inventory_refresh`).Scan(&state); err != nil || state != "stopped" {
				t.Fatal("stopped request not recorded", state, err)
			}
		})
	}
}

func TestRefreshRetriesAreBoundedAndCancellationRetainsIntent(t *testing.T) {
	t.Run("bounded retries", func(t *testing.T) {
		var calls int
		f := newRefreshFixture(t, func(context.Context, string, string) error {
			calls++
			return errors.New("synthetic lost acknowledgement")
		})
		f.request(t)
		for i := 0; i < 5; i++ {
			f.due(t)
			if _, err := f.store.DispatchOne(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if r := f.latest(t); calls != 5 || r.Status != "unconfirmed" || r.Attempts != 5 {
			t.Fatal("retry budget or uncertainty lost", calls, r)
		}
		f.due(t)
		if found, err := f.store.DispatchOne(t.Context()); found || err != nil || calls != 5 {
			t.Fatal("exhausted request republished", found, calls, err)
		}
	})
	t.Run("cancel during handoff", func(t *testing.T) {
		started := make(chan struct{})
		f := newRefreshFixture(t, func(ctx context.Context, _, _ string) error { close(started); <-ctx.Done(); return ctx.Err() })
		r := f.request(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := f.store.DispatchOne(ctx); done <- err }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("handoff did not start")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost", err)
		}
		if status := f.latest(t); status.Status != "queued" || status.Attempts != 1 {
			t.Fatal("cancellation erased attempt", status)
		}
		var retried string
		restarted, err := inventory.NewRefreshStore(f.db, f.permissions, false, func(_ context.Context, _, id string) error { retried = id; return nil })
		if err != nil {
			t.Fatal(err)
		}
		if found, err := restarted.DispatchOne(t.Context()); !found || err != nil || retried != r.ID {
			t.Fatal("restart did not reuse retained request", found, retried, err)
		}
	})
}

func TestRefreshDispatchHoldsPermissionsAndMembershipAndSkipsOwnedWork(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := newRefreshFixture(t, func(ctx context.Context, _, _ string) error {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	f.request(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	dispatch := make(chan error, 1)
	go func() { _, err := f.store.DispatchOne(ctx); dispatch <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	type dispatchResult struct {
		found bool
		err   error
	}
	second := make(chan dispatchResult, 1)
	go func() { found, err := f.store.DispatchOne(ctx); second <- dispatchResult{found, err} }()
	revoked, moved := make(chan error, 1), make(chan error, 1)
	go func() { revoked <- f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil) }()
	go func() { moved <- f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx) }()
	// Both writes must wait behind the publication's actual database locks.
	for {
		var pending int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE NOT l.granted AND a.application_name=current_setting('application_name')`).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if pending >= 2 {
			break
		}
		select {
		case err := <-revoked:
			t.Fatal("revocation overtook handoff", err)
		case err := <-moved:
			t.Fatal("membership overtook handoff", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(release)
	if err := <-dispatch; err != nil {
		t.Fatal(err)
	}
	if result := <-second; result.found || result.err != nil {
		t.Fatal("another dispatcher took owned work", result)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if err := <-moved; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent dispatcher published twice")
	}
}

func TestRefreshRequiresCurrentIndividualIdentityAndConsumer(t *testing.T) {
	for _, change := range []string{"ready", "revoked", "expired", "consumer", "scope"} {
		t.Run(change, func(t *testing.T) {
			var calls int
			publish := func(context.Context, string, string) error { calls++; return nil }
			f := newRefreshFixture(t, publish)
			identity, err := registry.NewStore(f.db, "inventory-refresh-fixture-master-key")
			if err != nil {
				t.Fatal(err)
			}
			if err = identity.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err = identity.EnsureAuthority(t.Context(), f.scope.TenantID, "Refresh fixture", "https://uem.example.test", "admin", nil, nil); err != nil {
				t.Fatal(err)
			}
			invitation, err := identity.Invite(t.Context(), registry.InvitationOptions{Scope: registry.Scope{TenantID: f.scope.TenantID, SiteID: f.scope.SiteID}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
			if err != nil {
				t.Fatal(err)
			}
			keys, err := enrollment.GenerateKeys()
			if err != nil {
				t.Fatal(err)
			}
			defer keys.Broker.Wipe()
			claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Refresh agent")
			if err != nil {
				t.Fatal(err)
			}
			response, err := identity.Claim(t.Context(), *claim)
			if err != nil {
				t.Fatal(err)
			}
			f.id = response.DeviceID
			if err = f.client.Agent.Create().SetID(f.id).SetHostname("Individual refresh agent").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			f.store, err = inventory.NewRefreshStore(f.db, f.permissions, true, publish)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.Request(t.Context(), "operator", f.scope, f.id, uuid.NewString()); !errors.Is(err, inventory.ErrRefreshNotReady) {
				t.Fatal("unprovisioned consumer accepted", err)
			}
			if _, err = f.db.Exec(`UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1`, f.id); err != nil {
				t.Fatal(err)
			}
			f.request(t)
			switch change {
			case "revoked":
				_, err = f.db.Exec(`UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
			case "expired":
				_, err = f.db.Exec(`UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
			case "consumer":
				_, err = f.db.Exec(`UPDATE uem_agent_command_consumers SET revision=revision+1 WHERE device_id=$1`, f.id)
			case "scope":
				_, err = f.db.Exec(`UPDATE uem_agent_identities SET site_id=$2 WHERE id=$1`, f.id, f.otherSite)
			}
			if err != nil {
				t.Fatal(err)
			}
			if found, err := f.store.DispatchOne(t.Context()); !found || err != nil {
				t.Fatal("individual request dispatch failed", found, err)
			}
			state := f.latest(t)
			if change == "ready" {
				if calls != 1 || state.Status != "accepted" {
					t.Fatal("ready identity not published", calls, state)
				}
			} else if calls != 0 || state.Status != "stopped" {
				t.Fatal("changed identity received a queued command", calls, state)
			}
		})
	}
}

func TestRefreshRetentionPreservesActiveAttemptEvidence(t *testing.T) {
	f := newRefreshFixture(t, func(context.Context, string, string) error { return errors.New("synthetic lost acknowledgement") })
	f.request(t)
	if _, err := f.store.DispatchOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE uem_inventory_refresh_audit SET created_at=clock_timestamp()-interval '45 days' WHERE action='inventory.refresh.attempt'`); err != nil {
		t.Fatal(err)
	}
	audits, err := audit.NewStore(f.db, f.permissions)
	if err != nil {
		t.Fatal(err)
	}
	if err = audits.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	scope := access.Scope{TenantID: f.scope.TenantID}
	preview, err := audits.PreviewRetention(t.Context(), "admin", scope, 30)
	if err != nil || preview.Counts["inventory-refresh"] != 0 {
		t.Fatal("retention includes active attempt evidence", preview, err)
	}
	if err = audits.ApplyRetention(t.Context(), "admin", scope, preview.ID, preview.Token); err != nil {
		t.Fatal(err)
	}
	if err = audits.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := f.latest(t); r.Attempts != 1 {
		t.Fatal("retention erased active uncertainty", r)
	}
	if _, err = f.db.Exec(`UPDATE uem_inventory_refresh SET expires_at=clock_timestamp()-interval '1 second',next_attempt_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.DispatchOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec(`UPDATE uem_audit_retention SET next_sweep_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if err = audits.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := f.latest(t); r.Attempts != 0 || r.Status != "unconfirmed" {
		t.Fatal("terminal retention changed outcome", r)
	}
}

func TestRefreshWorkerJoinsCancellationAndResumesRetainedWork(t *testing.T) {
	started := make(chan struct{})
	f := newRefreshFixture(t, func(ctx context.Context, _, _ string) error { close(started); <-ctx.Done(); return ctx.Err() })
	f.request(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); f.store.Run(ctx, nil) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not join cancellation")
	}
	if r := f.latest(t); r.Status != "queued" || r.Attempts != 1 {
		t.Fatal("worker shutdown lost retained intent", r)
	}
}
