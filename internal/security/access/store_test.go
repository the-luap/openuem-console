package access

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for permission persistence integration tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "access_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if _, err = db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY);CREATE TABLE tenants(id BIGINT PRIMARY KEY);CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT REFERENCES tenants(id));INSERT INTO users VALUES('admin'),('other'),('viewer'),('operator'),('new_user');INSERT INTO tenants VALUES(1),(2);INSERT INTO sites VALUES(11,1),(12,1),(21,2)`); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal("non-idempotent migration", err)
	}
	if err = s.Bootstrap(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPermissionsPersistAndRevocationsSurviveRestart(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	before, err := s.Principal(ctx, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Grants) != 0 || before.Revision != 0 {
		t.Fatal("new user received implicit access")
	}
	grants := []Grant{{Role: Viewer, Scope: Scope{TenantID: 1, SiteID: 11}}}
	if err = s.ReplaceGrants(ctx, "admin", "viewer", 0, grants); err != nil {
		t.Fatal(err)
	}
	p, err := s.Principal(ctx, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 1 || !p.Can(ReadDevices, Scope{TenantID: 1, SiteID: 11}) || p.Can(ReadDevices, Scope{TenantID: 1, SiteID: 12}) {
		t.Fatal("stored permissions did not retain scope", p)
	}
	if err = s.ReplaceGrants(ctx, "admin", "viewer", p.Revision, nil); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Bootstrap(ctx, "viewer"); err != nil {
		t.Fatal(err)
	}
	p, err = restarted.Principal(ctx, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 2 || len(p.Grants) != 0 {
		t.Fatal("restart re-granted revoked privileges")
	}
	events, err := s.Audit(ctx, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Actor != "admin" || events[0].Subject != "viewer" || string(events[0].After) != "[]" {
		t.Fatalf("missing audit evidence: %+v", events)
	}
	if _, err = s.Audit(ctx, "viewer", 0); !errors.Is(err, ErrDenied) {
		t.Fatal("viewer read permission history", err)
	}
}

func TestPermissionChangesRejectEscalationStaleEditorsAndForeignScopes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	adminGrant := []Grant{{Role: Administrator}}
	if err := s.ReplaceGrants(ctx, "viewer", "viewer", 0, adminGrant); !errors.Is(err, ErrDenied) {
		t.Fatal("user elevated itself", err)
	}
	if err := s.ReplaceGrants(ctx, "admin", "admin", 1, nil); !errors.Is(err, ErrLastAdministrator) {
		t.Fatal("removed last administrator", err)
	}
	for _, g := range []Grant{{Role: Viewer, Scope: Scope{TenantID: 1, SiteID: 21}}, {Role: Operator, Scope: Scope{TenantID: 999}}, {Role: Administrator, Scope: Scope{TenantID: 1}}} {
		if err := s.ReplaceGrants(ctx, "admin", "viewer", 0, []Grant{g}); err == nil {
			t.Fatal("invalid scope accepted", g)
		}
	}
	if err := s.ReplaceGrants(ctx, "admin", "viewer", 0, []Grant{{Role: Viewer, Scope: Scope{TenantID: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceGrants(ctx, "admin", "viewer", 0, adminGrant); !errors.Is(err, ErrConflict) {
		t.Fatal("stale editor replaced permissions", err)
	}
	if _, err := s.db.Exec(`DELETE FROM users WHERE uid='admin'`); err == nil {
		t.Fatal("user deletion bypassed administrator retention")
	}
	if _, err := s.db.Exec(`DELETE FROM tenants WHERE id=1`); err == nil {
		t.Fatal("deleted organization with outstanding permission grants")
	}
	events, err := s.Audit(ctx, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatal("failed changes modified audit/state", len(events))
	}
}

func TestConcurrentAdministratorRemovalLeavesOneAdministrator(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.ReplaceGrants(ctx, "admin", "other", 0, []Grant{{Role: Administrator}}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, user := range []string{"admin", "other"} {
		wg.Add(1)
		go func(user string) { defer wg.Done(); <-start; results <- s.ReplaceGrants(ctx, user, user, 1, nil) }(user)
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded := 0
	rejected := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrLastAdministrator) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("unsafe concurrent removal: %d success, %d rejected", succeeded, rejected)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_access_grants WHERE role='administrator'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("last administrator lost")
	}
}

func TestConcurrentPermissionEditorsDoNotLoseUpdates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, site := range []int{11, 12} {
		go func(site int) {
			<-start
			results <- s.ReplaceGrants(ctx, "admin", "viewer", 0, []Grant{{Role: Viewer, Scope: Scope{TenantID: 1, SiteID: site}}})
		}(site)
	}
	close(start)
	first, second := <-results, <-results
	if !((first == nil && errors.Is(second, ErrConflict)) || (second == nil && errors.Is(first, ErrConflict))) {
		t.Fatal("concurrent editors silently overwrote a grant", first, second)
	}
}
