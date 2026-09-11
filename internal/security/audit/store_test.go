package audit

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/openuem-console/internal/desktop"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func testStore(t *testing.T, allSources bool) *Store {
	t.Helper()
	return testStoreWithAuditMigration(t, allSources, true)
}

func testStoreWithAuditMigration(t *testing.T, allSources, migrateAudit bool) *Store {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for audit integration tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "audit_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	if _, err = db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY); CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT NOT NULL REFERENCES tenants(id)); INSERT INTO users VALUES('admin'),('organization-admin'),('viewer'),('operator'); INSERT INTO tenants VALUES(1),(2); INSERT INTO sites VALUES(11,1),(12,1),(21,2)`); err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	for user, role := range map[string]access.Role{"organization-admin": access.TenantAdmin, "viewer": access.Viewer, "operator": access.Operator} {
		if err = permissions.ReplaceGrants(t.Context(), "admin", user, 0, []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1}}}); err != nil {
			t.Fatal(err)
		}
	}
	if allSources {
		appleStore, err := apple.NewStore(db, strings.Repeat("a", 32))
		if err != nil {
			t.Fatal(err)
		}
		if err = appleStore.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		desktopStore, err := desktop.NewStore(db, strings.Repeat("a", 32))
		if err != nil {
			t.Fatal(err)
		}
		if err = desktopStore.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewStore(db, permissions)
	if err != nil {
		t.Fatal(err)
	}
	if !migrateAudit {
		return s
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal("migration is not idempotent", err)
	}
	return s
}

func TestAuditExportByteLimitRejectsBothFormatsWithoutPartialData(t *testing.T) {
	s := testStore(t, true)
	if _, err := s.db.Exec(`INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,created_at) SELECT 1,'fixture','large',repeat('x',2048),clock_timestamp()-interval '1 hour' FROM generate_series(1,8000)`); err != nil {
		t.Fatal(err)
	}
	f := Filter{Scope: access.Scope{TenantID: 1}, Action: "large", From: time.Now().Add(-2 * time.Hour), Until: time.Now()}
	for _, export := range []func(context.Context, string, Filter) ([]byte, error){s.ExportCSV, s.ExportJSON} {
		data, err := export(t.Context(), "organization-admin", f)
		if !errors.Is(err, ErrTooLarge) || len(data) != 0 {
			t.Fatal("byte-limited export returned partial data", len(data), err)
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_audit_activity WHERE action='audit.export' AND result='failure'`).Scan(&count); err != nil || count != 2 {
		t.Fatal("byte-limited export failure was not audited", count, err)
	}
}

func testFilter() Filter {
	return Filter{Scope: access.Scope{TenantID: 1}, From: time.Now().Add(-24 * time.Hour).UTC(), Until: time.Now().Add(time.Minute).UTC()}
}

func TestAuditScopesOutcomesAndStableCrossSourcePagination(t *testing.T) {
	s := testStore(t, true)
	at := time.Now().Add(-time.Hour).UTC()
	for tenant := 1; tenant <= 2; tenant++ {
		if _, err := s.db.Exec(`INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details,created_at) SELECT $1,'audit-fixture','apple.command.acknowledged',n::text,jsonb_build_object('site_id',$2::integer,'result','success','secret','DO-NOT-EXPORT'),$3 FROM generate_series(1,150)n`, tenant, tenant*10+1, at); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO uem_agent_audit(tenant_id,site_id,actor,action,resource_id,created_at) SELECT $1,$2,'audit-fixture','agent.identity.issue',('10000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,$3 FROM generate_series(1,150)n`, tenant, tenant*10+1, at); err != nil {
			t.Fatal(err)
		}
	}
	f := testFilter()
	f.Actor = "audit-fixture"
	seen := map[string]bool{}
	next := ""
	var firstCursor string
	for i := 0; i < 4; i++ {
		page, err := s.List(t.Context(), "organization-admin", f, next)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			key := event.Source + ":" + strconv.FormatInt(event.ID, 10)
			if seen[key] || event.TenantID != 1 || event.SiteID != 11 {
				t.Fatal("duplicate or out-of-scope event", event)
			}
			seen[key] = true
			if (event.Source == "apple" && event.Result != "success") || (event.Source == "agent" && event.Result != "recorded") {
				t.Fatal("invented audit outcome", event)
			}
		}
		if i == 0 {
			firstCursor = page.Next
		}
		if page.Next == "" {
			break
		}
		next = page.Next
	}
	if len(seen) != 300 || firstCursor == "" {
		t.Fatal("pagination lost tied timestamps", len(seen))
	}
	for _, actor := range []string{"viewer", "operator", "absent"} {
		if _, err := s.List(t.Context(), actor, f, ""); !errors.Is(err, access.ErrDenied) {
			t.Fatal("unauthorized audit read", actor, err)
		}
		if _, err := s.ExportCSV(t.Context(), actor, f); !errors.Is(err, access.ErrDenied) {
			t.Fatal("unauthorized audit export", actor, err)
		}
	}
	for _, scope := range []access.Scope{{TenantID: 2}, {}, {TenantID: 1, SiteID: 21}} {
		other := f
		other.Scope = scope
		if _, err := s.List(t.Context(), "organization-admin", other, ""); !errors.Is(err, access.ErrDenied) {
			t.Fatal("cross-scope audit read", scope, err)
		}
	}
	other := f
	other.Scope = access.Scope{TenantID: 2}
	if _, err := s.List(t.Context(), "admin", other, firstCursor); !errors.Is(err, ErrInvalid) {
		t.Fatal("cursor crossed filters", err)
	}
	f.Scope.SiteID = 12
	page, err := s.List(t.Context(), "organization-admin", f, "")
	if err != nil || len(page.Events) != 0 {
		t.Fatal("site filter included other sites", err)
	}
	f.Scope.SiteID = 0
	exported, err := s.ExportJSON(t.Context(), "organization-admin", f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), "DO-NOT-EXPORT") {
		t.Fatal("arbitrary audit details exported")
	}
	var events []Event
	if err = json.Unmarshal(exported, &events); err != nil || len(events) != 300 {
		t.Fatal("JSON export incomplete", len(events), err)
	}
	if err = s.permissions.ReplaceGrants(t.Context(), "admin", "organization-admin", 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ExportJSON(t.Context(), "organization-admin", f); !errors.Is(err, access.ErrDenied) {
		t.Fatal("stale service instance retained revoked export access", err)
	}
}

func TestAuditOptionalSourcesAndExportLimits(t *testing.T) {
	s := testStore(t, false)
	f := testFilter()
	f.Scope = access.Scope{}
	page, err := s.List(t.Context(), "admin", f, "")
	if err != nil || len(page.Sources) != 4 {
		t.Fatal("unconfigured platforms broke audit", page, err)
	}
	f.Scope.TenantID = 1
	page, err = s.List(t.Context(), "organization-admin", f, "")
	if err != nil || len(page.Events) != 0 || strings.Join(page.Sources, ",") != "inventory,activity,retention" {
		t.Fatal("global access events leaked into organization", page, err)
	}
	if _, err = s.db.Exec(`INSERT INTO uem_audit_activity(tenant_id,actor,action,resource_id,result,event_count,created_at) SELECT 1,'limit-fixture','audit.view',repeat('a',64),'success',0,clock_timestamp()-interval '1 hour' FROM generate_series(1,10001)`); err != nil {
		t.Fatal(err)
	}
	f.Actor = "limit-fixture"
	if data, err := s.ExportCSV(t.Context(), "organization-admin", f); !errors.Is(err, ErrTooLarge) || len(data) != 0 {
		t.Fatal("oversized export was silently truncated", err)
	}
	var failed int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_audit_activity WHERE actor='organization-admin' AND action='audit.export' AND result='failure'`).Scan(&failed); err != nil || failed != 1 {
		t.Fatal("export failure was not audited", failed, err)
	}
}

func TestAuditCSVUsesTextForFormulaLikeFields(t *testing.T) {
	for _, value := range []string{"=1+1", " +2", "\t@SUM(1,2)", "\ufeff=1", "＝1+1", "＋2", "－2", "＠foo", "hello\r\n=1"} {
		data, err := encodeCSV([]Event{{Actor: value, Resource: `plain, "quoted"`, Result: "recorded"}})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
		if err != nil || len(rows) != 2 || rows[1][5] != "[text] "+strings.ReplaceAll(value, "\r\n", "\n") || rows[1][7] != `plain, "quoted"` {
			t.Fatalf("unsafe or broken CSV for %q: %v", value, err)
		}
	}
}

func TestAuditReadDoesNotOutrunPermissionRevocation(t *testing.T) {
	s := testStore(t, false)
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := s.List(ctx, "organization-admin", testFilter(), ""); result <- err }()
	if _, err = tx.Exec(`DELETE FROM uem_access_grants WHERE user_id='organization-admin'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, access.ErrDenied) {
		t.Fatal("read bypassed committed revocation", err)
	}
}
