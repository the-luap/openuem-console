package desktop

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func desktopStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AGENT_ENROLLMENT_TEST_DATABASE_URL for desktop metadata tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "desktop_metadata_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Exec(`CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT NOT NULL REFERENCES tenants(id),description TEXT NOT NULL DEFAULT 'Isolated site'); INSERT INTO tenants VALUES(1),(2); INSERT INTO sites(id,tenant_sites) VALUES(1,1),(2,2),(3,1)`); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db, "isolated-desktop-metadata-master-key")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []int{1, 2} {
		if _, err = store.Registry.EnsureAuthority(context.Background(), tenant, "Test organization", "https://uem.example.test", "admin", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func TestDesktopMetadataIsScopedPaginatedAndDoesNotExposeEnrollmentSecrets(t *testing.T) {
	s := desktopStore(t)
	ctx := context.Background()
	scopes := []registry.Scope{{TenantID: 1, SiteID: 1}, {TenantID: 1, SiteID: 1}, {TenantID: 1, SiteID: 3}, {TenantID: 2, SiteID: 2}}
	tokens := []string{}
	ids := []string{}
	for _, scope := range scopes {
		invitation, err := s.Registry.Invite(ctx, registry.InvitationOptions{Scope: scope, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
		if err != nil {
			t.Fatal(err)
		}
		token := invitation.URL[strings.LastIndex(invitation.URL, "/")+1:]
		tokens = append(tokens, token)
		keys, err := enrollment.GenerateKeys()
		if err != nil {
			t.Fatal(err)
		}
		request, err := keys.Request(token, "windows", "amd64", "Test endpoint")
		if err != nil {
			t.Fatal(err)
		}
		identity, err := s.Registry.Claim(ctx, *request)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, identity.DeviceID)
	}
	page, err := s.Identities(ctx, registry.Scope{TenantID: 1, SiteID: 1}, "site-viewer", "", 1)
	if err != nil || len(page.Rows) != 1 || page.Next == "" {
		t.Fatal("first bounded identity page failed", err)
	}
	first := page.Rows[0].ID
	page, err = s.Identities(ctx, registry.Scope{TenantID: 1, SiteID: 1}, "site-viewer", page.Next, 1)
	if err != nil || len(page.Rows) != 1 || page.Next != "" || page.Rows[0].ID == first {
		t.Fatal("identity cursor skipped or repeated a row", err)
	}
	all, err := s.Identities(ctx, registry.Scope{TenantID: 1}, "org-viewer", "", 100)
	if err != nil || len(all.Rows) != 3 {
		t.Fatal("organization identity query crossed scope", err)
	}
	for _, item := range all.Rows {
		if item.TenantID != 1 || item.ConsumerReady || !item.ScopeValid {
			t.Fatal("incorrect scoped identity metadata")
		}
	}
	invites, err := s.Invitations(ctx, registry.Scope{TenantID: 1, SiteID: 1}, "site-viewer", "", 1)
	if err != nil || len(invites.Rows) != 1 || invites.Next == "" || invites.Rows[0].Uses != 1 {
		t.Fatal("invitation metadata failed", err)
	}
	next, err := s.Invitations(ctx, registry.Scope{TenantID: 1, SiteID: 1}, "site-viewer", invites.Next, 1)
	if err != nil || len(next.Rows) != 1 || next.Next != "" || next.Rows[0].ID == invites.Rows[0].ID {
		t.Fatal("invitation keyset pagination failed", err)
	}
	encoded, err := json.Marshal(invites)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if strings.Contains(string(encoded), token) {
			t.Fatal("metadata exposed a reusable invitation token")
		}
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), "token_hash") || strings.Contains(string(encoded), "broker_key") {
		t.Fatal("metadata exposed credential material")
	}
	if _, err = s.Authority(ctx, registry.Scope{TenantID: 1, SiteID: 2}, "viewer"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("authority read accepted another organization's site", err)
	}
	if _, err = s.Identities(ctx, registry.Scope{TenantID: 2, SiteID: 1}, "viewer", "", 50); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("identity read accepted another organization's site", err)
	}
	if _, err = s.Invitations(ctx, registry.Scope{TenantID: 1}, "viewer", "invalid cursor", 50); !errors.Is(err, registry.ErrInvalid) {
		t.Fatal("malformed cursor accepted", err)
	}
	if err = s.Registry.RevokeIdentity(ctx, registry.Scope{TenantID: 1}, ids[0], "admin"); err != nil {
		t.Fatal(err)
	}
	all, err = s.Identities(ctx, registry.Scope{TenantID: 1}, "org-viewer", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range all.Rows {
		if item.ID == ids[0] {
			found = item.RevokedAt != nil
		}
	}
	if !found {
		t.Fatal("revocation was hidden from scoped metadata")
	}
	var reads int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE actor IN ('site-viewer','org-viewer') AND action IN ('agent.identities.read','agent.invitations.read')`).Scan(&reads); err != nil || reads < 5 {
		t.Fatal("inventory and invitation reads were not audited", err)
	}
}
