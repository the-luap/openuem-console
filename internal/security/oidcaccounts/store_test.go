package oidcaccounts_test

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
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

type fixture struct {
	s *oidcaccounts.Store
	m *models.Model
	a *access.Store
	p oidcaccounts.Policy
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for OpenID account integration")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "oidc_accounts_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	t.Setenv("ENV", "test")
	m, err := models.New(u.String(), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	for _, id := range []string{"admin", "reader", "other", "password", "viewer"} {
		if err = m.Client.User.Create().SetID(id).SetName(id).SetEmail(id + "@example.test").SetOpenid(id == "reader" || id == "other").SetPasswd(id == "password").SetUse2fa(false).SetRegister(nats.REGISTER_APPROVED).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	a, err := access.NewStore(m.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = a.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	settings, err := m.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings, err = settings.Update().SetUseOIDC(true).SetOIDCIssuerURL("https://identity.example.test").SetOIDCClientID("console").SetOIDCProvider("authelia").SetOIDCRole("members").SetOIDCAutoCreateAccount(false).SetOIDCAutoApprove(false).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s, err := oidcaccounts.NewStore(m.DB, a)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	return fixture{s, m, a, oidcaccounts.PolicyFrom(settings)}
}

func (f fixture) change(t *testing.T, actor, uid, subject, action string, revision int64) error {
	t.Helper()
	return f.s.Change(t.Context(), actor, uid, f.p.Issuer, f.p.ClientID, subject, action, revision)
}

func TestOIDCAccountBindingMigrationRevocationAndIssuerIsolation(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	tenant, err := f.m.Client.Tenant.Create().SetDescription("Owned organization").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.ReplaceGrants(ctx, "admin", "reader", 0, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: tenant.ID}}}); err != nil {
		t.Fatal(err)
	}
	id := oidcaccounts.Identity{Issuer: f.p.Issuer, Subject: "Case-Sensitive-subject", Name: "reader", Email: "reader@example.test"}
	if _, err := f.s.Resolve(ctx, f.p, id); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("unlinked existing account accepted", err)
	}
	if err := f.change(t, "viewer", "reader", id.Subject, "link", 0); !errors.Is(err, access.ErrDenied) {
		t.Fatal("unprivileged link", err)
	}
	for _, uid := range []string{"admin", "password"} {
		if err := f.change(t, "admin", uid, id.Subject, "link", 0); !errors.Is(err, oidcaccounts.ErrIdentity) {
			t.Fatal("wrong account mode linked", uid, err)
		}
	}
	if err := f.change(t, "admin", "reader", id.Subject, "link", 0); err != nil {
		t.Fatal(err)
	}
	if err := f.change(t, "admin", "reader", id.Subject, "link", 0); !errors.Is(err, oidcaccounts.ErrConflict) {
		t.Fatal("stale form replay accepted", err)
	}
	id.Name = "renamed account"
	id.Email = "other@example.test"
	if uid, err := f.s.Resolve(ctx, f.p, id); err != nil || uid != "reader" {
		t.Fatal("profile rename changed account", uid, err)
	}
	for _, subject := range []string{"case-sensitive-subject", "reader", "different-subject"} {
		changed := id
		changed.Subject = subject
		if _, err := f.s.Resolve(ctx, f.p, changed); !errors.Is(err, oidcaccounts.ErrIdentity) {
			t.Fatal("subject alias selected account", err)
		}
	}
	if err := f.change(t, "admin", "other", id.Subject, "link", 0); !errors.Is(err, oidcaccounts.ErrConflict) {
		t.Fatal("identity transferred account", err)
	}
	if err := f.change(t, "admin", "reader", id.Subject, "disable", 1); err != nil {
		t.Fatal(err)
	}
	settings, err := f.m.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings, err = settings.Update().SetOIDCAutoCreateAccount(true).SetOIDCAutoApprove(true).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.p = oidcaccounts.PolicyFrom(settings)
	if _, err = f.s.Resolve(ctx, f.p, id); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("automatic registration bypassed disabled binding", err)
	}
	if err = f.change(t, "admin", "reader", id.Subject, "enable", 2); err != nil {
		t.Fatal(err)
	}
	if err = f.m.Client.User.UpdateOneID("reader").SetRegister(nats.REGISTER_REVOKED).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Resolve(ctx, f.p, id); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("automatic approval bypassed revoked account", err)
	}
	if err = f.m.Client.User.UpdateOneID("reader").SetRegister(nats.REGISTER_APPROVED).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := f.s.Page(ctx, "admin", "reader")
	if err != nil || page.Revision != 3 || len(page.Bindings) != 1 || !page.Bindings[0].Active || len(page.Events) != 3 {
		t.Fatal("binding history", page, err)
	}
	if err = f.m.DeleteUser("reader"); err == nil {
		t.Fatal("bound account deletion allowed identity reuse")
	}
	oldPolicy := f.p
	settings, err = settings.Update().SetOIDCIssuerURL("https://replacement.example.test").SetOIDCAutoCreateAccount(false).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.p = oidcaccounts.PolicyFrom(settings)
	if _, err = f.s.Resolve(ctx, oldPolicy, id); !errors.Is(err, oidcaccounts.ErrConflict) {
		t.Fatal("old provider admitted after configuration change", err)
	}
	id.Issuer = f.p.Issuer
	if _, err = f.s.Resolve(ctx, f.p, id); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("new issuer reused old subject mapping", err)
	}
	if err = f.change(t, "admin", "reader", id.Subject, "link", 3); err != nil {
		t.Fatal(err)
	}
	if uid, err := f.s.Resolve(ctx, f.p, id); err != nil || uid != "reader" {
		t.Fatal("explicit issuer migration failed", uid, err)
	}
	principal, err := f.a.Principal(ctx, "reader")
	if err != nil || len(principal.Grants) != 1 || principal.Grants[0].Role != access.Viewer || principal.Grants[0].TenantID != tenant.ID {
		t.Fatal("identity migration changed existing permissions", err)
	}
	if _, err = f.s.Page(ctx, "viewer", "reader"); !errors.Is(err, access.ErrDenied) {
		t.Fatal("identity history exposed to unprivileged account", err)
	}
	if err = f.a.ReplaceGrants(ctx, "admin", "other", 0, []access.Grant{{Role: access.Administrator}}); err != nil {
		t.Fatal(err)
	}
	if err = f.a.ReplaceGrants(ctx, "admin", "other", 1, nil); err != nil {
		t.Fatal(err)
	}
	if err = f.change(t, "other", "reader", id.Subject, "disable", 4); !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked administrator changed identity", err)
	}
}

func TestOIDCAutomaticCreationIsAtomicConcurrentAndIndependent(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	settings, err := f.m.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings, err = settings.Update().SetOIDCAutoCreateAccount(true).SetOIDCAutoApprove(false).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.p = oidcaccounts.PolicyFrom(settings)
	id := oidcaccounts.Identity{Issuer: f.p.Issuer, Subject: "brand-new", Name: "admin", Email: "admin@example.test"}
	results := make(chan string, 12)
	failures := make(chan error, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() { uid, err := f.s.Resolve(ctx, f.p, id); results <- uid; failures <- err })
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	uid := ""
	for result := range results {
		if uid == "" {
			uid = result
		}
		if uid != result {
			t.Fatal("concurrent sign-ins created different accounts")
		}
	}
	if !strings.HasPrefix(uid, "oidc-") {
		t.Fatal("provider name selected local ID", uid)
	}
	user, err := f.m.GetUserById(uid)
	if err != nil || user.Register != nats.REGISTER_IN_REVIEW || user.EmailVerified || user.Passwd || !user.Openid {
		t.Fatal("registration state lost", err)
	}
	p, err := f.a.Principal(ctx, uid)
	if err != nil || len(p.Grants) != 0 {
		t.Fatal("new account inherited privileges", err)
	}
	page, err := f.s.Page(ctx, "admin", uid)
	if err != nil || page.Revision != 1 || len(page.Events) != 1 {
		t.Fatal("registration duplicated binding or audit", err)
	}
	if _, err = f.m.DB.Exec(`CREATE FUNCTION reject_oidc_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit failure'; END $$; CREATE TRIGGER reject_oidc_audit BEFORE INSERT ON uem_oidc_audit FOR EACH ROW EXECUTE FUNCTION reject_oidc_audit()`); err != nil {
		t.Fatal(err)
	}
	id.Subject = "audit-failure"
	before, err := f.m.Client.User.Query().Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Resolve(ctx, f.p, id); err == nil {
		t.Fatal("account created without audit")
	}
	after, err := f.m.Client.User.Query().Count(ctx)
	if err != nil || before != after {
		t.Fatal("failed audit left account behind", err)
	}
	if err = f.change(t, "admin", uid, "brand-new", "disable", 1); err == nil {
		t.Fatal("binding changed without audit")
	}
	page, err = f.s.Page(ctx, "admin", uid)
	if err != nil || page.Revision != 1 || !page.Bindings[0].Active {
		t.Fatal("audit failure did not roll back binding", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = f.s.Resolve(canceled, f.p, id); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestOIDCConcurrentBindingCannotTransferIdentity(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, uid := range []string{"reader", "other"} {
		wg.Go(func() { results <- f.change(t, "admin", uid, "shared-subject", "link", 0) })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, oidcaccounts.ErrConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("identity linked to multiple accounts", success)
	}
}
