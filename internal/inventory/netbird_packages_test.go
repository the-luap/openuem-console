package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func ownedNetbirdPackage(scope access.Scope) packageapi.Package {
	return packageapi.Package{Schema: 1, ApprovalID: uuid.NewString(), TenantID: int64(scope.TenantID), Platform: "linux", Architecture: "arm64", Format: "deb", PackageID: "netbird", Version: "0.78.1", URL: "https://packages.example.invalid/netbird.deb?private=owned-source-secret", Size: 1234, SHA256: strings.Repeat("a", 64)}
}

func TestNetbirdPackageApprovalsScopeReplayPrivacyAndRevocation(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	store, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	input := ownedNetbirdPackage(scope)
	for _, actor := range []string{"tag-viewer", "tag-operator", "viewer", "operator", "missing"} {
		_, err = store.Approve(ctx, actor, scope, input, "Owned publisher review 42")
		require.ErrorIs(t, err, access.ErrDenied)
	}
	approved, err := store.Approve(ctx, "tag-admin", scope, input, "Owned publisher review 42")
	require.NoError(t, err)
	for _, actor := range []string{"tag-viewer", "tag-operator", "tag-admin", "admin"} {
		got, err := store.Read(ctx, actor, scope, approved.ID)
		require.NoError(t, err)
		require.Equal(t, approved, got)
		data, err := json.Marshal(got)
		require.NoError(t, err)
		require.NotContains(t, string(data), "owned-source-secret")
		require.NotContains(t, fmt.Sprintf("%#v", got), "packages.example.invalid")
	}
	for _, actor := range []string{"viewer", "operator"} {
		_, err = store.Read(ctx, actor, scope, approved.ID)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, badScope := range []access.Scope{{}, f.scope, {TenantID: -1}} {
		_, err = store.List(ctx, "admin", badScope, "")
		require.ErrorIs(t, err, inventory.ErrNetbirdPackageInvalid)
	}
	other, err := f.client.Tenant.Create().SetDescription("Other package organization").Save(ctx)
	require.NoError(t, err)
	foreign := access.Scope{TenantID: other.ID}
	_, err = store.Read(ctx, "tag-admin", foreign, approved.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = store.Read(ctx, "admin", foreign, approved.ID)
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageMissing)
	_, err = store.List(ctx, "admin", foreign, approved.ID)
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageMissing)
	for _, change := range []string{"source", "scope", "version", "verification", "actor"} {
		p, actor, verification := input, "tag-admin", "Owned publisher review 42"
		switch change {
		case "source":
			p.URL += "-changed"
		case "scope":
			p.TenantID = int64(other.ID)
			actor = "admin"
		case "version":
			p.Version = "0.78.2"
		case "verification":
			verification = "Other review"
		case "actor":
			actor = "admin"
		}
		selected := scope
		if change == "scope" {
			selected = foreign
		}
		_, err = store.Approve(ctx, actor, selected, p, verification)
		require.ErrorIs(t, err, inventory.ErrNetbirdPackageConflict)
	}
	got, err := store.Approve(ctx, "tag-admin", scope, input, "Owned publisher review 42")
	require.NoError(t, err)
	require.Equal(t, approved, got)
	var encrypted []byte
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT encrypted_descriptor FROM uem_netbird_packages WHERE id=$1`, approved.ID).Scan(&encrypted))
	require.NotContains(t, string(encrypted), "owned-source-secret")
	wrong, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, strings.Repeat("z", 32))
	require.NoError(t, err)
	_, err = wrong.Approve(ctx, "tag-admin", scope, input, "Owned publisher review 42")
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageSecret)
	_, err = wrong.Read(ctx, "tag-viewer", scope, approved.ID)
	require.NoError(t, err)
	revocation := uuid.NewString()
	_, err = store.Revoke(ctx, "tag-operator", scope, approved.ID, approved.Digest, revocation)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = store.Revoke(ctx, "tag-admin", scope, approved.ID, strings.Repeat("b", 64), revocation)
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageConflict)
	revoked, err := wrong.Revoke(ctx, "tag-admin", scope, approved.ID, approved.Digest, revocation)
	require.NoError(t, err)
	require.NotNil(t, revoked.RevokedAt)
	got, err = store.Revoke(ctx, "tag-admin", scope, approved.ID, approved.Digest, revocation)
	require.NoError(t, err)
	require.Equal(t, revoked, got)
	_, err = store.Revoke(ctx, "tag-admin", scope, approved.ID, approved.Digest, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageConflict)
	got, err = store.Approve(ctx, "tag-admin", scope, input, "Owned publisher review 42")
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt, "approval replay reactivated revoked bytes")
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_settings_audit WHERE action IN ('settings.netbird.packages.approve','settings.netbird.packages.revoke')`).Scan(&count))
	require.Equal(t, 2, count)
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	exported, err := audits.ExportJSON(ctx, "tag-admin", audit.Filter{Scope: scope, Source: "settings", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	require.Contains(t, string(exported), "settings.netbird.packages.approve")
	require.NotContains(t, string(exported), "owned-source-secret")
	require.NotContains(t, string(exported), "Owned publisher review")
}

func TestNetbirdPackageApprovalAtomicAuditAndBounds(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	store, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	for _, change := range []string{"identity", "scope", "hash", "size", "url", "wire-bound", "verification", "whitespace", "newline"} {
		p, verification := ownedNetbirdPackage(scope), "Owned review"
		switch change {
		case "identity":
			p.ApprovalID = "10000000-0000-4000-8000-00000000000A"
		case "scope":
			p.TenantID++
		case "hash":
			p.SHA256 = "a"
		case "size":
			p.Size = packageapi.MaxPackageSize + 1
		case "url":
			p.URL = "http://packages.invalid/netbird.deb"
		case "wire-bound":
			p.URL = "https://packages.invalid/netbird.deb?" + strings.Repeat("&", 1800)
		case "verification":
			verification = strings.Repeat("x", 513)
		case "whitespace":
			verification = " "
		case "newline":
			verification = "a\nb"
		}
		_, err = store.Approve(ctx, "tag-admin", scope, p, verification)
		require.ErrorIs(t, err, inventory.ErrNetbirdPackageInvalid, change)
	}
	missingKey, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, "")
	require.NoError(t, err)
	_, err = missingKey.Approve(ctx, "tag-admin", scope, ownedNetbirdPackage(scope), "Owned review")
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageSecret)
	input := ownedNetbirdPackage(scope)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_settings_audit ADD CONSTRAINT owned_package_audit_failure CHECK(action NOT LIKE 'settings.netbird.packages.%') NOT VALID`)
	require.NoError(t, err)
	_, err = store.Approve(ctx, "tag-admin", scope, input, "Owned review")
	require.Error(t, err)
	page, err := store.List(ctx, "tag-viewer", scope, "")
	require.Error(t, err)
	require.Nil(t, page)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_packages`).Scan(&count))
	require.Zero(t, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_settings_audit DROP CONSTRAINT owned_package_audit_failure`)
	require.NoError(t, err)
	p, err := store.Approve(ctx, "tag-admin", scope, input, "Owned review")
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_settings_audit ADD CONSTRAINT owned_package_audit_failure CHECK(action<>'settings.netbird.packages.revoke') NOT VALID`)
	require.NoError(t, err)
	_, err = store.Revoke(ctx, "tag-admin", scope, p.ID, p.Digest, uuid.NewString())
	require.Error(t, err)
	got, err := store.Read(ctx, "tag-viewer", scope, p.ID)
	require.NoError(t, err)
	require.Nil(t, got.RevokedAt)
	for _, query := range []string{`UPDATE uem_netbird_packages SET version='changed'`, `DELETE FROM uem_netbird_packages`} {
		_, err = f.db.ExecContext(ctx, query)
		require.Error(t, err)
	}
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_packages DISABLE TRIGGER uem_netbird_package_immutable`)
	require.NoError(t, err)
	require.Error(t, inventory.Migrate(ctx, f.db), "startup accepted disabled approval protection")
}

func TestNetbirdPackageConcurrentReplayAndPagination(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	store, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	input := ownedNetbirdPackage(scope)
	errors := make(chan error, 8)
	for range 8 {
		go func() { _, err := store.Approve(ctx, "tag-admin", scope, input, "Owned review"); errors <- err }()
	}
	for range 8 {
		require.NoError(t, <-errors)
	}
	p, err := store.Read(ctx, "tag-admin", scope, input.ApprovalID)
	require.NoError(t, err)
	requestID := uuid.NewString()
	for range 8 {
		go func() { _, err := store.Revoke(ctx, "tag-admin", scope, p.ID, p.Digest, requestID); errors <- err }()
	}
	for range 8 {
		require.NoError(t, <-errors)
	}
	for _, query := range []string{`UPDATE uem_netbird_package_revocations SET actor='changed'`, `DELETE FROM uem_netbird_package_revocations`} {
		_, err = f.db.ExecContext(ctx, query)
		require.Error(t, err)
	}
	for range 52 {
		_, err = store.Approve(ctx, "tag-admin", scope, ownedNetbirdPackage(scope), "Owned page fixture")
		require.NoError(t, err)
	}
	first, err := store.List(ctx, "tag-viewer", scope, "")
	require.NoError(t, err)
	require.Len(t, first.Approvals, 50)
	require.NotEmpty(t, first.Next)
	_, err = store.Approve(ctx, "tag-admin", scope, ownedNetbirdPackage(scope), "Newer approval after first page")
	require.NoError(t, err)
	second, err := store.List(ctx, "tag-viewer", scope, first.Next)
	require.NoError(t, err)
	require.Len(t, second.Approvals, 3)
	require.Empty(t, second.Next)
	seen := map[string]bool{}
	for _, page := range []*inventory.NetbirdPackagePage{first, second} {
		for _, entry := range page.Approvals {
			require.False(t, seen[entry.ID])
			seen[entry.ID] = true
		}
	}
	require.True(t, seen[p.ID])
	var approvals, revocations int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE action='settings.netbird.packages.approve'),count(*) FILTER(WHERE action='settings.netbird.packages.revoke') FROM uem_settings_audit`).Scan(&approvals, &revocations))
	require.Equal(t, 54, approvals)
	require.Equal(t, 1, revocations)
}

func TestNetbirdPackageApprovalHoldsAuthorityUntilAuditCommit(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	store, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(673810095)`)
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(673810095)`)
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_package_entered; CREATE FUNCTION hold_owned_package() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='settings.netbird.packages.approve' THEN PERFORM nextval('owned_package_entered'); PERFORM pg_advisory_xact_lock(673810095); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_package AFTER INSERT ON uem_settings_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_package()`)
	require.NoError(t, err)
	input := ownedNetbirdPackage(scope)
	done := make(chan error, 1)
	go func() { _, err := store.Approve(ctx, "tag-admin", scope, input, "Owned review"); done <- err }()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, `SELECT is_called FROM owned_package_entered`).Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	require.Error(t, f.permissions.ReplaceGrants(bounded, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}))
	cancel()
	release()
	require.NoError(t, <-done)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}))
	_, err = store.Approve(ctx, "tag-admin", scope, input, "Owned review")
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestNetbirdPackageEncryptedScopeAndRevocationRequestIdentity(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	store, err := inventory.NewNetbirdPackageStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	firstInput, secondInput := ownedNetbirdPackage(scope), ownedNetbirdPackage(scope)
	first, err := store.Approve(ctx, "tag-admin", scope, firstInput, "Owned first verification")
	require.NoError(t, err)
	second, err := store.Approve(ctx, "tag-admin", scope, secondInput, "Owned second verification")
	require.NoError(t, err)
	requestID := uuid.NewString()
	_, err = store.Revoke(ctx, "tag-admin", scope, first.ID, first.Digest, requestID)
	require.NoError(t, err)
	_, err = store.Revoke(ctx, "tag-admin", scope, second.ID, second.Digest, requestID)
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageConflict)
	got, err := store.Read(ctx, "tag-viewer", scope, second.ID)
	require.NoError(t, err)
	require.Nil(t, got.RevokedAt)
	_, err = f.db.ExecContext(ctx, `INSERT INTO uem_netbird_package_revocations(approval_id,id,actor,digest) VALUES($1,$2,'tag-admin',$3)`, second.ID, uuid.NewString(), first.Digest)
	require.Error(t, err)
	// Deliberately bypass the database guard inside this owned schema to prove
	// ciphertext remains authenticated to the immutable record, not just the key.
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_packages DISABLE TRIGGER uem_netbird_package_immutable`)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `UPDATE uem_netbird_packages SET encrypted_descriptor=(SELECT encrypted_descriptor FROM uem_netbird_packages WHERE id=$2) WHERE id=$1`, second.ID, first.ID)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_netbird_packages ENABLE TRIGGER uem_netbird_package_immutable`)
	require.NoError(t, err)
	_, err = store.Approve(ctx, "tag-admin", scope, secondInput, "Owned second verification")
	require.ErrorIs(t, err, inventory.ErrNetbirdPackageSecret)
}
