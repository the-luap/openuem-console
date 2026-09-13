package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/stretchr/testify/require"
)

func TestNetbirdSettingsHiddenExplicitScopedAndConcurrent(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	key := strings.Repeat("k", 32)
	store, err := consolesettings.NewNetbirdStore(f.db, f.permissions, key)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	require.NoError(t, store.Migrate(ctx))
	for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
		_, err := store.Read(ctx, actor, scope)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, invalid := range []access.Scope{{}, f.scope, {TenantID: -1}} {
		_, err := store.Read(ctx, "admin", invalid)
		require.ErrorIs(t, err, consolesettings.ErrNetbirdInvalid)
	}
	review, err := store.Read(ctx, "admin", scope)
	require.NoError(t, err)
	require.Zero(t, review.ID)
	require.False(t, review.TokenSet)
	count, err := f.client.NetbirdSettings.Query().Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count, "GET created provider settings")
	for _, base := range []string{"http://provider.invalid", "https://user:secret@provider.invalid", "https://provider.invalid?secret=private", "https://provider.invalid/a/../b"} {
		require.ErrorIs(t, store.Save(ctx, "admin", scope, review.ID, review.Revision, base, "replace", "owned-token"), consolesettings.ErrNetbirdInvalid)
	}
	for _, action := range []string{"keep", "clear", "unknown"} {
		require.ErrorIs(t, store.Save(ctx, "admin", scope, review.ID, review.Revision, "https://provider.example.invalid", action, "owned-token"), consolesettings.ErrNetbirdInvalid)
	}
	require.NoError(t, store.Save(ctx, "admin", scope, review.ID, review.Revision, "https://provider.example.invalid", "replace", "aabb"))
	require.ErrorIs(t, store.Save(ctx, "admin", scope, review.ID, review.Revision, "https://stale.example.invalid", "clear", ""), consolesettings.ErrNetbirdConflict)
	review, err = store.Read(ctx, "admin", scope)
	require.NoError(t, err)
	require.True(t, review.TokenSet)
	require.False(t, review.Shared)
	stored, err := f.client.NetbirdSettings.Get(ctx, int(review.ID))
	require.NoError(t, err)
	plain, err := legacysecret.Open(stored.AccessToken, key)
	require.NoError(t, err)
	require.True(t, plain == "aabb")
	require.NotEqual(t, plain, stored.AccessToken)
	withoutKey, err := consolesettings.NewNetbirdStore(f.db, f.permissions, "")
	require.NoError(t, err)
	require.NoError(t, withoutKey.Save(ctx, "admin", scope, review.ID, review.Revision, "https://kept.example.invalid", "keep", ""))
	kept, err := f.client.NetbirdSettings.Get(ctx, int(review.ID))
	require.NoError(t, err)
	require.Equal(t, stored.AccessToken, kept.AccessToken)
	review, err = store.Read(ctx, "admin", scope)
	require.NoError(t, err)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			results <- store.Save(ctx, "admin", scope, review.ID, review.Revision, fmt.Sprintf("https://concurrent-%d.example.invalid", i), "keep", "")
		}(i)
	}
	success, conflict := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, consolesettings.ErrNetbirdConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, conflict)
	review, err = store.Read(ctx, "admin", scope)
	require.NoError(t, err)
	require.NoError(t, withoutKey.Save(ctx, "admin", scope, review.ID, review.Revision, review.ManagementURL, "clear", ""))
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	export, err := audits.ExportJSON(ctx, "admin", audit.Filter{Scope: scope, Source: "settings", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	for _, hidden := range []string{"aabb", stored.AccessToken, "provider.example.invalid", key} {
		require.NotContains(t, string(export), hidden)
	}
	require.Contains(t, string(export), "settings.netbird.update")
}

func TestNetbirdSharedSettingsCopyWithoutReadingTokenAndAuditRollback(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	other, err := f.client.Tenant.Create().SetDescription("Owned shared NetBird organization").Save(ctx)
	require.NoError(t, err)
	ciphertext, err := legacysecret.Seal("owned-shared-token", strings.Repeat("k", 32))
	require.NoError(t, err)
	original, err := f.client.NetbirdSettings.Create().SetManagementURL("https://original.example.invalid").SetAccessToken(ciphertext).AddTenantIDs(scope.TenantID, other.ID).Save(ctx)
	require.NoError(t, err)
	store, err := consolesettings.NewNetbirdStore(f.db, f.permissions, "")
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	review, err := store.Read(ctx, "admin", scope)
	require.NoError(t, err)
	require.True(t, review.Shared)
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_netbird_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit failure'; END $$; CREATE TRIGGER reject_owned_netbird_audit BEFORE INSERT ON uem_settings_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_netbird_audit()`)
	require.NoError(t, err)
	require.Error(t, store.Save(ctx, "admin", scope, review.ID, review.Revision, "https://copy.example.invalid", "keep", ""))
	count, err := f.client.NetbirdSettings.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	var owner int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT tenant_netbird FROM tenants WHERE id=$1", scope.TenantID).Scan(&owner))
	require.Equal(t, original.ID, owner)
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_netbird_audit ON uem_settings_audit")
	require.NoError(t, err)
	require.NoError(t, store.Save(ctx, "admin", scope, review.ID, review.Revision, "https://copy.example.invalid", "keep", ""))
	changed, err := store.Read(ctx, "admin", scope)
	require.NoError(t, err)
	require.NotEqual(t, review.ID, changed.ID)
	require.False(t, changed.Shared)
	copy, err := f.client.NetbirdSettings.Get(ctx, int(changed.ID))
	require.NoError(t, err)
	require.Equal(t, ciphertext, copy.AccessToken)
	foreign, err := store.Read(ctx, "admin", access.Scope{TenantID: other.ID})
	require.NoError(t, err)
	require.Equal(t, int64(original.ID), foreign.ID)
	require.Equal(t, "https://original.example.invalid", foreign.ManagementURL)
	_, err = f.db.ExecContext(ctx, "UPDATE tenants SET tenant_netbird=$2 WHERE id=$1", scope.TenantID, original.ID)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "UPDATE tenants SET tenant_netbird=$2 WHERE id=$1", scope.TenantID, changed.ID)
	require.NoError(t, err)
	require.ErrorIs(t, store.Save(ctx, "admin", scope, changed.ID, changed.Revision, "https://copy.example.invalid", "clear", ""), consolesettings.ErrNetbirdConflict, "ownership ABA reused an old review")
	current, err := store.Read(ctx, "admin", scope)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "UPDATE netbird_settings SET management_url='https://external.example.invalid' WHERE id=$1", current.ID)
	require.NoError(t, err)
	require.ErrorIs(t, store.Save(ctx, "admin", scope, current.ID, current.Revision, "https://copy.example.invalid", "clear", ""), consolesettings.ErrNetbirdConflict)
	_, err = f.db.ExecContext(ctx, "ALTER TABLE tenants DISABLE TRIGGER uem_netbird_tenant_revision")
	require.NoError(t, err)
	require.Error(t, store.Migrate(ctx))
}

func TestNetbirdSecretMigrationBoundedResumableAndScoped(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	key := strings.Repeat("k", 32)
	store, err := consolesettings.NewNetbirdStore(f.db, f.permissions, key)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	ids := []int{}
	for i := 0; i < 66; i++ {
		value := "aabb"
		if i == 65 {
			value = strings.Repeat("a", 56)
		}
		create := f.client.NetbirdSettings.Create().SetAccessToken(value)
		if i == 0 {
			create.AddTenantIDs(scope.TenantID)
		}
		entry, err := create.Save(ctx)
		require.NoError(t, err)
		ids = append(ids, entry.ID)
	}
	require.ErrorIs(t, store.MigrateSecrets(ctx), consolesettings.ErrNetbirdMigration)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_settings_audit WHERE action='settings.netbird.secrets_migrate'").Scan(&count))
	require.Equal(t, 64, count)
	rolled, err := f.client.NetbirdSettings.Get(ctx, ids[64])
	require.NoError(t, err)
	require.Equal(t, "aabb", rolled.AccessToken)
	require.NoError(t, f.client.NetbirdSettings.UpdateOneID(ids[65]).SetAccessToken("owned-repaired-token").Exec(ctx))
	require.NoError(t, store.MigrateSecrets(ctx))
	require.NoError(t, store.MigrateSecrets(ctx))
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_settings_audit WHERE action='settings.netbird.secrets_migrate'").Scan(&count))
	require.Equal(t, 66, count)
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_settings_audit WHERE action='settings.netbird.secrets_migrate' AND tenant_id=$1", scope.TenantID).Scan(&count))
	require.Equal(t, 1, count)
	wrong, err := consolesettings.NewNetbirdStore(f.db, f.permissions, strings.Repeat("z", 32))
	require.NoError(t, err)
	require.ErrorIs(t, wrong.MigrateSecrets(ctx), consolesettings.ErrNetbirdMigration)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, store.MigrateSecrets(canceled), consolesettings.ErrNetbirdMigration)
}

func TestNetbirdMigrationPreservesSharedScopeNullAndAuditAtomicity(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	other, err := f.client.Tenant.Create().SetDescription("Owned second migration organization").Save(ctx)
	require.NoError(t, err)
	entry, err := f.client.NetbirdSettings.Create().SetAccessToken("owned-migration-token").AddTenantIDs(scope.TenantID, other.ID).Save(ctx)
	require.NoError(t, err)
	empty, err := f.client.NetbirdSettings.Create().Save(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "UPDATE netbird_settings SET access_token=NULL WHERE id=$1", empty.ID)
	require.NoError(t, err)
	store, err := consolesettings.NewNetbirdStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_netbird_migration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned migration failure'; END $$; CREATE TRIGGER reject_owned_netbird_migration BEFORE INSERT ON uem_settings_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_netbird_migration()`)
	require.NoError(t, err)
	require.ErrorIs(t, store.MigrateSecrets(ctx), consolesettings.ErrNetbirdMigration)
	stored, err := f.client.NetbirdSettings.Get(ctx, entry.ID)
	require.NoError(t, err)
	require.True(t, stored.AccessToken == "owned-migration-token")
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_netbird_migration ON uem_settings_audit")
	require.NoError(t, err)
	require.NoError(t, store.MigrateSecrets(ctx))
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_settings_audit WHERE action='settings.netbird.secrets_migrate' AND tenant_id IN ($1,$2)", scope.TenantID, other.ID).Scan(&count))
	require.Equal(t, 2, count)
	var isNull bool
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT access_token IS NULL FROM netbird_settings WHERE id=$1", empty.ID).Scan(&isNull))
	require.True(t, isNull)
}

func TestNetbirdNavigationProjectionAndCredentialReadsAreBounded(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	model := &models.Model{DB: f.db, Client: f.client}
	present, err := model.HasNetbirdToken(ctx, scope.TenantID)
	require.NoError(t, err)
	require.False(t, present)
	_, err = model.GetNetbirdSettings(ctx, scope.TenantID)
	require.Error(t, err)
	count, err := f.client.NetbirdSettings.Query().Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count)
	entry, err := f.client.NetbirdSettings.Create().SetAccessToken(strings.Repeat("x", legacysecret.MaxStoredSize+1)).AddTenantIDs(scope.TenantID).Save(ctx)
	require.NoError(t, err)
	present, err = model.HasNetbirdToken(ctx, scope.TenantID)
	require.NoError(t, err)
	require.True(t, present)
	_, err = model.GetNetbirdSettings(ctx, scope.TenantID)
	require.Error(t, err)
	require.NoError(t, f.client.NetbirdSettings.UpdateOneID(entry.ID).SetAccessToken("owned-current").Exec(ctx))
	snapshot, err := model.GetNetbirdSettings(ctx, scope.TenantID)
	require.NoError(t, err)
	require.True(t, snapshot.AccessToken == "owned-current")
	require.NoError(t, f.client.NetbirdSettings.UpdateOneID(entry.ID).SetAccessToken("owned-replaced").Exec(ctx))
	fresh, err := model.GetNetbirdSettings(ctx, scope.TenantID)
	require.NoError(t, err)
	require.True(t, fresh.AccessToken == "owned-replaced")
	require.True(t, snapshot.AccessToken == "owned-current")
	_, err = model.GetNetbirdSettings(ctx, scope.TenantID+10000)
	require.Error(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = model.HasNetbirdToken(canceled, scope.TenantID)
	require.Error(t, err)
}
