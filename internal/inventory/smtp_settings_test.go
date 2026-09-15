package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/stretchr/testify/require"
)

func ownedSMTPConfig() consolesettings.SMTPConfig {
	return consolesettings.SMTPConfig{Server: "smtp.example.invalid", Port: 587, User: "owned-user", Auth: "PLAIN", From: "owned@example.invalid", Encryption: "starttls"}
}

func TestSMTPSettingsScopeSecretsAndAtomicRevision(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	global, err := f.client.Settings.Create().SetSMTPServer("global.example.invalid").SetSMTPPassword("owned-existing-global").Save(ctx)
	require.NoError(t, err)
	scoped, err := f.client.Settings.Create().SetTenantID(organization.TenantID).SetSMTPServer("organization.example.invalid").SetSMTPPassword("owned-existing-org").Save(ctx)
	require.NoError(t, err)
	key := strings.Repeat("k", 32)
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, key)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	require.NoError(t, store.Migrate(ctx))
	for _, scope := range []access.Scope{{}, organization} {
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			_, err := store.Read(ctx, actor, scope)
			require.ErrorIs(t, err, access.ErrDenied)
		}
	}
	_, err = store.Read(ctx, "admin", f.scope)
	require.ErrorIs(t, err, consolesettings.ErrInvalid)
	review, err := store.Read(ctx, "admin", organization)
	require.NoError(t, err)
	require.True(t, review.PasswordSet)
	require.NotContains(t, fmt.Sprint(review), "owned-existing-org")
	require.Equal(t, int64(scoped.ID), review.ID)
	require.ErrorIs(t, store.Save(ctx, "admin", organization, int64(global.ID), review.Revision, ownedSMTPConfig(), "keep", ""), consolesettings.ErrNotFound)
	noKey, err := consolesettings.NewSMTPStore(f.db, f.permissions, "")
	require.NoError(t, err)
	require.ErrorIs(t, noKey.Save(ctx, "admin", organization, review.ID, review.Revision, ownedSMTPConfig(), "replace", "owned-new"), consolesettings.ErrSecret)
	require.NoError(t, noKey.Save(ctx, "admin", organization, review.ID, review.Revision, ownedSMTPConfig(), "keep", ""))
	kept, err := f.client.Settings.Get(ctx, scoped.ID)
	require.NoError(t, err)
	require.Equal(t, "owned-existing-org", kept.SMTPPassword)
	require.ErrorIs(t, store.Save(ctx, "admin", organization, review.ID, review.Revision, ownedSMTPConfig(), "clear", ""), consolesettings.ErrConflict)
	review, err = store.Read(ctx, "admin", organization)
	require.NoError(t, err)
	start := make(chan struct{})
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			done <- store.Save(ctx, "admin", organization, review.ID, review.Revision, ownedSMTPConfig(), "replace", "aabb")
		}()
	}
	close(start)
	results := []error{<-done, <-done}
	if results[0] != nil {
		require.ErrorIs(t, results[0], consolesettings.ErrConflict)
		require.NoError(t, results[1])
	} else {
		require.ErrorIs(t, results[1], consolesettings.ErrConflict)
	}
	saved, err := f.client.Settings.Get(ctx, scoped.ID)
	require.NoError(t, err)
	require.NotEqual(t, "aabb", saved.SMTPPassword)
	plain, err := legacysecret.Open(saved.SMTPPassword, key)
	require.NoError(t, err)
	require.True(t, plain == "aabb")
	globalAfter, err := f.client.Settings.Get(ctx, global.ID)
	require.NoError(t, err)
	require.Equal(t, "owned-existing-global", globalAfter.SMTPPassword)
	review, err = store.Read(ctx, "admin", organization)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "UPDATE settings SET smtp_user='owned-legacy-edit' WHERE id=$1", scoped.ID)
	require.NoError(t, err)
	require.ErrorIs(t, store.Save(ctx, "admin", organization, review.ID, review.Revision, ownedSMTPConfig(), "clear", ""), consolesettings.ErrConflict)
	review, err = store.Read(ctx, "admin", organization)
	require.NoError(t, err)
	require.NoError(t, noKey.Save(ctx, "admin", organization, review.ID, review.Revision, ownedSMTPConfig(), "clear", ""))
	saved, err = f.client.Settings.Get(ctx, scoped.ID)
	require.NoError(t, err)
	require.Empty(t, saved.SMTPPassword)
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	filter := audit.Filter{Scope: organization, Source: "settings", Action: "settings.smtp.update", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
	exported, err := audits.ExportJSON(ctx, "admin", filter)
	require.NoError(t, err)
	require.Contains(t, string(exported), "settings.smtp.update")
	for _, private := range []string{"owned-existing-org", "aabb", "owned-user", "smtp.example.invalid", key} {
		require.NotContains(t, string(exported), private)
	}
}

func TestSMTPSettingsAuditRollbackBoundsAndRevocation(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	entry, err := f.client.Settings.Create().SetSMTPServer("owned.example.invalid").SetSMTPPassword("owned-existing").Save(ctx)
	require.NoError(t, err)
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	review, err := store.Read(ctx, "admin", access.Scope{})
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_smtp_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit failure'; END $$; CREATE TRIGGER reject_owned_smtp_audit BEFORE INSERT ON uem_settings_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_smtp_audit()`)
	require.NoError(t, err)
	require.Error(t, store.Save(ctx, "admin", access.Scope{}, review.ID, review.Revision, ownedSMTPConfig(), "replace", "owned-new"))
	current, err := f.client.Settings.Get(ctx, entry.ID)
	require.NoError(t, err)
	require.Equal(t, "owned-existing", current.SMTPPassword)
	require.Equal(t, "owned.example.invalid", current.SMTPServer)
	_, err = store.Read(ctx, "admin", access.Scope{})
	require.Error(t, err)
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_smtp_audit ON uem_settings_audit")
	require.NoError(t, err)
	for _, choice := range []string{"", "keep", "clear"} {
		require.ErrorIs(t, store.Save(ctx, "admin", access.Scope{}, review.ID, review.Revision, ownedSMTPConfig(), choice, "conflicting-input"), consolesettings.ErrInvalid)
	}
	require.ErrorIs(t, store.Save(ctx, "admin", access.Scope{}, review.ID, review.Revision, ownedSMTPConfig(), "replace", strings.Repeat("x", legacysecret.MaxPlainSize+1)), consolesettings.ErrSecret)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, store.Save(cancelled, "admin", access.Scope{}, review.ID, review.Revision, ownedSMTPConfig(), "clear", ""))
	require.NoError(t, f.client.Settings.UpdateOneID(entry.ID).SetSMTPUser(strings.Repeat("x", 1025)).Exec(ctx))
	_, err = store.Read(ctx, "admin", access.Scope{})
	require.ErrorIs(t, err, consolesettings.ErrConflict)
	require.NoError(t, f.client.Settings.UpdateOneID(entry.ID).SetSMTPUser("owned-user").Exec(ctx))
	require.NoError(t, f.client.User.Create().SetID("smtp-admin").SetName("Owned settings administrator").SetEmail("smtp-admin@example.invalid").Exec(ctx))
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "smtp-admin", 0, []access.Grant{{Role: access.Administrator}}))
	delegated, err := store.Read(ctx, "smtp-admin", access.Scope{})
	require.NoError(t, err)
	principal, err := f.permissions.Principal(ctx, "smtp-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "smtp-admin", principal.Revision, nil))
	require.ErrorIs(t, store.Save(ctx, "smtp-admin", access.Scope{}, delegated.ID, delegated.Revision, ownedSMTPConfig(), "clear", ""), access.ErrDenied)

	_, err = f.db.ExecContext(ctx, "ALTER TABLE settings DISABLE TRIGGER uem_smtp_revision")
	require.NoError(t, err)
	require.Error(t, store.Migrate(ctx))
}

func TestSMTPSettingsTestAttemptSurvivesTerminalFailureAndReplay(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	_, err := f.client.Settings.Create().Save(ctx)
	require.NoError(t, err)
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	review, err := store.Read(ctx, "admin", access.Scope{})
	require.NoError(t, err)
	require.NoError(t, store.Save(ctx, "admin", access.Scope{}, review.ID, review.Revision, ownedSMTPConfig(), "replace", "owned-smtp-test"))
	review, err = store.Read(ctx, "admin", access.Scope{})
	require.NoError(t, err)
	calls := 0
	send := func(ctx context.Context, cfg consolesettings.SMTPConfig, password string) error {
		calls++
		require.Equal(t, ownedSMTPConfig(), cfg)
		require.True(t, password == "owned-smtp-test")
		return nil
	}
	request := uuid.NewString()
	first, err := store.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, request, send)
	require.NoError(t, err)
	require.Equal(t, "sent", first.Status)
	again, err := store.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, request, send)
	require.NoError(t, err)
	require.Equal(t, *first, *again)
	require.Equal(t, 1, calls)
	_, err = store.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, uuid.NewString(), send)
	require.ErrorIs(t, err, consolesettings.ErrRecent)
	_, err = f.db.ExecContext(ctx, "UPDATE uem_smtp_test_attempts SET created_at=clock_timestamp()-interval '2 minutes'")
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_smtp_terminal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='settings.smtp.test_sent' THEN RAISE EXCEPTION 'owned terminal failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_smtp_terminal BEFORE INSERT ON uem_settings_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_smtp_terminal()`)
	require.NoError(t, err)
	uncertain := uuid.NewString()
	_, err = store.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, uncertain, send)
	require.Error(t, err)
	require.Equal(t, 2, calls)
	restart, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	result, err := restart.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, uncertain, send)
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", result.Status)
	require.Equal(t, 2, calls)
	_, err = restart.Test(ctx, "admin", access.Scope{}, review.ID+1, review.Revision, uncertain, send)
	require.ErrorIs(t, err, consolesettings.ErrConflict)
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_smtp_terminal ON uem_settings_audit; UPDATE uem_smtp_test_attempts SET created_at=clock_timestamp()-interval '2 minutes'")
	require.NoError(t, err)
	result, err = store.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, uuid.NewString(), func(context.Context, consolesettings.SMTPConfig, string) error {
		return errors.New("owned-private-provider-error")
	})
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", result.Status)
	var auditText string
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT jsonb_agg(to_jsonb(a))::text FROM uem_settings_audit a").Scan(&auditText))
	require.NotContains(t, auditText, "owned-private-provider-error")
	require.NotContains(t, auditText, "owned-smtp-test")
}

func TestSMTPSecretMigrationIsBoundedAuditedAndResumable(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	key := strings.Repeat("k", 32)
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, key)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	ids := []int{}
	for i := 0; i < 66; i++ {
		password := "aabb"
		if i == 65 {
			password = strings.Repeat("a", 56)
		}
		organization, err := f.client.Tenant.Create().SetDescription(fmt.Sprintf("SMTP migration %d", i)).Save(ctx)
		require.NoError(t, err)
		entry, err := f.client.Settings.Create().SetTenantID(organization.ID).SetSMTPPassword(password).Save(ctx)
		require.NoError(t, err)
		ids = append(ids, entry.ID)
	}
	require.ErrorIs(t, store.MigrateSecrets(ctx), consolesettings.ErrMigration)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_settings_audit WHERE action='settings.smtp.secrets_migrate'").Scan(&count))
	require.Equal(t, 64, count)
	rolled, err := f.client.Settings.Get(ctx, ids[64])
	require.NoError(t, err)
	require.Equal(t, "aabb", rolled.SMTPPassword)
	require.NoError(t, f.client.Settings.UpdateOneID(ids[65]).SetSMTPPassword("owned-fixed").Exec(ctx))
	require.NoError(t, store.MigrateSecrets(ctx))
	require.NoError(t, store.MigrateSecrets(ctx))
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_settings_audit WHERE action='settings.smtp.secrets_migrate'").Scan(&count))
	require.Equal(t, 66, count)
	encrypted, err := f.client.Settings.Get(ctx, ids[0])
	require.NoError(t, err)
	plain, err := legacysecret.Open(encrypted.SMTPPassword, key)
	require.NoError(t, err)
	require.True(t, plain == "aabb")
	wrong, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("z", 32))
	require.NoError(t, err)
	require.ErrorIs(t, wrong.MigrateSecrets(ctx), consolesettings.ErrMigration)
}

func TestSMTPSettingsRejectsDuplicateGlobalScope(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	_, err := f.client.Settings.Create().Save(ctx)
	require.NoError(t, err)
	duplicate, err := f.client.Settings.Create().Save(ctx)
	require.NoError(t, err)
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.Error(t, store.Migrate(ctx), "ambiguous legacy globals must stop startup")
	require.NoError(t, f.client.Settings.DeleteOneID(duplicate.ID).Exec(ctx))
	require.NoError(t, store.Migrate(ctx))
	_, err = f.client.Settings.Create().Save(ctx)
	require.Error(t, err, "another writer must not create an ambiguous global scope")
	_, err = f.db.ExecContext(ctx, "DROP INDEX uem_settings_single_global")
	require.NoError(t, err)
	require.Error(t, store.Migrate(ctx), "missing singleton protection must stop startup")
}

func TestSMTPSettingsConcurrentReplayAndRetentionPreserveAttempt(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	for _, scope := range []access.Scope{{}, organization} {
		create := f.client.Settings.Create()
		if scope.TenantID > 0 {
			create.SetTenantID(scope.TenantID)
		}
		_, err := create.Save(ctx)
		require.NoError(t, err)
		review, err := store.Read(ctx, "admin", scope)
		require.NoError(t, err)
		require.NoError(t, store.Save(ctx, "admin", scope, review.ID, review.Revision, ownedSMTPConfig(), "replace", "owned-retention-password"))
		review, err = store.Read(ctx, "admin", scope)
		require.NoError(t, err)
		attempt := uuid.NewString()
		entered, release := make(chan struct{}, 2), make(chan struct{})
		send := func(context.Context, consolesettings.SMTPConfig, string) error {
			entered <- struct{}{}
			<-release
			return nil
		}
		results := make(chan error, 2)
		go func() {
			_, err := store.Test(ctx, "admin", scope, review.ID, review.Revision, attempt, send)
			results <- err
		}()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("SMTP attempt did not reach owned sender")
		}
		go func() {
			_, err := store.Test(ctx, "admin", scope, review.ID, review.Revision, attempt, send)
			results <- err
		}()
		close(release)
		require.NoError(t, <-results)
		require.NoError(t, <-results)
		require.Empty(t, entered, "concurrent replay sent twice")
		_, err = f.db.ExecContext(ctx, "UPDATE uem_settings_audit SET created_at=clock_timestamp()-interval '100 days'; UPDATE uem_smtp_test_attempts SET created_at=clock_timestamp()-interval '100 days'")
		require.NoError(t, err)
		preview, err := audits.PreviewRetention(ctx, "admin", scope, 30)
		require.NoError(t, err)
		require.Positive(t, preview.Counts["settings"])
		require.NoError(t, audits.ApplyRetention(ctx, "admin", scope, preview.ID, preview.Token))
		require.NoError(t, audits.PruneRetention(ctx))
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_settings_audit WHERE tenant_id=$1", scope.TenantID).Scan(&count))
		require.Zero(t, count)
		result, err := store.Test(ctx, "admin", scope, review.ID, review.Revision, attempt, func(context.Context, consolesettings.SMTPConfig, string) error {
			t.Error("retention erased deduplication evidence")
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, "sent", result.Status)
	}
}

func TestSMTPSettingsTestRequiresSecretAndCommittedAudit(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	key := strings.Repeat("k", 32)
	_, err := f.client.Settings.Create().Save(ctx)
	require.NoError(t, err)
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, key)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	review, err := store.Read(ctx, "admin", access.Scope{})
	require.NoError(t, err)
	require.NoError(t, store.Save(ctx, "admin", access.Scope{}, review.ID, review.Revision, ownedSMTPConfig(), "replace", "owned-test-secret"))
	review, err = store.Read(ctx, "admin", access.Scope{})
	require.NoError(t, err)
	neverSend := func(context.Context, consolesettings.SMTPConfig, string) error {
		t.Error("SMTP sent without secret and committed audit")
		return nil
	}
	wrong, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("z", 32))
	require.NoError(t, err)
	_, err = wrong.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, uuid.NewString(), neverSend)
	require.ErrorIs(t, err, consolesettings.ErrSecret)
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_smtp_attempt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned attempt audit failure'; END $$; CREATE TRIGGER reject_owned_smtp_attempt BEFORE INSERT ON uem_settings_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_smtp_attempt()`)
	require.NoError(t, err)
	_, err = store.Test(ctx, "admin", access.Scope{}, review.ID, review.Revision, uuid.NewString(), neverSend)
	require.Error(t, err)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_smtp_test_attempts").Scan(&count))
	require.Zero(t, count)
}

func TestSMTPSecretMigrationPreservesNullAndRollsBackAuditFailure(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	global, err := f.client.Settings.Create().Save(ctx)
	require.NoError(t, err)
	entry, err := f.client.Settings.Create().SetTenantID(organization.TenantID).SetSMTPPassword("owned-legacy-password").Save(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "UPDATE settings SET smtp_password=NULL WHERE id=$1", global.ID)
	require.NoError(t, err)
	store, err := consolesettings.NewSMTPStore(f.db, f.permissions, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_smtp_migration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned migration audit failure'; END $$; CREATE TRIGGER reject_owned_smtp_migration BEFORE INSERT ON uem_settings_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_smtp_migration()`)
	require.NoError(t, err)
	require.ErrorIs(t, store.MigrateSecrets(ctx), consolesettings.ErrMigration)
	stored, err := f.client.Settings.Get(ctx, entry.ID)
	require.NoError(t, err)
	require.True(t, stored.SMTPPassword == "owned-legacy-password")
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_smtp_migration ON uem_settings_audit")
	require.NoError(t, err)
	require.NoError(t, store.MigrateSecrets(ctx))
	var stillNull bool
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT smtp_password IS NULL FROM settings WHERE id=$1", global.ID).Scan(&stillNull))
	require.True(t, stillNull)
	var scope int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT tenant_id FROM uem_settings_audit WHERE action='settings.smtp.secrets_migrate'").Scan(&scope))
	require.Equal(t, organization.TenantID, scope)
}
