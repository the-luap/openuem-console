package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/utils"
	"github.com/stretchr/testify/require"
)

func TestTaskWizardScopeReadOnlySettingsAndAudit(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	called := 0
	key := strings.Repeat("k", 32)
	resolver := func(ctx context.Context, base, token string) ([]nats.NetBirdGroups, error) {
		called++
		require.Equal(t, "https://owned-provider.invalid", base)
		require.Equal(t, "owned-provider-token", token)
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), 5*time.Second)
		return []nats.NetBirdGroups{{ID: "owned-ID", Name: "Owned <group>"}}, nil
	}
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		p := ownedTagProfile(t, f, scope, "Owned wizard destination")
		read := func(actor string, scope access.Scope, stage, value string) ([]nats.NetBirdGroups, error) {
			return inventory.ReadTaskWizard(ctx, f.db, f.permissions, actor, scope, int64(p.ID), stage, value, key, resolver)
		}
		for _, actor := range []string{"tag-admin", "tag-viewer", "tag-operator", "viewer", "missing"} {
			_, err := read(actor, scope, "types", "windows")
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, organization, f.scope} {
			if wrong != scope {
				_, err := read("admin", wrong, "definition", "netbird_register")
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		}
		require.Zero(t, called)
		for stage, value := range map[string]string{"types": "windows", "subtypes": "powershell_type", "definition": "winget_install"} {
			groups, err := read("admin", scope, stage, value)
			require.NoError(t, err)
			require.Empty(t, groups)
			audits, err := audit.NewStore(f.db, f.permissions)
			require.NoError(t, err)
			filter := audit.Filter{Scope: scope, Source: "inventory", Action: "inventory.tasks.wizard_read", Resource: fmt.Sprintf("%d/stage/%s", p.ID, stage), From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
			page, err := audits.List(ctx, "admin", filter, "")
			require.NoError(t, err)
			require.Len(t, page.Events, 1)
			body, err := audits.ExportJSON(ctx, "admin", filter)
			require.NoError(t, err)
			require.NotContains(t, string(body), "owned-provider-token")
		}
		before, err := f.client.NetbirdSettings.Query().Count(ctx)
		require.NoError(t, err)
		_, err = read("admin", scope, "definition", "netbird_register")
		if scope.TenantID == 0 {
			require.ErrorIs(t, err, inventory.ErrProfileCloneProviderScope)
		} else {
			require.ErrorIs(t, err, inventory.ErrTaskWizardProvider)
		}
		after, e := f.client.NetbirdSettings.Query().Count(ctx)
		require.NoError(t, e)
		require.Equal(t, before, after)
		require.Zero(t, called)
	}
	p := ownedTagProfile(t, f, f.scope, "Owned provider destination")
	encrypted, err := utils.EncryptSensitiveField("owned-provider-token", key)
	require.NoError(t, err)
	settings, err := f.client.NetbirdSettings.Create().SetManagementURL("https://owned-provider.invalid").SetAccessToken(encrypted).AddTenantIDs(f.scope.TenantID).Save(ctx)
	require.NoError(t, err)
	read := func(master string, resolver inventory.TaskWizardGroupReader) ([]nats.NetBirdGroups, error) {
		return inventory.ReadTaskWizard(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), "definition", "netbird_register", master, resolver)
	}
	for _, master := range []string{"", strings.Repeat("x", 32), "invalid"} {
		groups, err := read(master, resolver)
		require.ErrorIs(t, err, inventory.ErrTaskWizardProvider)
		require.Nil(t, groups)
	}
	require.Zero(t, called)
	groups, err := read(key, resolver)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, 1, called)
	stored, err := f.client.NetbirdSettings.Get(ctx, settings.ID)
	require.NoError(t, err)
	require.Equal(t, encrypted, stored.AccessToken)
	require.NoError(t, f.client.NetbirdSettings.UpdateOneID(settings.ID).SetAccessToken("aa").Exec(ctx))
	_, err = read(key, func(ctx context.Context, base, token string) ([]nats.NetBirdGroups, error) {
		require.Equal(t, "aa", token)
		return nil, nil
	})
	require.NoError(t, err, "short hex token must not panic")
	_, err = read(key, func(context.Context, string, string) ([]nats.NetBirdGroups, error) {
		return nil, errors.New("owned upstream detail")
	})
	require.ErrorIs(t, err, inventory.ErrTaskWizardProvider)
	require.NotContains(t, err.Error(), "upstream")
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_wizard_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.wizard_read' THEN RAISE EXCEPTION 'owned wizard audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_wizard_audit BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_wizard_audit()`)
	require.NoError(t, err)
	groups, err = read(key, func(context.Context, string, string) ([]nats.NetBirdGroups, error) {
		return []nats.NetBirdGroups{{ID: "not-published"}}, nil
	})
	require.Error(t, err)
	require.Nil(t, groups)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = inventory.ReadTaskWizard(cancelled, f.db, f.permissions, "admin", f.scope, int64(p.ID), "types", "windows", key, resolver)
	require.Error(t, err)
	for stage, value := range map[string]string{"unknown": "windows", "types": "invalid", "subtypes": "apt_type", "definition": "modify_unix_local_user"} {
		_, err = inventory.ReadTaskWizard(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), stage, value, key, resolver)
		require.ErrorIs(t, err, inventory.ErrTaskInvalid)
	}
}
