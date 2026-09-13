package inventory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestTaskWizardHoldsProviderAndAuthorityThroughAudit(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	p := ownedTagProfile(t, f, f.scope, "Owned wizard lock parent")
	settings, err := f.client.NetbirdSettings.Create().SetManagementURL("https://owned.invalid").SetAccessToken("owned-token").AddTenantIDs(f.scope.TenantID).Save(ctx)
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810074)")
	require.NoError(t, err)
	var auditOnce, lookupOnce sync.Once
	releaseAudit := func() {
		auditOnce.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810074)")
			_ = conn.Close()
		})
	}
	t.Cleanup(releaseAudit)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_task_wizard_entered; CREATE FUNCTION hold_owned_task_wizard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tasks.wizard_read' THEN PERFORM nextval('owned_task_wizard_entered'); PERFORM pg_advisory_xact_lock(673810074); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_task_wizard AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_task_wizard()`)
	require.NoError(t, err)
	lookup, ready := make(chan struct{}), make(chan struct{})
	releaseLookup := func() { lookupOnce.Do(func() { close(lookup) }) }
	t.Cleanup(releaseLookup)
	type outcome struct {
		groups []nats.NetBirdGroups
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		groups, err := inventory.ReadTaskWizard(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(p.ID), "definition", "netbird_register", "", func(ctx context.Context, base, token string) ([]nats.NetBirdGroups, error) {
			close(ready)
			select {
			case <-lookup:
				return []nats.NetBirdGroups{{ID: "owned"}}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		done <- outcome{groups, err}
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("provider lookup did not start")
	}
	blocked := func() {
		t.Helper()
		for _, change := range []func(context.Context) error{
			func(ctx context.Context) error {
				_, err := f.db.ExecContext(ctx, `UPDATE netbird_settings SET access_token='rotated' WHERE id=$1`, settings.ID)
				return err
			},
			func(ctx context.Context) error {
				_, err := f.db.ExecContext(ctx, `UPDATE tenants SET tenant_netbird=NULL WHERE id=$1`, f.scope.TenantID)
				return err
			},
			func(ctx context.Context) error {
				_, err := f.db.ExecContext(ctx, `DELETE FROM site_profiles WHERE profile_id=$1`, p.ID)
				return err
			},
			func(ctx context.Context) error {
				_, err := f.db.ExecContext(ctx, `DELETE FROM profiles WHERE id=$1`, p.ID)
				return err
			},
			func(ctx context.Context) error {
				return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}})
			},
		} {
			bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			err := change(bounded)
			cancel()
			require.Error(t, err)
		}
		select {
		case <-done:
			t.Fatal("wizard groups were published before audit commit")
		default:
		}
	}
	blocked()
	releaseLookup()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_task_wizard_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	blocked()
	releaseAudit()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Len(t, result.groups, 1)
	case <-time.After(2 * time.Second):
		t.Fatal("wizard lookup did not leave audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	_, err = inventory.ReadTaskWizard(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(p.ID), "definition", "netbird_register", "", func(context.Context, string, string) ([]nats.NetBirdGroups, error) {
		t.Fatal("revoked request contacted provider")
		return nil, nil
	})
	require.ErrorIs(t, err, access.ErrDenied)
}
