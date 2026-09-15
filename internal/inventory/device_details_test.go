package inventory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func newDetailsFixture(t *testing.T) *refreshFixture {
	f := newSoftwareFixture(t)
	require.NoError(t, f.client.User.Create().SetID("details-admin").SetName("Details administrator").SetEmail("details@example.test").SetUse2fa(false).Exec(t.Context()))
	require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", "details-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	return f
}

func TestDeviceDetailsAtomicRevisionAndConcurrentEdits(t *testing.T) {
	f := newDetailsFixture(t)
	ctx := t.Context()
	read := func() *inventory.DeviceDetails {
		d, err := inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id)
		require.NoError(t, err)
		return d
	}
	first := read()
	values := inventory.DeviceDetailValues{Nickname: "Finance & support", Description: "Private contacts\n\tSecond line\r\n", EndpointType: "Laptop"}
	updated, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id, first.Revision, values)
	require.NoError(t, err)
	require.NotEqual(t, first.Revision, updated.Revision)
	require.Equal(t, values, read().Values)
	unchanged, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id, updated.Revision, values)
	require.NoError(t, err)
	require.Equal(t, updated.Revision, unchanged.Revision)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetHostname("Later reported hostname").SetNotes("Independent notes").Exec(ctx))
	require.Equal(t, updated.Revision, read().Revision)
	_, err = f.db.ExecContext(ctx, `UPDATE agents SET uem_details_revision=$2 WHERE oid=$1`, f.id, uuid.NewString())
	require.Error(t, err)
	// Changes by legacy writers and changes away and back invalidate the editor.
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetDescription("Legacy edit").Exec(ctx))
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetDescription(values.Description).Exec(ctx))
	legacy := read()
	require.NotEqual(t, updated.Revision, legacy.Revision)
	got, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id, updated.Revision, values)
	require.ErrorIs(t, err, inventory.ErrDeviceDetailsConflict)
	require.Nil(t, got)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"First writer", "Second writer"} {
		go func() {
			<-start
			next := values
			next.Nickname = name
			_, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id, legacy.Revision, next)
			results <- err
		}()
	}
	close(start)
	won, stale := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			won++
		} else if errors.Is(err, inventory.ErrDeviceDetailsConflict) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, won)
	require.Equal(t, 1, stale)
	latest := read()
	cleared, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id, latest.Revision, inventory.DeviceDetailValues{EndpointType: "Other"})
	require.NoError(t, err)
	require.Empty(t, cleared.Values.Nickname)
	require.Empty(t, cleared.Values.Description)
	require.Equal(t, "Later reported hostname", cleared.Hostname)
	stored, err := f.client.Agent.Get(ctx, f.id)
	require.NoError(t, err)
	require.Equal(t, "Independent notes", stored.Notes)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.details.update' AND tenant_id=$1 AND site_id=$2 AND resource_id LIKE $3`, f.scope.TenantID, f.scope.SiteID, f.id+"/%").Scan(&count))
	require.Equal(t, 4, count)
}

func TestDeviceDetailsCurrentScopeAndRoleIsolation(t *testing.T) {
	f := newDetailsFixture(t)
	ctx := t.Context()
	for _, actor := range []string{"viewer", "operator", "missing"} {
		d, err := inventory.ReadDeviceDetails(ctx, f.db, f.permissions, actor, f.scope, f.id)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, d)
		d, err = inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, actor, f.scope, f.id, uuid.NewString(), inventory.DeviceDetailValues{EndpointType: "Server"})
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, d)
	}
	for _, change := range []string{"other-site", "foreign-organization", "ambiguous", "orphan", "waiting", "missing"} {
		t.Run(change, func(t *testing.T) {
			f := newDetailsFixture(t)
			id := f.id
			switch change {
			case "other-site":
				require.NoError(t, f.client.Agent.UpdateOneID(id).ClearSite().AddSiteIDs(f.otherSite).Exec(ctx))
			case "foreign-organization":
				tenant, err := f.client.Tenant.Create().SetDescription("Foreign organization").Save(ctx)
				require.NoError(t, err)
				site, err := f.client.Site.Create().SetDescription("Foreign site").SetTenantID(tenant.ID).Save(ctx)
				require.NoError(t, err)
				require.NoError(t, f.client.Agent.UpdateOneID(id).ClearSite().AddSiteIDs(site.ID).Exec(ctx))
			case "ambiguous":
				require.NoError(t, f.client.Agent.UpdateOneID(id).AddSiteIDs(f.otherSite).Exec(ctx))
			case "orphan":
				require.NoError(t, f.client.Agent.UpdateOneID(id).ClearSite().Exec(ctx))
			case "waiting":
				require.NoError(t, f.client.Agent.UpdateOneID(id).SetAgentStatus(agent.AgentStatusWaitingForAdmission).Exec(ctx))
			case "missing":
				id = "missing-device"
			}
			for _, actor := range []string{"admin", "details-admin"} {
				d, err := inventory.ReadDeviceDetails(ctx, f.db, f.permissions, actor, f.scope, id)
				require.ErrorIs(t, err, inventory.ErrNotFound)
				require.Nil(t, d)
				d, err = inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, actor, f.scope, id, uuid.NewString(), inventory.DeviceDetailValues{EndpointType: "Other"})
				require.ErrorIs(t, err, inventory.ErrNotFound)
				require.Nil(t, d)
			}
		})
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "details-admin", 1, nil))
	d, err := inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, d)
}

func TestDeviceDetailsRejectInvalidAndOversizedValues(t *testing.T) {
	f := newDetailsFixture(t)
	ctx := t.Context()
	first, err := inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id)
	require.NoError(t, err)
	for _, values := range []inventory.DeviceDetailValues{
		{Nickname: strings.Repeat("n", 256), EndpointType: "Other"},
		{Nickname: strings.Repeat("é", 128), EndpointType: "Other"},
		{Nickname: "bad\nname", EndpointType: "Other"},
		{Nickname: "bad\x00name", EndpointType: "Other"},
		{Nickname: string([]byte{0xff}), EndpointType: "Other"},
		{Description: strings.Repeat("d", 4097), EndpointType: "Other"},
		{Description: "bad\x01text", EndpointType: "Other"},
		{Description: string([]byte{0xff}), EndpointType: "Other"},
		{EndpointType: "arbitrary"},
		{EndpointType: ""},
	} {
		d, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id, first.Revision, values)
		require.ErrorIs(t, err, inventory.ErrDeviceDetailsInvalid)
		require.Nil(t, d)
	}
	for _, revision := range []string{"", uuid.Nil.String(), strings.ToUpper(first.Revision), "not-a-uuid"} {
		d, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id, revision, first.Values)
		require.ErrorIs(t, err, inventory.ErrDeviceDetailsInvalid)
		require.Nil(t, d)
	}
	max := inventory.DeviceDetailValues{Nickname: strings.Repeat("n", 255), Description: strings.Repeat("d", 4096), EndpointType: "AllInOne"}
	d, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id, first.Revision, max)
	require.NoError(t, err)
	require.Equal(t, max, d.Values)
	_, err = f.db.ExecContext(ctx, `UPDATE agents SET description=$2 WHERE oid=$1`, f.id, strings.Repeat("oversized", 1000))
	require.NoError(t, err)
	d, err = inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id)
	require.ErrorIs(t, err, inventory.ErrDeviceDetailsInvalid)
	require.Nil(t, d)
}

func TestDeviceDetailsAuditFailureRollsBackAllFields(t *testing.T) {
	f := newDetailsFixture(t)
	ctx := t.Context()
	first, err := inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT details_audit_failure CHECK(action NOT IN ('inventory.details.read','inventory.details.update')) NOT VALID`)
	require.NoError(t, err)
	d, err := inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id, first.Revision, inventory.DeviceDetailValues{Nickname: "Must not save", Description: "Must roll back", EndpointType: "Server"})
	require.Error(t, err)
	require.Nil(t, d)
	d, err = inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "admin", f.scope, f.id)
	require.Error(t, err)
	require.Nil(t, d)
	var values inventory.DeviceDetailValues
	var revision string
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT nickname,description,endpoint_type,uem_details_revision::text FROM agents WHERE oid=$1`, f.id).Scan(&values.Nickname, &values.Description, &values.EndpointType, &revision))
	require.Equal(t, first.Values, values)
	require.Equal(t, first.Revision, revision)
}

func TestDeviceDetailsKeepAuthorityMembershipAndValuesThroughAudit(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[write], func(t *testing.T) {
			f := newDetailsFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			first, err := inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id)
			require.NoError(t, err)
			blocker, err := f.db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer blocker.Rollback()
			_, err = blocker.ExecContext(ctx, `LOCK TABLE uem_inventory_audit IN SHARE MODE`)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() {
				var err error
				if write {
					_, err = inventory.UpdateDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id, first.Revision, inventory.DeviceDetailValues{Nickname: "Committed label", EndpointType: "Laptop"})
				} else {
					_, err = inventory.ReadDeviceDetails(ctx, f.db, f.permissions, "details-admin", f.scope, f.id)
				}
				done <- err
			}()
			wait := func(n int, auditOnly bool) {
				t.Helper()
				require.Eventually(t, func() bool {
					var count int
					err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE NOT l.granted AND a.application_name=current_setting('application_name') AND (NOT $1 OR (l.relation='uem_inventory_audit'::regclass AND l.mode='RowExclusiveLock'))`, auditOnly).Scan(&count)
					return err == nil && count >= n
				}, 3*time.Second, 10*time.Millisecond)
			}
			wait(1, true)
			changed := make(chan error, 3)
			go func() { changed <- f.permissions.ReplaceGrants(ctx, "admin", "details-admin", 1, nil) }()
			go func() {
				_, err := f.db.ExecContext(ctx, `INSERT INTO site_agents(site_id,agent_id) VALUES($1,$2)`, f.otherSite, f.id)
				changed <- err
			}()
			go func() {
				_, err := f.db.ExecContext(ctx, `UPDATE agents SET description='Later legacy edit' WHERE oid=$1`, f.id)
				changed <- err
			}()
			wait(4, false)
			select {
			case err := <-changed:
				t.Fatal("change overtook the details audit", err)
			default:
			}
			require.NoError(t, blocker.Commit())
			require.NoError(t, <-done)
			for range 3 {
				require.NoError(t, <-changed)
			}
		})
	}
}
