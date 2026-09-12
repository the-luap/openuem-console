package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestDeviceGroupsRevisionMembershipAndScope(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	definition := inventory.DeviceGroupDefinition{Name: "Owned Windows", Description: "Current literal rule", Rule: inventory.DeviceGroupRule{Platform: "windows", Search: "Refresh"}}
	save := func(id string, revision int, d inventory.DeviceGroupDefinition) *inventory.DeviceGroup {
		t.Helper()
		g, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, id, revision, d)
		require.NoError(t, err)
		return g
	}
	g := save("", 0, definition)
	require.Equal(t, 1, g.Revision)
	inspect := func(position inventory.DeviceGroupPosition) *inventory.DeviceGroupInspection {
		t.Helper()
		p, err := inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, position)
		require.NoError(t, err)
		return p
	}
	require.Len(t, inspect(inventory.DeviceGroupPosition{}).Members.Entries, 1)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetHostname("Renamed outside the rule").Exec(ctx))
	require.Empty(t, inspect(inventory.DeviceGroupPosition{}).Members.Entries)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetNickname("Literal %_ <device>").Exec(ctx))
	definition.Rule.Search = "%_"
	g = save(g.ID, 1, definition)
	preview := inspect(inventory.DeviceGroupPosition{Revision: 2})
	require.Len(t, preview.Members.Entries, 1)
	require.Len(t, preview.History, 2)
	require.Equal(t, "Refresh", preview.History[1].Rule.Search)
	_, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, g.ID, 1, definition)
	require.ErrorIs(t, err, inventory.ErrGroupConflict)
	_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{Revision: 1})
	require.ErrorIs(t, err, inventory.ErrGroupConflict)
	// A hidden second edge must not become a target even for a global admin.
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx))
	preview, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "admin", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.NoError(t, err)
	require.Empty(t, preview.Members.Entries)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(ctx))
	require.Empty(t, inspect(inventory.DeviceGroupPosition{}).Members.Entries)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.scope.SiteID).Exec(ctx))
	definition.Archived = true
	g = save(g.ID, 2, definition)
	require.Empty(t, inspect(inventory.DeviceGroupPosition{}).Members.Entries)
	definition.Archived = false
	g = save(g.ID, 3, definition)
	require.Len(t, inspect(inventory.DeviceGroupPosition{}).Members.Entries, 1)
	for _, scope := range []access.Scope{{TenantID: f.scope.TenantID}, {TenantID: f.scope.TenantID, SiteID: f.otherSite}} {
		_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "admin", scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
		require.ErrorIs(t, err, inventory.ErrNotFound)
		_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "admin", scope, g.ID, 4, definition)
		require.ErrorIs(t, err, inventory.ErrNotFound)
		page, err := inventory.ListDeviceGroups(ctx, f.db, f.permissions, "admin", scope, "")
		require.NoError(t, err)
		require.Empty(t, page.Groups)
	}
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, "", 0, definition)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", access.Scope{TenantID: f.scope.TenantID}, "", 0, definition)
	require.ErrorIs(t, err, access.ErrDenied)
	organization := access.Scope{TenantID: f.scope.TenantID}
	og, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "admin", organization, "", 0, definition)
	require.NoError(t, err)
	_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", organization, inventory.DeviceSources{}, og.ID, inventory.DeviceGroupPosition{})
	require.ErrorIs(t, err, access.ErrDenied)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "viewer", 1, nil))
	_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestDeviceGroupsPaginationAndDefinitionBinding(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	var g *inventory.DeviceGroup
	for i := range 31 {
		var err error
		g, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, "", 0, inventory.DeviceGroupDefinition{Name: fmt.Sprintf("Group %02d", i), Rule: inventory.DeviceGroupRule{Platform: "linux"}})
		require.NoError(t, err)
		require.NoError(t, f.client.Agent.Create().SetID(fmt.Sprintf("group-member-%02d", i)).SetHostname("Owned dynamic member").SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	}
	page, err := inventory.ListDeviceGroups(ctx, f.db, f.permissions, "viewer", f.scope, "")
	require.NoError(t, err)
	require.Len(t, page.Groups, 25)
	require.NotEmpty(t, page.Next)
	second, err := inventory.ListDeviceGroups(ctx, f.db, f.permissions, "viewer", f.scope, page.Next)
	require.NoError(t, err)
	require.Len(t, second.Groups, 6)
	require.Empty(t, second.Next)
	seen := map[string]bool{}
	for _, item := range append(page.Groups, second.Groups...) {
		require.False(t, seen[item.ID])
		seen[item.ID] = true
	}
	preview, err := inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.NoError(t, err)
	require.Len(t, preview.Members.Entries, 25)
	require.NotEmpty(t, preview.Members.Next)
	next := inventory.DeviceGroupPosition{Revision: 1, After: preview.Members.Next}
	nextPage, err := inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, next)
	require.NoError(t, err)
	require.Len(t, nextPage.Members.Entries, 6)
	other := page.Groups[0]
	if other.ID == g.ID {
		other = page.Groups[1]
	}
	_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, other.ID, next)
	require.ErrorIs(t, err, inventory.ErrReportFilter)
	for i := 1; i < 31; i++ {
		g, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, g.ID, i, g.DeviceGroupDefinition)
		require.NoError(t, err)
	}
	_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, next)
	require.ErrorIs(t, err, inventory.ErrGroupConflict)
	preview, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.NoError(t, err)
	require.Len(t, preview.History, 25)
	require.Equal(t, 7, preview.HistoryBefore)
	preview, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{Revision: 31, HistoryBefore: 7})
	require.NoError(t, err)
	require.Len(t, preview.History, 6)
	require.Equal(t, 1, preview.History[5].Revision)
}

func TestDeviceGroupsAtomicAuditAndConcurrentRevision(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	definition := inventory.DeviceGroupDefinition{Name: "Concurrent group"}
	g, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, "", 0, definition)
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, g.ID, 1, definition)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, inventory.ErrGroupConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, conflict)
	_, err = f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_group_audit_failure CHECK(action NOT LIKE 'inventory.groups.%') NOT VALID`)
	require.NoError(t, err)
	saved, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, g.ID, 2, definition)
	require.Error(t, err)
	require.Nil(t, saved)
	saved, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, "", 0, definition)
	require.Error(t, err)
	require.Nil(t, saved)
	preview, err := inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.Error(t, err)
	require.Nil(t, preview)
	page, err := inventory.ListDeviceGroups(ctx, f.db, f.permissions, "viewer", f.scope, "")
	require.Error(t, err)
	require.Nil(t, page)
	var count int
	require.NoError(t, f.db.QueryRow(`SELECT count(*) FROM uem_device_groups`).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, f.db.QueryRow(`SELECT count(*) FROM uem_device_group_revisions`).Scan(&count))
	require.Equal(t, 2, count)
	_, err = f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_group_audit_failure`)
	require.NoError(t, err)
	lock, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer lock.Rollback()
	_, err = lock.Exec(`SELECT id FROM uem_device_groups WHERE id=$1 FOR UPDATE`, g.ID)
	require.NoError(t, err)
	deadline, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	saved, err = inventory.SaveDeviceGroup(deadline, f.db, f.permissions, "operator", f.scope, g.ID, 2, definition)
	require.Error(t, err)
	require.Nil(t, saved)
	require.NoError(t, lock.Rollback())
	preview, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.NoError(t, err)
	require.Equal(t, 2, preview.Group.Revision)
}

func TestDeviceGroupDefinitionValidation(t *testing.T) {
	for _, d := range []inventory.DeviceGroupDefinition{{}, {Name: "  "}, {Name: "bad\nname"}, {Name: strings.Repeat("é", 61)}, {Name: "ok", Description: strings.Repeat("x", 1025)}, {Name: "ok", Rule: inventory.DeviceGroupRule{Platform: "android"}}, {Name: "ok", Rule: inventory.DeviceGroupRule{Search: "bad\x00query"}}} {
		require.False(t, d.Valid())
	}
	require.True(t, (inventory.DeviceGroupDefinition{Name: "日本語 <script>", Rule: inventory.DeviceGroupRule{Search: "%_' OR true --"}}).Valid())
}

func TestDeviceGroupsCapacityAndMovedScope(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO uem_device_groups(id,tenant_id,site_id,revision) SELECT md5('owned-group-'||i::text)::uuid,$1,$2,1 FROM generate_series(1,999) i`, f.scope.TenantID, f.scope.SiteID)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO uem_device_group_revisions(group_id,revision,name,description,platform,search,archived,actor) SELECT id,1,'Owned capacity fixture','','','',false,'operator' FROM uem_device_groups`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	definition := inventory.DeviceGroupDefinition{Name: "Thousandth group"}
	g, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, "", 0, definition)
	require.NoError(t, err)
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, "", 0, definition)
	require.ErrorIs(t, err, inventory.ErrGroupLimit)
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, g.ID, 1, definition)
	require.NoError(t, err)
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, "", 0, definition)
	require.ErrorIs(t, err, inventory.ErrGroupLimit)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil))
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", f.scope, g.ID, 2, definition)
	require.ErrorIs(t, err, access.ErrDenied)
	other, err := f.client.Tenant.Create().SetDescription("Owned moved scope").Save(ctx)
	require.NoError(t, err)
	require.NoError(t, f.client.Site.UpdateOneID(f.scope.SiteID).SetTenantID(other.ID).Exec(ctx))
	_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "admin", f.scope, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "admin", f.scope, g.ID, 2, definition)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = inventory.InspectDeviceGroup(ctx, f.db, f.permissions, "admin", access.Scope{TenantID: other.ID, SiteID: f.scope.SiteID}, inventory.DeviceSources{}, g.ID, inventory.DeviceGroupPosition{})
	require.ErrorIs(t, err, inventory.ErrNotFound)
}
