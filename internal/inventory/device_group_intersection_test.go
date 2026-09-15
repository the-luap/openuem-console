package inventory_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestOrganizationGroupIntersectionKeepsSourceAuthorityAndExactTargetSite(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	organization := access.Scope{TenantID: f.scope.TenantID}
	group, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "admin", organization, "", 0, inventory.DeviceGroupDefinition{Name: "Owned organization source", Rule: inventory.DeviceGroupRule{Platform: "windows"}})
	require.NoError(t, err)
	read := func(actor string, source, target access.Scope, id string, revision int) (*inventory.DeviceGroupSnapshot, error) {
		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		r, err := inventory.DeviceGroupIntersectionTransaction(ctx, tx, f.permissions, actor, source, target, inventory.DeviceSources{}, id, revision)
		if err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return r, nil
	}
	r, err := read("admin", organization, f.scope, group.ID, 1)
	require.NoError(t, err)
	require.Equal(t, organization, r.Group.Scope)
	require.Len(t, r.Entries, 1)
	require.Equal(t, f.id, r.Entries[0].ID)
	var resource string
	require.NoError(t, f.db.QueryRow(`SELECT resource_id FROM uem_inventory_audit WHERE action='inventory.groups.read' ORDER BY id DESC LIMIT 1`).Scan(&resource))
	require.Equal(t, group.ID+"@1/site:"+strconv.Itoa(f.scope.SiteID), resource)
	for _, actor := range []string{"viewer", "operator"} {
		r, err = read(actor, organization, f.scope, group.ID, 1)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, r)
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "viewer", 1, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	r, err = read("viewer", organization, f.scope, group.ID, 1)
	require.NoError(t, err)
	require.Len(t, r.Entries, 1)
	// Source kind is explicit: an organization ID cannot masquerade as a site group.
	r, err = read("admin", f.scope, f.scope, group.ID, 1)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.Nil(t, r)
	r, err = read("admin", organization, organization, group.ID, 1)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, r)
	r, err = read("admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.scope, group.ID, 1)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, r)
	other, err := f.client.Tenant.Create().SetDescription("Foreign organization").Save(ctx)
	require.NoError(t, err)
	r, err = read("admin", organization, access.Scope{TenantID: other.ID, SiteID: f.scope.SiteID}, group.ID, 1)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, r)
	r, err = read("admin", organization, f.scope, group.ID, 2)
	require.ErrorIs(t, err, inventory.ErrGroupConflict)
	require.Nil(t, r)
	// Ambiguous agent placement is excluded even for a server administrator.
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx))
	r, err = read("admin", organization, f.scope, group.ID, 1)
	require.NoError(t, err)
	require.Empty(t, r.Entries)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.scope.SiteID).Exec(ctx))
	require.NoError(t, f.client.Site.UpdateOneID(f.scope.SiteID).SetTenantID(other.ID).Exec(ctx))
	r, err = read("admin", organization, f.scope, group.ID, 1)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.Nil(t, r)
}

func TestOrganizationGroupIntersectionBoundsOnlyTheSelectedSite(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	organization := access.Scope{TenantID: f.scope.TenantID}
	group, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "admin", organization, "", 0, inventory.DeviceGroupDefinition{Name: "Owned broad group", Rule: inventory.DeviceGroupRule{Platform: "windows"}})
	require.NoError(t, err)
	// The organization has more than 100 matching devices outside the target site.
	for i := 0; i < 105; i++ {
		require.NoError(t, f.client.Agent.Create().SetID(fmt.Sprintf("outside-intersection-%03d", i)).SetHostname("Other site private name").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(ctx))
	}
	read := func() (*inventory.DeviceGroupSnapshot, error) {
		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		r, err := inventory.DeviceGroupIntersectionTransaction(ctx, tx, f.permissions, "admin", organization, f.scope, inventory.DeviceSources{}, group.ID, 1)
		if err != nil {
			return nil, err
		}
		return r, tx.Commit()
	}
	r, err := read()
	require.NoError(t, err)
	require.Len(t, r.Entries, 1)
	require.Equal(t, f.id, r.Entries[0].ID)
	for i := 0; i < 99; i++ {
		require.NoError(t, f.client.Agent.Create().SetID(fmt.Sprintf("inside-intersection-%03d", i)).SetHostname("Target site member").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	}
	r, err = read()
	require.NoError(t, err)
	require.Len(t, r.Entries, 100)
	for _, d := range r.Entries {
		require.Equal(t, f.scope.SiteID, d.SiteID)
		require.NotEqual(t, "Other site private name", d.Name)
	}
	require.NoError(t, f.client.Agent.Create().SetID("inside-intersection-overflow").SetHostname("Excess target site member").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	r, err = read()
	require.ErrorIs(t, err, inventory.ErrGroupSnapshotLarge)
	require.Nil(t, r)
}

func TestOrganizationGroupIntersectionLocksSourceTargetAndPermissionThroughCallerCommit(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	organization := access.Scope{TenantID: f.scope.TenantID}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: organization}}))
	definition := inventory.DeviceGroupDefinition{Name: "Locked organization group", Rule: inventory.DeviceGroupRule{Platform: "windows"}}
	group, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", organization, "", 0, definition)
	require.NoError(t, err)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	r, err := inventory.DeviceGroupIntersectionTransaction(ctx, tx, f.permissions, "operator", organization, f.scope, inventory.DeviceSources{}, group.ID, 1)
	require.NoError(t, err)
	require.Len(t, r.Entries, 1)
	for _, mutation := range []string{"group", "site", "grant"} {
		t.Run(mutation, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			switch mutation {
			case "group":
				definition.Archived = true
				_, err = inventory.SaveDeviceGroup(bounded, f.db, f.permissions, "operator", organization, group.ID, 1, definition)
			case "site":
				_, err = f.db.ExecContext(bounded, `UPDATE sites SET description='Blocked site change' WHERE id=$1`, f.scope.SiteID)
			case "grant":
				err = f.permissions.ReplaceGrants(bounded, "admin", "operator", 2, nil)
			}
			require.Error(t, err)
		})
	}
	require.NoError(t, tx.Commit())
	_, err = inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "operator", organization, group.ID, 1, definition)
	require.NoError(t, err)
	tx, err = f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	r, err = inventory.DeviceGroupIntersectionTransaction(ctx, tx, f.permissions, "operator", organization, f.scope, inventory.DeviceSources{}, group.ID, 2)
	require.ErrorIs(t, err, inventory.ErrGroupConflict)
	require.Nil(t, r)
	require.NoError(t, tx.Rollback())
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 2, nil))
}

func TestOrganizationGroupIntersectionWithholdsResultsOnAuditFailure(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	organization := access.Scope{TenantID: f.scope.TenantID}
	group, err := inventory.SaveDeviceGroup(ctx, f.db, f.permissions, "admin", organization, "", 0, inventory.DeviceGroupDefinition{Name: "Audited organization group", Rule: inventory.DeviceGroupRule{Platform: "windows"}})
	require.NoError(t, err)
	_, err = f.db.Exec(`CREATE FUNCTION reject_organization_group_read() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.groups.read' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_organization_group_read BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_organization_group_read()`)
	require.NoError(t, err)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	r, err := inventory.DeviceGroupIntersectionTransaction(ctx, tx, f.permissions, "admin", organization, f.scope, inventory.DeviceSources{}, group.ID, 1)
	require.Error(t, err)
	require.Nil(t, r)
}
