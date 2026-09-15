package inventory_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestProfileAudienceMovesPreserveDefinitionAndAuditBothScopes(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	for _, tc := range []struct {
		source access.Scope
		global bool
	}{{organization, true}, {f.scope, true}, {f.scope, false}} {
		profile := ownedTagProfile(t, f, tc.source, "Retained profile definition")
		tag, err := f.client.Tag.Create().SetTag(fmt.Sprintf("Audience tag %d", profile.ID)).SetColor("red").SetTenantID(organization.TenantID).Save(ctx)
		require.NoError(t, err)
		require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).SetDisabled(true).AddTagIDs(tag.ID).Exec(ctx))
		task, err := f.client.Task.Create().SetName("Retained audience task").SetType("powershell_script").SetProfileID(profile.ID).Save(ctx)
		require.NoError(t, err)
		move := func(actor string, source access.Scope) error {
			return inventory.PromoteProfileAudience(ctx, f.db, f.permissions, actor, source, int64(profile.ID), tc.global)
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			require.ErrorIs(t, move(actor, tc.source), access.ErrDenied)
		}
		wrong := access.Scope{TenantID: organization.TenantID, SiteID: f.otherSite}
		require.ErrorIs(t, move("admin", wrong), inventory.ErrNotFound)
		require.NoError(t, move("admin", tc.source))
		// A retry at the old URL must not move the now differently scoped object.
		require.ErrorIs(t, move("admin", tc.source), inventory.ErrNotFound)
		current, err := f.client.Profile.Query().Where(entprofile.ID(profile.ID)).WithTenant().WithSite().WithTasks().WithTags().Only(ctx)
		require.NoError(t, err)
		require.Empty(t, current.Edges.Site)
		if tc.global {
			require.Empty(t, current.Edges.Tenant)
		} else {
			require.Len(t, current.Edges.Tenant, 1)
			require.Equal(t, organization.TenantID, current.Edges.Tenant[0].ID)
		}
		require.Equal(t, profile.Name, current.Name)
		require.Equal(t, profile.Type, current.Type)
		require.True(t, current.Disabled)
		require.True(t, current.ApplyToAll)
		require.Len(t, current.Edges.Tasks, 1)
		require.Equal(t, task.ID, current.Edges.Tasks[0].ID)
		require.Len(t, current.Edges.Tags, 1)
		require.Equal(t, tag.ID, current.Edges.Tags[0].ID)
		destination, action := organization, "inventory.profiles.move_organization"
		if tc.global {
			destination = access.Scope{}
			action = "inventory.profiles.move_global"
		}
		resource := fmt.Sprintf("%d/from/%d/%d/to/%d/%d", profile.ID, tc.source.TenantID, tc.source.SiteID, destination.TenantID, destination.SiteID)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		filter := audit.Filter{Scope: organization, Source: "inventory", Action: action, Resource: resource, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
		page, err := audits.List(ctx, "tag-admin", filter, "")
		require.NoError(t, err)
		if tc.global {
			require.Len(t, page.Events, 1)
		} else {
			require.Len(t, page.Events, 2)
		}
		for _, event := range page.Events {
			require.Equal(t, organization.TenantID, event.TenantID)
		}
		filter.Scope = access.Scope{}
		page, err = audits.List(ctx, "admin", filter, "")
		require.NoError(t, err)
		require.Len(t, page.Events, 2)
		exported, err := audits.ExportJSON(ctx, "admin", filter)
		require.NoError(t, err)
		require.Contains(t, string(exported), resource)
		_, err = audits.List(ctx, "tag-admin", filter, "")
		require.ErrorIs(t, err, access.ErrDenied)
	}
}

func TestProfileAudienceRejectsInvalidAmbiguousAndChangedSource(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	for _, tc := range []struct {
		source access.Scope
		global bool
	}{{access.Scope{}, true}, {access.Scope{SiteID: f.scope.SiteID}, true}, {organization, false}, {access.Scope{TenantID: organization.TenantID, SiteID: -1}, true}} {
		require.ErrorIs(t, inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "admin", tc.source, 1, tc.global), inventory.ErrProfileInvalid)
	}
	require.ErrorIs(t, inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "admin", f.scope, 0, true), inventory.ErrProfileInvalid)
	for _, edge := range []string{"site", "organization"} {
		profile := ownedTagProfile(t, f, f.scope, "Ambiguous "+edge)
		if edge == "site" {
			require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).AddSiteIDs(f.otherSite).Exec(ctx))
		} else {
			other, err := f.client.Tenant.Create().SetDescription("Other audience tenant").Save(ctx)
			require.NoError(t, err)
			require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).AddTenantIDs(other.ID).Exec(ctx))
		}
		require.ErrorIs(t, inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), true), inventory.ErrNotFound)
	}
	profile := ownedTagProfile(t, f, f.scope, "Pending audience change")
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, profile.ID)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	require.Error(t, inventory.PromoteProfileAudience(bounded, f.db, f.permissions, "admin", f.scope, int64(profile.ID), true))
	cancel()
	require.NoError(t, tx.Commit())
	require.ErrorIs(t, inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), true), inventory.ErrNotFound)
}

func TestProfileAudienceFailedDestinationAuditRollsBackEntireMove(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	profile := ownedTagProfile(t, f, f.scope, "Atomic profile move")
	_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_profile_destination_failure CHECK(action!='inventory.profiles.move_global' OR tenant_id!=0) NOT VALID`)
	require.NoError(t, err)
	move := func(ctx context.Context) error {
		return inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), true)
	}
	require.Error(t, move(ctx))
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_profile_destination_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, move(canceled))
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.profiles.move_global'`).Scan(&count))
	require.Zero(t, count)
	current, err := f.client.Profile.Query().Where(entprofile.ID(profile.ID)).WithSite().WithTenant().Only(ctx)
	require.NoError(t, err)
	require.Len(t, current.Edges.Site, 1)
	require.Equal(t, f.scope.SiteID, current.Edges.Site[0].ID)
	require.Len(t, current.Edges.Tenant, 1)
	require.Equal(t, f.scope.TenantID, current.Edges.Tenant[0].ID)
	require.NoError(t, move(ctx))
}

func TestProfileAudienceConcurrentMovesDoNotUpgradeSharedLocks(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	var ids []int64
	for i := 0; i < 6; i++ {
		ids = append(ids, int64(ownedTagProfile(t, f, f.scope, fmt.Sprintf("Concurrent move %d", i)).ID))
	}
	var wg sync.WaitGroup
	results := make(chan error, len(ids))
	for _, id := range ids {
		wg.Go(func() {
			results <- inventory.PromoteProfileAudience(ctx, f.db, f.permissions, "admin", f.scope, id, true)
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
}
