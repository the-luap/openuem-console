package inventory_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestProfileTagAssignmentRejectsForeignOrganization(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	foreign, err := f.client.Tenant.Create().SetDescription("Other profile organization").Save(ctx)
	require.NoError(t, err)
	profile, err := f.client.Profile.Create().SetName("Other organization profile").AddTenantIDs(foreign.ID).Save(ctx)
	require.NoError(t, err)
	tag, err := f.client.Tag.Create().SetTag("Current organization tag").SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
	require.NoError(t, err)
	for _, requested := range []access.Scope{scope, {TenantID: foreign.ID}} {
		err = inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", requested, int64(profile.ID), int64(tag.ID), true)
		require.ErrorIs(t, err, inventory.ErrNotFound)
	}
}

func ownedTagProfile(t *testing.T, f *refreshFixture, scope access.Scope, name string) *ent.Profile {
	t.Helper()
	q := f.client.Profile.Create().SetName(name).SetApplyToAll(true)
	if scope.TenantID != 0 {
		q.AddTenantIDs(scope.TenantID)
	}
	if scope.SiteID != 0 {
		q.AddSiteIDs(scope.SiteID)
	}
	p, err := q.Save(t.Context())
	require.NoError(t, err)
	return p
}

func TestProfileTagsKeepGlobalOrganizationAndSiteAudiences(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	tag, err := f.client.Tag.Create().SetTag("Current profile tag").SetColor("blue").SetTenantID(organization.TenantID).Save(ctx)
	require.NoError(t, err)
	other, err := f.client.Tenant.Create().SetDescription("Second profile organization").Save(ctx)
	require.NoError(t, err)
	foreign, err := f.client.Tag.Create().SetTag("Second profile tag").SetColor("red").SetTenantID(other.ID).Save(ctx)
	require.NoError(t, err)
	scopes := []access.Scope{{}, organization, f.scope}
	for i, scope := range scopes {
		profile := ownedTagProfile(t, f, scope, fmt.Sprintf("Profile audience %d", i))
		change := func(actor string, requested access.Scope, tagID int, assigned bool) error {
			return inventory.ChangeProfileTag(ctx, f.db, f.permissions, actor, requested, int64(profile.ID), int64(tagID), assigned)
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			require.ErrorIs(t, change(actor, scope, tag.ID, true), access.ErrDenied)
		}
		for _, requested := range scopes {
			if requested != scope {
				require.ErrorIs(t, change("admin", requested, tag.ID, true), inventory.ErrNotFound)
			}
		}
		require.NoError(t, change("admin", scope, tag.ID, true))
		require.NoError(t, change("admin", scope, tag.ID, true))
		current, err := f.client.Profile.Get(ctx, profile.ID)
		require.NoError(t, err)
		require.False(t, current.ApplyToAll)
		require.Equal(t, profile.Name, current.Name)
		if scope.TenantID == 0 {
			require.NoError(t, change("admin", scope, foreign.ID, true))
		} else {
			require.ErrorIs(t, change("admin", scope, foreign.ID, true), inventory.ErrNotFound)
			require.ErrorIs(t, change("admin", scope, foreign.ID, false), inventory.ErrNotFound)
			// Repair a legacy foreign association without changing other tags.
			require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).AddTagIDs(foreign.ID).Exec(ctx))
		}
		require.NoError(t, change("admin", scope, foreign.ID, false))
		var count int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM profile_tags WHERE profile_id=$1`, profile.ID).Scan(&count))
		require.Equal(t, 1, count)
		// Removing a tag must not implicitly turn off an existing apply-to-all setting.
		require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).SetApplyToAll(true).Exec(ctx))
		require.NoError(t, change("admin", scope, tag.ID, false))
		current, err = f.client.Profile.Get(ctx, profile.ID)
		require.NoError(t, err)
		require.True(t, current.ApplyToAll)
	}
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	filter := audit.Filter{Scope: organization, Source: "inventory", Action: "inventory.profile_tags.assign", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
	page, err := audits.List(ctx, "tag-admin", filter, "")
	require.NoError(t, err)
	require.Len(t, page.Events, 4)
	for _, event := range page.Events {
		require.Equal(t, organization.TenantID, event.TenantID)
	}
	filter.Scope = access.Scope{}
	page, err = audits.List(ctx, "admin", filter, "")
	require.NoError(t, err)
	require.Len(t, page.Events, 7)
	_, err = audits.List(ctx, "tag-admin", filter, "")
	require.ErrorIs(t, err, access.ErrDenied)
	exported, err := audits.ExportJSON(ctx, "admin", filter)
	require.NoError(t, err)
	require.Contains(t, string(exported), `"tenant_id":0`)
}

func TestProfileTagsRejectAmbiguousAndCrossedAudienceEdges(t *testing.T) {
	for _, state := range []string{"multiple organizations", "multiple sites", "site without organization", "site in another organization"} {
		t.Run(state, func(t *testing.T) {
			f, organization := tagFixture(t)
			ctx := t.Context()
			profile := ownedTagProfile(t, f, f.scope, state)
			tag, err := f.client.Tag.Create().SetTag("Audience tag").SetColor("blue").SetTenantID(organization.TenantID).Save(ctx)
			require.NoError(t, err)
			other, err := f.client.Tenant.Create().SetDescription("Hidden profile organization").Save(ctx)
			require.NoError(t, err)
			switch state {
			case "multiple organizations":
				err = f.client.Profile.UpdateOneID(profile.ID).AddTenantIDs(other.ID).Exec(ctx)
			case "multiple sites":
				err = f.client.Profile.UpdateOneID(profile.ID).AddSiteIDs(f.otherSite).Exec(ctx)
			case "site without organization":
				err = f.client.Profile.UpdateOneID(profile.ID).ClearTenant().Exec(ctx)
			case "site in another organization":
				err = f.client.Site.UpdateOneID(f.scope.SiteID).SetTenantID(other.ID).Exec(ctx)
			}
			require.NoError(t, err)
			for _, requested := range []access.Scope{{}, organization, f.scope} {
				require.ErrorIs(t, inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", requested, int64(profile.ID), int64(tag.ID), true), inventory.ErrNotFound)
			}
		})
	}
}

func TestProfileTagAuditFailureAndCancellationRollBackAssignmentMode(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	profile := ownedTagProfile(t, f, scope, "Atomic tag mode")
	tag, err := f.client.Tag.Create().SetTag("Atomic profile tag").SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_profile_tag_audit_failure CHECK(action NOT LIKE 'inventory.profile_tags.%') NOT VALID`)
	require.NoError(t, err)
	change := func(ctx context.Context, assigned bool) error {
		return inventory.ChangeProfileTag(ctx, f.db, f.permissions, "admin", scope, int64(profile.ID), int64(tag.ID), assigned)
	}
	require.Error(t, change(ctx, true))
	current, err := f.client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.True(t, current.ApplyToAll)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM profile_tags WHERE profile_id=$1`, profile.ID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).AddTagIDs(tag.ID).Exec(ctx))
	require.Error(t, change(ctx, false))
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM profile_tags WHERE profile_id=$1`, profile.ID).Scan(&count))
	require.Equal(t, 1, count)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_profile_tag_audit_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, change(canceled, true))
	current, err = f.client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.True(t, current.ApplyToAll)
}
