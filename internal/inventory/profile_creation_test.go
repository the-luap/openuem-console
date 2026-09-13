package inventory_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestProfileCreationStartsUnassignedInTheExactScope(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			id, err := inventory.CreateLegacyProfile(ctx, f.db, f.permissions, actor, scope, "Denied creation")
			require.Zero(t, id)
			require.ErrorIs(t, err, access.ErrDenied)
		}
		name := "Owned <creation>\n第二行"
		id, err := inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "admin", scope, name)
		require.NoError(t, err)
		require.Positive(t, id)
		current, err := f.client.Profile.Query().Where(entprofile.ID(int(id))).WithTasks().WithTags().WithTenant().WithSite().Only(ctx)
		require.NoError(t, err)
		require.Equal(t, name, current.Name)
		require.False(t, current.Disabled)
		require.False(t, current.ApplyToAll)
		require.Equal(t, entprofile.TypeWinget, current.Type)
		require.Empty(t, current.Edges.Tasks)
		require.Empty(t, current.Edges.Tags)
		if scope.TenantID == 0 {
			require.Empty(t, current.Edges.Tenant)
		} else {
			require.Len(t, current.Edges.Tenant, 1)
			require.Equal(t, scope.TenantID, current.Edges.Tenant[0].ID)
		}
		if scope.SiteID == 0 {
			require.Empty(t, current.Edges.Site)
		} else {
			require.Len(t, current.Edges.Site, 1)
			require.Equal(t, scope.SiteID, current.Edges.Site[0].ID)
		}
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		filter := audit.Filter{Scope: scope, Source: "inventory", Action: "inventory.profiles.create", Resource: strconv.FormatInt(id, 10), From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
		page, err := audits.List(ctx, "admin", filter, "")
		require.NoError(t, err)
		require.Len(t, page.Events, 1)
		require.Equal(t, scope.TenantID, page.Events[0].TenantID)
		require.Equal(t, scope.SiteID, page.Events[0].SiteID)
		exported, err := audits.ExportJSON(ctx, "admin", filter)
		require.NoError(t, err)
		require.Contains(t, string(exported), filter.Resource)
	}
	count, err := f.client.Profile.Query().Where(entprofile.NameEQ("Denied creation")).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count)
}

func TestProfileCreationRejectsInvalidNamesAndCrossedSiteParents(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	for _, name := range []string{"", " \t\n", strings.Repeat("x", 2049), "bad\x00name", "bad\xffname"} {
		id, err := inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "admin", organization, name)
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrProfileInvalid)
	}
	id, err := inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "admin", organization, strings.Repeat("x", 2048))
	require.NoError(t, err)
	require.Positive(t, id)
	other, err := f.client.Tenant.Create().SetDescription("Other creation organization").Save(ctx)
	require.NoError(t, err)
	site, err := f.client.Site.Create().SetDescription("Other creation site").SetTenantID(other.ID).Save(ctx)
	require.NoError(t, err)
	id, err = inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "admin", access.Scope{TenantID: organization.TenantID, SiteID: site.ID}, "Crossed audience")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	for _, scope := range []access.Scope{{SiteID: f.scope.SiteID}, {TenantID: -1}, {TenantID: organization.TenantID, SiteID: -1}} {
		id, err := inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "admin", scope, "Invalid source")
		require.Zero(t, id)
		require.ErrorIs(t, err, access.ErrDenied)
	}
}

func TestProfileCreationRollsBackProfileAudienceAndAudit(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	name := "Atomic profile creation"
	create := func(ctx context.Context) (int64, error) {
		return inventory.CreateLegacyProfile(ctx, f.db, f.permissions, "admin", f.scope, name)
	}
	unchanged := func() {
		count, err := f.client.Profile.Query().Where(entprofile.NameEQ(name)).Count(ctx)
		require.NoError(t, err)
		require.Zero(t, count)
		var events int
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.profiles.create'").Scan(&events))
		require.Zero(t, events)
	}
	_, err := f.db.ExecContext(ctx, "CREATE FUNCTION reject_owned_profile_creation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned site association failure'; END $$; CREATE TRIGGER reject_owned_profile_creation BEFORE INSERT ON site_profiles FOR EACH ROW EXECUTE FUNCTION reject_owned_profile_creation()")
	require.NoError(t, err)
	id, err := create(ctx)
	require.Zero(t, id)
	require.Error(t, err)
	unchanged()
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_profile_creation ON site_profiles; DROP FUNCTION reject_owned_profile_creation()")
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_profile_creation_audit_failure CHECK(action!='inventory.profiles.create') NOT VALID")
	require.NoError(t, err)
	id, err = create(ctx)
	require.Zero(t, id)
	require.Error(t, err)
	unchanged()
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_profile_creation_audit_failure")
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	id, err = create(canceled)
	require.Zero(t, id)
	require.Error(t, err)
	unchanged()
	id, err = create(ctx)
	require.NoError(t, err)
	require.Positive(t, id)
	var edges int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM tenant_profiles WHERE profile_id=$1)+(SELECT count(*) FROM site_profiles WHERE profile_id=$1)", id).Scan(&edges))
	require.Equal(t, 2, edges)
	_, err = f.client.Profile.Get(ctx, int(id))
	require.NoError(t, err, fmt.Sprint(id))
}
