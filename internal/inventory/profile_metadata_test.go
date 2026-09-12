package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileMetadataRequiresExactAudienceAndPreservesOtherFields(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	tag, err := f.client.Tag.Create().SetTag("Retained profile metadata tag").SetColor("red").SetTenantID(organization.TenantID).Save(ctx)
	require.NoError(t, err)
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		profile := ownedTagProfile(t, f, scope, "Original metadata")
		require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).SetDisabled(true).Exec(ctx))
		task, err := f.client.Task.Create().SetName("Retained metadata task").SetType("powershell_script").SetProfileID(profile.ID).Save(ctx)
		require.NoError(t, err)
		save := func(actor string, requested access.Scope, d inventory.ProfileMetadata) error {
			return inventory.SaveProfileMetadata(ctx, f.db, f.permissions, actor, requested, int64(profile.ID), d)
		}
		definition := inventory.ProfileMetadata{Name: "Changed metadata", Assignment: "useTags"}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			require.ErrorIs(t, save(actor, scope, definition), access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, organization, f.scope} {
			if wrong != scope {
				require.ErrorIs(t, save("admin", wrong, definition), inventory.ErrNotFound)
			}
		}
		for _, mode := range []string{"useTags", "applyToAll", "dontApplyToAll"} {
			require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).AddTagIDs(tag.ID).SetApplyToAll(true).Exec(ctx))
			definition := inventory.ProfileMetadata{Name: "Owned <metadata>\n第二行", Assignment: mode}
			for range 2 {
				require.NoError(t, save("admin", scope, definition))
			}
			current, err := f.client.Profile.Query().Where(entprofile.ID(profile.ID)).WithSite().WithTenant().WithTags().WithTasks().Only(ctx)
			require.NoError(t, err)
			require.Equal(t, definition.Name, current.Name)
			require.Equal(t, mode == "applyToAll", current.ApplyToAll)
			require.True(t, current.Disabled)
			require.Equal(t, profile.Type, current.Type)
			require.Len(t, current.Edges.Tasks, 1)
			require.Equal(t, task.ID, current.Edges.Tasks[0].ID)
			if mode == "useTags" {
				require.Len(t, current.Edges.Tags, 1)
				require.Equal(t, tag.ID, current.Edges.Tags[0].ID)
			} else {
				require.Empty(t, current.Edges.Tags)
			}
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
			var events int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND action='inventory.profiles.update' AND resource_id=$3`, scope.TenantID, scope.SiteID, fmt.Sprintf("%d/assignment/%s", profile.ID, mode)).Scan(&events))
			require.Equal(t, 2, events)
		}
		require.NoError(t, save("admin", scope, inventory.ProfileMetadata{Name: strings.Repeat("x", 2048), Assignment: "useTags"}))
	}
}

func TestProfileMetadataValidationDoesNotChangeAssignments(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	profile := ownedTagProfile(t, f, f.scope, "Validation target")
	for _, d := range []inventory.ProfileMetadata{{Name: "", Assignment: "applyToAll"}, {Name: " \t\n", Assignment: "applyToAll"}, {Name: strings.Repeat("x", 2049), Assignment: "applyToAll"}, {Name: "Invalid\x00name", Assignment: "applyToAll"}, {Name: "Invalid\xffname", Assignment: "applyToAll"}, {Name: "Unknown mode", Assignment: "all"}, {Name: "Missing mode"}, {Name: "Control\x1b", Assignment: "useTags"}} {
		require.ErrorIs(t, inventory.SaveProfileMetadata(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), d), inventory.ErrProfileInvalid)
	}
	current, err := f.client.Profile.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.Equal(t, profile.Name, current.Name)
	require.True(t, current.ApplyToAll)
}

func TestProfileMetadataAuditFailureRestoresNameModeAndTags(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	profile := ownedTagProfile(t, f, f.scope, "Atomic metadata")
	tag, err := f.client.Tag.Create().SetTag("Atomic metadata tag").SetColor("blue").SetTenantID(organization.TenantID).Save(ctx)
	require.NoError(t, err)
	require.NoError(t, f.client.Profile.UpdateOneID(profile.ID).AddTagIDs(tag.ID).Exec(ctx))
	save := func(ctx context.Context) error {
		return inventory.SaveProfileMetadata(ctx, f.db, f.permissions, "admin", f.scope, int64(profile.ID), inventory.ProfileMetadata{Name: "Changed metadata", Assignment: "dontApplyToAll"})
	}
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_profile_metadata_failure CHECK(action!='inventory.profiles.update') NOT VALID`)
	require.NoError(t, err)
	require.Error(t, save(ctx))
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_profile_metadata_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, save(canceled))
	current, err := f.client.Profile.Query().Where(entprofile.ID(profile.ID)).WithTags().Only(ctx)
	require.NoError(t, err)
	require.Equal(t, profile.Name, current.Name)
	require.True(t, current.ApplyToAll)
	require.Len(t, current.Edges.Tags, 1)
	require.Equal(t, tag.ID, current.Edges.Tags[0].ID)
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO site_profiles(site_id,profile_id) VALUES($1,$2)`, f.otherSite, profile.ID)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	require.Error(t, save(bounded))
	cancel()
	require.NoError(t, tx.Commit())
	require.ErrorIs(t, save(ctx), inventory.ErrNotFound)
}
