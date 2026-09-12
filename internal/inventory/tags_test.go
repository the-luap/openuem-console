package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func tagFixture(t *testing.T) (*refreshFixture, access.Scope) {
	t.Helper()
	f := newSoftwareFixture(t)
	scope := access.Scope{TenantID: f.scope.TenantID}
	for actor, role := range map[string]access.Role{"tag-admin": access.TenantAdmin, "tag-viewer": access.Viewer, "tag-operator": access.Operator} {
		require.NoError(t, f.client.User.Create().SetID(actor).SetName(actor).SetEmail(actor+"@example.test").Exec(t.Context()))
		require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", actor, 0, []access.Grant{{Role: role, Scope: scope}}))
	}
	return f, scope
}
func tagDefinition(name string) inventory.TagDefinition {
	return inventory.TagDefinition{Name: name, Description: "Owned tag description", Color: "#aBc123"}
}

func TestOrganizationTagsAuthorizeScopeAndRetainLegacyWriters(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	created, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, 0, "", tagDefinition("Owned first"))
	require.NoError(t, err)
	for _, actor := range []string{"tag-viewer", "tag-operator", "viewer", "operator"} {
		_, err = inventory.SaveOrganizationTag(ctx, f.db, f.permissions, actor, scope, 0, "", tagDefinition(actor))
		require.ErrorIs(t, err, access.ErrDenied)
		err = inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, actor, scope, created.ID, created.Revision)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	for _, actor := range []string{"tag-viewer", "tag-operator", "tag-admin", "admin"} {
		got, err := inventory.ReadOrganizationTag(ctx, f.db, f.permissions, actor, scope, created.ID)
		require.NoError(t, err)
		require.Equal(t, created.Revision, got.Revision)
	}
	for _, actor := range []string{"viewer", "operator"} {
		_, err = inventory.ListOrganizationTags(ctx, f.db, f.permissions, actor, scope, inventory.ReportFilter{})
		require.ErrorIs(t, err, access.ErrDenied)
	}
	_, err = inventory.ListOrganizationTags(ctx, f.db, f.permissions, "admin", f.scope, inventory.ReportFilter{})
	require.ErrorIs(t, err, access.ErrDenied)
	other, err := f.client.Tenant.Create().SetDescription("Foreign organization").Save(ctx)
	require.NoError(t, err)
	foreign := access.Scope{TenantID: other.ID}
	_, err = inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", foreign, created.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "admin", foreign, created.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "admin", foreign, created.ID, created.Revision, tagDefinition("Moved"))
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "admin", foreign, 0, "", tagDefinition("Owned first"))
	require.ErrorIs(t, err, inventory.ErrTagName)
	// Both changes use the original Ent writer, which knows no revision metadata.
	require.NoError(t, f.client.Tag.UpdateOneID(int(created.ID)).SetDescription("Intermediate").Exec(ctx))
	require.NoError(t, f.client.Tag.UpdateOneID(int(created.ID)).SetDescription(created.Description).Exec(ctx))
	_, err = inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, created.ID, created.Revision, tagDefinition("Stale"))
	require.ErrorIs(t, err, inventory.ErrTagConflict)
	restored, err := inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, created.ID)
	require.NoError(t, err)
	require.NotEqual(t, created.Revision, restored.Revision)
	_, err = f.db.ExecContext(ctx, `UPDATE tags SET uem_revision=$1 WHERE id=$2`, created.Revision, created.ID)
	require.Error(t, err)
	unchanged, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, created.ID, restored.Revision, restored.TagDefinition)
	require.NoError(t, err)
	require.Equal(t, restored.Revision, unchanged.Revision)
	require.NoError(t, inventory.Migrate(ctx, f.db))
	after, err := inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, created.ID)
	require.NoError(t, err)
	require.Equal(t, restored.Revision, after.Revision)
	require.NoError(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, created.ID, after.Revision))
	_, err = f.db.ExecContext(ctx, `INSERT INTO tags(id,tag,description,color,tenant_tags,uem_revision) VALUES($1,$2,$3,$4,$5,$6)`, created.ID, created.Name, created.Description, created.Color, scope.TenantID, after.Revision)
	require.NoError(t, err)
	err = inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, created.ID, after.Revision)
	require.ErrorIs(t, err, inventory.ErrTagConflict)
}

func TestOrganizationTagsBoundSearchAndAuditRollback(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	for i := 0; i < 28; i++ {
		_, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, 0, "", tagDefinition(fmt.Sprintf("Owned tag %02d", i)))
		require.NoError(t, err)
	}
	literal, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, 0, "", tagDefinition("Literal %_ <tag>"))
	require.NoError(t, err)
	first, err := inventory.ListOrganizationTags(ctx, f.db, f.permissions, "tag-viewer", scope, inventory.ReportFilter{})
	require.NoError(t, err)
	require.Len(t, first.Tags, 25)
	require.Positive(t, first.Next)
	last, err := inventory.ListOrganizationTags(ctx, f.db, f.permissions, "tag-viewer", scope, inventory.ReportFilter{After: first.Next})
	require.NoError(t, err)
	require.Len(t, last.Tags, 4)
	require.Zero(t, last.Next)
	require.Greater(t, last.Tags[0].ID, first.Next)
	match, err := inventory.ListOrganizationTags(ctx, f.db, f.permissions, "tag-viewer", scope, inventory.ReportFilter{Search: "%_"})
	require.NoError(t, err)
	require.Len(t, match.Tags, 1)
	require.Equal(t, literal.ID, match.Tags[0].ID)
	match, err = inventory.ListOrganizationTags(ctx, f.db, f.permissions, "tag-viewer", scope, inventory.ReportFilter{Search: "' OR true --"})
	require.NoError(t, err)
	require.Empty(t, match.Tags)
	for _, filter := range []inventory.ReportFilter{{After: -1}, {Search: strings.Repeat("x", 257)}, {Search: "line\nbreak"}} {
		_, err = inventory.ListOrganizationTags(ctx, f.db, f.permissions, "tag-admin", scope, filter)
		require.ErrorIs(t, err, inventory.ErrTagInvalid)
	}
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_tag_audit_failure CHECK(action NOT LIKE 'inventory.tags.%') NOT VALID`)
	require.NoError(t, err)
	page, err := inventory.ListOrganizationTags(ctx, f.db, f.permissions, "tag-admin", scope, inventory.ReportFilter{})
	require.Error(t, err)
	require.Nil(t, page)
	changed, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, literal.ID, literal.Revision, tagDefinition("Must roll back"))
	require.Error(t, err)
	require.Nil(t, changed)
	err = inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, literal.ID, literal.Revision)
	require.Error(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_tag_audit_failure`)
	require.NoError(t, err)
	current, err := inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, literal.ID)
	require.NoError(t, err)
	require.Equal(t, literal.Revision, current.Revision)
	require.Equal(t, literal.Name, current.Name)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE actor='tag-admin' AND tenant_id=$1 AND site_id=0 AND action='inventory.tags.create'`, scope.TenantID).Scan(&count))
	require.Equal(t, 29, count)
}

func TestOrganizationTagsRequireUnusedCurrentRevisionAndLiveGrants(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	tag, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, 0, "", tagDefinition("Assigned"))
	require.NoError(t, err)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddTagIDs(int(tag.ID)).Exec(ctx))
	used, err := inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-viewer", scope, tag.ID)
	require.NoError(t, err)
	require.True(t, used.Used)
	require.ErrorIs(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision), inventory.ErrTagUsed)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).RemoveTagIDs(int(tag.ID)).Exec(ctx))
	tx, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `UPDATE tags SET description='Uncommitted' WHERE id=$1`, tag.ID)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = inventory.SaveOrganizationTag(bounded, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision, tagDefinition("Waiting"))
	cancel()
	require.Error(t, err)
	require.NoError(t, tx.Rollback())
	current, err := inventory.ReadOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID)
	require.NoError(t, err)
	require.Equal(t, tag.Revision, current.Revision)
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}))
	require.ErrorIs(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision), access.ErrDenied)
	_, err = inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, tag.ID, tag.Revision, tagDefinition("Revoked"))
	require.ErrorIs(t, err, access.ErrDenied)
	require.NoError(t, inventory.DeleteOrganizationTag(ctx, f.db, f.permissions, "admin", scope, tag.ID, tag.Revision))
}

func TestOrganizationTagValidationAndMigrationGuard(t *testing.T) {
	for _, d := range []inventory.TagDefinition{{Name: "", Color: "#ffffff"}, {Name: "Name", Color: "red"}, {Name: "Name", Color: "#fff\"xx"}, {Name: "Name", Color: "#000000", Description: "line\nbreak"}, {Name: strings.Repeat("x", 256), Color: "#000000"}} {
		require.False(t, d.Valid())
	}
	require.True(t, tagDefinition("Unicode label <tag>").Valid())
	f, scope := tagFixture(t)
	ctx := t.Context()
	_, err := inventory.SaveOrganizationTag(ctx, f.db, f.permissions, "tag-admin", scope, 0, uuid.NewString(), tagDefinition("Bad initial revision"))
	require.ErrorIs(t, err, inventory.ErrTagInvalid)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE tags DISABLE TRIGGER uem_tag_revision`)
	require.NoError(t, err)
	failure := inventory.Migrate(ctx, f.db)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE tags ENABLE TRIGGER uem_tag_revision`)
	require.NoError(t, err)
	require.Error(t, failure)
	require.NoError(t, inventory.Migrate(ctx, f.db))
}
