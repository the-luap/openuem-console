package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestProfileEditorScopeAndBoundedRead(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	own, err := f.client.Tag.Create().SetTag("Same <tag>").SetColor("blue").SetTenantID(organization.TenantID).Save(ctx)
	require.NoError(t, err)
	other, err := f.client.Tenant.Create().SetDescription("Other organization").Save(ctx)
	require.NoError(t, err)
	foreign, err := f.client.Tag.Create().SetTag("same <tag>").SetColor("red").SetTenantID(other.ID).Save(ctx)
	require.NoError(t, err)
	for _, scope := range []access.Scope{{}, organization, f.scope} {
		g := ownedDeletionGraph(t, f, scope)
		require.NoError(t, f.client.Task.UpdateOneID(g.task).SetOrder(9).SetScript("private-owned-script").SetLocalUserPassword("private-owned-password").SetLocalUserSSHKeyPassphrase("private-owned-passphrase").Exec(ctx))
		read := func(actor string, scope access.Scope) (*inventory.ProfileEditorReview, error) {
			return inventory.ReadProfileEditor(ctx, f.db, f.permissions, actor, scope, int64(g.profile), 9, 2, inventory.ProfileTagQuery{Page: 1, Search: "Same <tag>"})
		}
		for _, actor := range []string{"tag-admin", "tag-viewer", "tag-operator", "viewer", "missing"} {
			_, err := read(actor, scope)
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range []access.Scope{{}, organization, f.scope} {
			if wrong != scope {
				_, err := read("admin", wrong)
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		}
		review, err := read("admin", scope)
		require.NoError(t, err)
		require.Equal(t, g.profile, review.Profile.ID)
		require.Equal(t, 1, review.Tasks.Page)
		require.Equal(t, 1, review.Tasks.Total)
		require.Len(t, review.Tasks.Tasks, 1)
		require.Empty(t, review.Tasks.Tasks[0].Script)
		require.Empty(t, review.Tasks.Tasks[0].LocalUserPassword)
		require.Empty(t, review.Tasks.Tasks[0].LocalUserSSHKeyPassphrase)
		require.Empty(t, review.Profile.Edges.Tasks)
		require.Empty(t, review.Profile.Edges.Issues)
		if scope.TenantID == 0 {
			require.Len(t, review.Tags.Available, 2)
			require.Equal(t, int64(own.ID), review.Tags.Available[0].ID)
			require.Equal(t, other.ID, review.Tags.Available[1].TenantID)
		} else {
			require.Len(t, review.Tags.Available, 1)
			require.Equal(t, int64(own.ID), review.Tags.Available[0].ID)
		}
		stored, err := f.client.Task.Get(ctx, g.task)
		require.NoError(t, err)
		require.Equal(t, 9, stored.Order)
		assertDeletionGraph(t, f, g, true)
		// Existing foreign associations remain visible so administrators can remove them.
		require.NoError(t, f.client.Profile.UpdateOneID(g.profile).AddTagIDs(foreign.ID).Exec(ctx))
		panel, err := inventory.ReadProfileTagPanel(ctx, f.db, f.permissions, "admin", scope, int64(g.profile), inventory.ProfileTagQuery{Page: 1})
		require.NoError(t, err)
		found := false
		for _, choice := range panel.Applied {
			if choice.ID == int64(foreign.ID) {
				found = true
				require.Equal(t, other.ID, choice.TenantID)
			}
		}
		require.True(t, found)
		audits, err := audit.NewStore(f.db, f.permissions)
		require.NoError(t, err)
		for action, resource := range map[string]string{"inventory.profiles.read": fmt.Sprintf("%d/tasks/page/1/size/2/tags/page/1", g.profile), "inventory.profile_tags.read": fmt.Sprintf("%d/page/1", g.profile)} {
			filter := audit.Filter{Scope: scope, Source: "inventory", Action: action, Resource: resource, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
			page, err := audits.List(ctx, "admin", filter, "")
			require.NoError(t, err)
			require.Len(t, page.Events, 1)
			data, err := audits.ExportJSON(ctx, "admin", filter)
			require.NoError(t, err)
			require.NotContains(t, string(data), "private-owned")
			require.NotContains(t, string(data), "Same <tag>")
		}
	}
}

func TestProfileEditorTagPagingSearchAndReadRollback(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, strings.Repeat("界", 900))
	builders := make([]*ent.TagCreate, 0, 105)
	for i := 0; i < 105; i++ {
		builders = append(builders, f.client.Tag.Create().SetTag(fmt.Sprintf("Owned paging tag %03d", i)).SetColor("blue").SetTenantID(f.scope.TenantID))
	}
	tags, err := f.client.Tag.CreateBulk(builders...).Save(ctx)
	require.NoError(t, err)
	ids := []int{}
	for _, tag := range tags[:52] {
		ids = append(ids, tag.ID)
	}
	require.NoError(t, f.client.Profile.UpdateOneID(p.ID).AddTagIDs(ids...).Exec(ctx))
	review, err := inventory.ReadProfileEditor(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), 1, 5, inventory.ProfileTagQuery{Page: 99})
	require.NoError(t, err)
	require.True(t, review.NameNeedsReplacement)
	require.Empty(t, review.Profile.Name)
	require.LessOrEqual(t, len([]rune(review.NamePreview)), 513)
	require.Equal(t, 2, review.Tags.Query.Page)
	require.Equal(t, 52, review.Tags.Total)
	require.Len(t, review.Tags.Applied, 2)
	require.Len(t, review.Tags.Available, 50)
	require.True(t, review.Tags.HasMore)
	panel, err := inventory.ReadProfileTagPanel(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), inventory.ProfileTagQuery{Page: 1, Search: fmt.Sprint(tags[104].ID)})
	require.NoError(t, err)
	require.Len(t, panel.Available, 1)
	require.Equal(t, int64(tags[104].ID), panel.Available[0].ID)
	panel, err = inventory.ReadProfileTagPanel(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), inventory.ProfileTagQuery{Page: 1, Search: "%"})
	require.NoError(t, err)
	require.Empty(t, panel.Available, "search must be literal")
	for _, query := range []inventory.ProfileTagQuery{{Page: 0}, {Page: 1000001}, {Page: 1, Search: strings.Repeat("x", 257)}, {Page: 1, Search: "x\x00"}} {
		_, err = inventory.ReadProfileTagPanel(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), query)
		require.ErrorIs(t, err, inventory.ErrTagInvalid)
	}
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_profile_read() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('inventory.profiles.read','inventory.profile_tags.read') THEN RAISE EXCEPTION 'owned profile read audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_profile_read BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_profile_read()`)
	require.NoError(t, err)
	review, err = inventory.ReadProfileEditor(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), 1, 5, inventory.ProfileTagQuery{Page: 1})
	require.Error(t, err)
	require.Nil(t, review)
	panel, err = inventory.ReadProfileTagPanel(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), inventory.ProfileTagQuery{Page: 1})
	require.Error(t, err)
	require.Nil(t, panel)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = inventory.ReadProfileEditor(cancelled, f.db, f.permissions, "admin", f.scope, int64(p.ID), 1, 5, inventory.ProfileTagQuery{Page: 1})
	require.Error(t, err)
	stored, err := f.client.Profile.Get(ctx, p.ID)
	require.NoError(t, err)
	require.Equal(t, p.Name, stored.Name)
}

func TestProfileEditorTagMutationCommitsPanelAndAuditTogether(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Panel mutation")
	tag, err := f.client.Tag.Create().SetTag("Panel mutation tag").SetColor("blue").SetTenantID(f.scope.TenantID).Save(ctx)
	require.NoError(t, err)
	// A panel SELECT failure after the membership write must roll back both.
	_, err = f.db.ExecContext(ctx, `ALTER TABLE tenants RENAME COLUMN description TO owned_unavailable_description`)
	require.NoError(t, err)
	failed, err := inventory.ChangeProfileTagAndRead(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), int64(tag.ID), true, inventory.ProfileTagQuery{Page: 1})
	require.Error(t, err)
	require.Nil(t, failed)
	unchanged, err := f.client.Profile.Get(ctx, p.ID)
	require.NoError(t, err)
	require.True(t, unchanged.ApplyToAll)
	assignments, err := p.QueryTags().Count(ctx)
	require.NoError(t, err)
	require.Zero(t, assignments)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE tenants RENAME COLUMN owned_unavailable_description TO description`)
	require.NoError(t, err)
	panel, err := inventory.ChangeProfileTagAndRead(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), int64(tag.ID), true, inventory.ProfileTagQuery{Page: 1})
	require.NoError(t, err)
	require.False(t, panel.ApplyToAll)
	require.Equal(t, 1, panel.Total)
	require.Equal(t, int64(tag.ID), panel.Applied[0].ID)
	_, err = f.db.ExecContext(ctx, `CREATE FUNCTION reject_owned_panel_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profile_tags.unassign' THEN RAISE EXCEPTION 'owned mutation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_panel_mutation BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_panel_mutation()`)
	require.NoError(t, err)
	panel, err = inventory.ChangeProfileTagAndRead(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), int64(tag.ID), false, inventory.ProfileTagQuery{Page: 1})
	require.Error(t, err)
	require.Nil(t, panel)
	count, err := p.QueryTags().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	_, err = f.db.ExecContext(ctx, `DROP TRIGGER reject_owned_panel_mutation ON uem_inventory_audit; DROP FUNCTION reject_owned_panel_mutation()`)
	require.NoError(t, err)
	panel, err = inventory.ChangeProfileTagAndRead(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), int64(tag.ID), false, inventory.ProfileTagQuery{Page: 0})
	require.ErrorIs(t, err, inventory.ErrTagInvalid)
	require.Nil(t, panel)
	panel, err = inventory.ChangeProfileTagAndRead(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID), int64(tag.ID), false, inventory.ProfileTagQuery{Page: 99})
	require.NoError(t, err)
	require.Zero(t, panel.Total)
	require.Equal(t, 1, panel.Query.Page)
	require.False(t, panel.ApplyToAll)
}
