package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent"
	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestProfileCloningPreservesConfigurationInExactAuthorizedScopes(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	scopes := []access.Scope{{}, organization, f.scope}
	for _, source := range scopes {
		g := ownedDeletionGraph(t, f, source)
		require.NoError(t, f.client.Profile.UpdateOneID(g.profile).SetDisabled(true).Exec(ctx))
		require.NoError(t, f.client.Task.UpdateOneID(g.task).SetName("Owned APT task label").SetType(task.TypeAptInstall).SetAptName("owned-package").SetOrder(9).SetVersion(7).SetWhen(time.Now()).SetScript("owned synthetic script").SetLocalUserPassword("owned fixture value").SetDisabled(true).AddTagIDs(g.tag).Exec(ctx))
		second, err := f.client.Task.Create().SetName("Owned earlier task").SetType(task.TypeMsiInstall).SetMsiFileHashAlg(task.MsiFileHashAlgSHA256).SetOrder(2).SetProfileID(g.profile).Save(ctx)
		require.NoError(t, err)
		third, err := f.client.Task.Create().SetName("Owned tied task").SetType(task.TypeUnixScript).SetAgentType(task.AgentTypeLinux).SetOrder(2).SetProfileID(g.profile).Save(ctx)
		require.NoError(t, err)
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "operator", "viewer", "missing"} {
			id, err := inventory.CloneLegacyProfile(ctx, f.db, f.permissions, actor, source, organization, int64(g.profile), "Denied clone")
			require.Zero(t, id)
			require.ErrorIs(t, err, access.ErrDenied)
			_, err = inventory.ReviewProfileClone(ctx, f.db, f.permissions, actor, source, int64(g.profile))
			require.ErrorIs(t, err, access.ErrDenied)
		}
		for _, wrong := range scopes {
			if wrong == source {
				continue
			}
			id, err := inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "admin", wrong, organization, int64(g.profile), "Foreign clone")
			require.Zero(t, id)
			require.ErrorIs(t, err, inventory.ErrNotFound)
			_, err = inventory.ReviewProfileClone(ctx, f.db, f.permissions, "admin", wrong, int64(g.profile))
			require.ErrorIs(t, err, inventory.ErrNotFound)
		}
		for _, destination := range scopes {
			name := "Owned <clone>\n第二行"
			id, err := inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "admin", source, destination, int64(g.profile), name)
			require.NoError(t, err)
			p, err := f.client.Profile.Query().Where(entprofile.ID(int(id))).WithTasks(func(q *ent.TaskQuery) { q.Order(ent.Asc(task.FieldOrder)).WithTags().WithReports() }).WithTags().WithIssues().WithTenant().WithSite().Only(ctx)
			require.NoError(t, err)
			require.NotEqual(t, g.profile, p.ID)
			require.Equal(t, name, p.Name)
			require.False(t, p.ApplyToAll)
			require.False(t, p.Disabled)
			require.Equal(t, entprofile.TypeWinget, p.Type)
			require.Empty(t, p.Edges.Tags)
			require.Empty(t, p.Edges.Issues)
			if destination.TenantID == 0 {
				require.Empty(t, p.Edges.Tenant)
			} else {
				require.Len(t, p.Edges.Tenant, 1)
				require.Equal(t, destination.TenantID, p.Edges.Tenant[0].ID)
			}
			if destination.SiteID == 0 {
				require.Empty(t, p.Edges.Site)
			} else {
				require.Len(t, p.Edges.Site, 1)
				require.Equal(t, destination.SiteID, p.Edges.Site[0].ID)
			}
			require.Len(t, p.Edges.Tasks, 3)
			for i, original := range []int{second.ID, third.ID, g.task} {
				cloned := p.Edges.Tasks[i]
				require.NotEqual(t, original, cloned.ID)
				require.Equal(t, i+1, cloned.Order)
				require.Equal(t, 1, cloned.Version)
				require.True(t, cloned.When.IsZero())
				require.Empty(t, cloned.Edges.Tags)
				require.Empty(t, cloned.Edges.Reports)
				// Compare every stored configuration field, including NULL and
				// synthetic secret fields, without printing task contents on failure.
				var equal bool
				require.NoError(t, f.db.QueryRowContext(ctx, "SELECT (to_jsonb(a)-ARRAY['id','version','when','order','profile_tasks'])=(to_jsonb(b)-ARRAY['id','version','when','order','profile_tasks']) FROM tasks a,tasks b WHERE a.id=$1 AND b.id=$2", original, cloned.ID).Scan(&equal))
				require.True(t, equal, "cloned task configuration differs")
			}
			resource := fmt.Sprintf("%d/from/%d/%d/%d/to/%d/%d/tasks/3", id, g.profile, source.TenantID, source.SiteID, destination.TenantID, destination.SiteID)
			audits, err := audit.NewStore(f.db, f.permissions)
			require.NoError(t, err)
			for _, scope := range []access.Scope{source, destination} {
				filter := audit.Filter{Scope: scope, Source: "inventory", Action: "inventory.profiles.clone", Resource: resource, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
				page, err := audits.List(ctx, "admin", filter, "")
				require.NoError(t, err)
				found := 0
				for _, event := range page.Events {
					if event.TenantID == scope.TenantID && event.SiteID == scope.SiteID {
						found++
					}
				}
				require.Equal(t, 1, found)
				data, err := audits.ExportJSON(ctx, "admin", filter)
				require.NoError(t, err)
				require.Contains(t, string(data), resource)
				require.NotContains(t, string(data), "owned fixture value")
			}
			assertDeletionGraph(t, f, g, true)
		}
	}
}

func TestProfileCloningValidatesDestinationNamesAndProviderOrganization(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	p := ownedTagProfile(t, f, f.scope, "Clone validation")
	clone := func(scope access.Scope, name string) (int64, error) {
		return inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "admin", f.scope, scope, int64(p.ID), name)
	}
	for _, name := range []string{"", " \n\t", strings.Repeat("x", 2049), "bad\x00name", "bad\xffname"} {
		id, err := clone(organization, name)
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrProfileInvalid)
	}
	for _, scope := range []access.Scope{{SiteID: f.scope.SiteID}, {TenantID: -1}, {TenantID: organization.TenantID, SiteID: -1}} {
		id, err := clone(scope, "Invalid destination")
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrProfileInvalid)
	}
	other, err := f.client.Tenant.Create().SetDescription("Other clone organization").Save(ctx)
	require.NoError(t, err)
	otherSite, err := f.client.Site.Create().SetDescription("Other clone site").SetTenantID(other.ID).Save(ctx)
	require.NoError(t, err)
	id, err := clone(access.Scope{TenantID: organization.TenantID, SiteID: otherSite.ID}, "Crossed clone")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	id, err = clone(access.Scope{TenantID: other.ID, SiteID: otherSite.ID}, strings.Repeat("x", 2048))
	require.NoError(t, err)
	require.Positive(t, id)
	require.NoError(t, f.client.Profile.UpdateOneID(p.ID).SetName(strings.Repeat("x", 2049)).Exec(ctx))
	review, err := inventory.ReviewProfileClone(ctx, f.db, f.permissions, "admin", f.scope, int64(p.ID))
	require.NoError(t, err)
	require.Empty(t, review.Name)
	registration, err := f.client.Task.Create().SetName("Owned registration").SetType(task.TypeNetbirdRegister).SetTenant(organization.TenantID).SetNetbirdGroups("owned-group").SetNetbirdAllowExtraDNSLabels(true).SetProfileID(p.ID).Save(ctx)
	require.NoError(t, err)
	for _, destination := range []access.Scope{{}, {TenantID: other.ID}} {
		id, err = clone(destination, "Crossed provider clone")
		require.Zero(t, id)
		require.ErrorIs(t, err, inventory.ErrProfileCloneProviderScope)
	}
	id, err = clone(organization, "Provider clone")
	require.NoError(t, err)
	copied, err := f.client.Task.Query().Where(task.HasProfileWith(entprofile.ID(int(id)))).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, registration.Tenant, copied.Tenant)
	require.Equal(t, registration.NetbirdGroups, copied.NetbirdGroups)
	require.True(t, copied.NetbirdAllowExtraDNSLabels)
	_, err = f.db.ExecContext(ctx, "UPDATE tasks SET tenant=NULL WHERE id=$1", registration.ID)
	require.NoError(t, err)
	id, err = clone(organization, "Unconfigured provider clone")
	require.Zero(t, id)
	require.ErrorIs(t, err, inventory.ErrProfileCloneProviderScope)
}

func TestProfileCloningRollsBackTasksAudienceAndBothAuditReceipts(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	g := ownedDeletionGraph(t, f, f.scope)
	_, err := f.client.Task.Create().SetName("Owned second clone task").SetType(task.TypeUnixScript).SetOrder(2).SetProfileID(g.profile).Save(ctx)
	require.NoError(t, err)
	name := "Atomic clone"
	clone := func(ctx context.Context) (int64, error) {
		return inventory.CloneLegacyProfile(ctx, f.db, f.permissions, "admin", f.scope, organization, int64(g.profile), name)
	}
	unchanged := func() {
		count, err := f.client.Profile.Query().Where(entprofile.NameEQ(name)).Count(ctx)
		require.NoError(t, err)
		require.Zero(t, count)
		var tasks, events int
		require.NoError(t, f.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM tasks),(SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.profiles.clone')").Scan(&tasks, &events))
		require.Equal(t, 2, tasks)
		require.Zero(t, events)
		assertDeletionGraph(t, f, g, true)
	}
	_, err = f.db.ExecContext(ctx, "CREATE FUNCTION reject_owned_clone_task() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.profile_tasks!="+fmt.Sprint(g.profile)+" AND NEW.\"order\"=2 THEN RAISE EXCEPTION 'owned clone task failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_clone_task BEFORE INSERT ON tasks FOR EACH ROW EXECUTE FUNCTION reject_owned_clone_task()")
	require.NoError(t, err)
	id, err := clone(ctx)
	require.Zero(t, id)
	require.Error(t, err)
	unchanged()
	_, err = f.db.ExecContext(ctx, "DROP TRIGGER reject_owned_clone_task ON tasks; DROP FUNCTION reject_owned_clone_task(); ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_clone_audit_failure CHECK(action!='inventory.profiles.clone' OR site_id!=0) NOT VALID")
	require.NoError(t, err)
	id, err = clone(ctx)
	require.Zero(t, id)
	require.Error(t, err)
	unchanged()
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_clone_audit_failure")
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	id, err = clone(canceled)
	require.Zero(t, id)
	require.Error(t, err)
	unchanged()
	id, err = clone(ctx)
	require.NoError(t, err)
	require.Positive(t, id)
}
