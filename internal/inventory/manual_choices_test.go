package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

func TestManualExecutionChoicesBoundedLiteralAndExactAudience(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	store := manualStore(t, f, nil)
	var visible []int
	for _, scope := range []access.Scope{{}, org, f.scope} {
		p, id := manualTask(t, f, scope)
		visible = append(visible, id)
		require.NoError(t, f.client.Profile.UpdateOneID(p).SetName("Owned %_profile").Exec(ctx))
		require.NoError(t, f.client.Task.UpdateOneID(id).SetName("Owned %_task").Exec(ctx))
	}
	otherOrg, err := f.client.Tenant.Create().SetDescription("Foreign organization").Save(ctx)
	require.NoError(t, err)
	for _, scope := range []access.Scope{{TenantID: otherOrg.ID}, {TenantID: org.TenantID, SiteID: f.otherSite}} {
		p, id := manualTask(t, f, scope)
		for _, source := range []struct {
			kind string
			id   int
		}{{"task", id}, {"profile", p}} {
			review, err := store.Review(ctx, "admin", f.scope, f.id, source.kind, int64(source.id))
			require.ErrorIs(t, err, inventory.ErrNotFound)
			require.Nil(t, review)
		}
	}
	p, disabled := manualTask(t, f, f.scope)
	require.NoError(t, f.client.Task.UpdateOneID(disabled).SetDisabled(true).Exec(ctx))
	p2, wrongOS := manualTask(t, f, f.scope)
	require.NoError(t, f.client.Task.UpdateOneID(wrongOS).SetType(task.TypeUnixScript).SetAgentType(task.AgentTypeLinux).Exec(ctx))
	p3, unsupported := manualTask(t, f, f.scope)
	require.NoError(t, f.client.Task.UpdateOneID(unsupported).SetType(task.TypeWingetUpdate).Exec(ctx))
	p4, disabledParent := manualTask(t, f, f.scope)
	require.NoError(t, f.client.Profile.UpdateOneID(p4).SetDisabled(true).Exec(ctx))
	for _, source := range []struct {
		kind string
		id   int
	}{{"task", disabled}, {"profile", p}, {"task", wrongOS}, {"profile", p2}, {"task", unsupported}, {"profile", p3}, {"task", disabledParent}, {"profile", p4}} {
		review, err := store.Review(ctx, "admin", f.scope, f.id, source.kind, int64(source.id))
		require.Error(t, err)
		require.Nil(t, review)
	}
	for _, kind := range []string{"task", "profile"} {
		page, err := store.Choices(ctx, "admin", f.scope, f.id, kind, "%_")
		require.NoError(t, err)
		require.Len(t, page.Sources, 3)
		require.False(t, page.More)
		require.NotContains(t, fmt.Sprint(page), "Owned command")
		for _, source := range page.Sources {
			require.Empty(t, source.Revision)
		}
		for _, actor := range []string{"tag-admin", "tag-operator", "tag-viewer", "missing"} {
			_, err = store.Choices(ctx, actor, f.scope, f.id, kind, "")
			require.ErrorIs(t, err, access.ErrDenied)
		}
	}
	for range 52 {
		manualTask(t, f, f.scope)
	}
	page, err := store.Choices(ctx, "admin", f.scope, f.id, "task", "")
	require.NoError(t, err)
	require.Len(t, page.Sources, 50)
	require.True(t, page.More)
	page, err = store.Choices(ctx, "admin", f.scope, f.id, "task", fmt.Sprint(visible[0]))
	require.NoError(t, err)
	require.Len(t, page.Sources, 1)
	require.EqualValues(t, visible[0], page.Sources[0].ID)
	long := strings.Repeat("x", 600) + "Owned unique suffix"
	require.NoError(t, f.client.Task.UpdateOneID(visible[0]).SetName(long).Exec(ctx))
	page, err = store.Choices(ctx, "admin", f.scope, f.id, "task", "Owned unique suffix")
	require.NoError(t, err)
	require.Len(t, page.Sources, 1)
	require.LessOrEqual(t, len([]rune(page.Sources[0].Name)), 513)
	for _, search := range []string{strings.Repeat("x", 257), "invalid\x00query", string([]byte{0xff})} {
		page, err = store.Choices(ctx, "admin", f.scope, f.id, "task", search)
		require.ErrorIs(t, err, inventory.ErrManualInvalid)
		require.Nil(t, page)
	}
	_, err = f.db.ExecContext(ctx, "ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_manual_read_failure CHECK(action NOT IN ('inventory.execution.choices','inventory.execution.review','inventory.execution.read')) NOT VALID")
	require.NoError(t, err)
	page, err = store.Choices(ctx, "admin", f.scope, f.id, "task", "")
	require.Error(t, err)
	require.Nil(t, page)
	review, err := store.Review(ctx, "admin", f.scope, f.id, "task", int64(visible[0]))
	require.Error(t, err)
	require.Nil(t, review)
}

func TestManualExecutionRechecksQueuedStateAndKeepsHistoricalReceipt(t *testing.T) {
	for _, change := range []string{"expired", "mode", "permission", "audience", "parent", "disabled", "platform", "membership", "deleted"} {
		t.Run(change, func(t *testing.T) {
			f, org := tagFixture(t)
			ctx := t.Context()
			p, id := manualTask(t, f, f.scope)
			store := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error {
				t.Error("stale request dispatched")
				return nil
			})
			principal, err := f.permissions.Principal(ctx, "tag-admin")
			require.NoError(t, err)
			require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
			request := queueManual(t, f, store, "tag-admin", id)
			reason := "source_changed"
			switch change {
			case "expired":
				_, err = f.db.ExecContext(ctx, "UPDATE uem_manual_execution SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", request.ID)
				reason = "expired"
			case "mode":
				store, err = inventory.NewManualExecutionStore(f.db, f.permissions, true, "", func(context.Context, string, string, *taskexecution.Payload) error {
					t.Error("changed mode dispatched")
					return nil
				})
				reason = "mode_changed"
			case "permission":
				principal, err = f.permissions.Principal(ctx, "tag-admin")
				require.NoError(t, err)
				err = f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.TenantAdmin, Scope: org}})
				reason = "not_authorized"
			case "audience":
				_, err = f.db.ExecContext(ctx, "INSERT INTO site_profiles(profile_id,site_id) VALUES($1,$2)", p, f.otherSite)
			case "parent":
				other := ownedTagProfile(t, f, org, "Moved parent")
				err = f.client.Task.UpdateOneID(id).SetProfileID(other.ID).Exec(ctx)
			case "disabled":
				err = f.client.Task.UpdateOneID(id).SetDisabled(true).Exec(ctx)
			case "platform":
				_, err = f.db.ExecContext(ctx, "UPDATE agents SET os='unsupported' WHERE oid=$1", f.id)
				reason = "target_changed"
			case "membership":
				_, err = f.db.ExecContext(ctx, "INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)", f.id, f.otherSite)
				reason = "target_changed"
			case "deleted":
				err = f.client.Task.DeleteOneID(id).Exec(ctx)
			}
			require.NoError(t, err)
			_, err = store.DispatchOne(ctx)
			require.NoError(t, err)
			receipt, err := store.Read(ctx, "admin", f.scope, f.id, request.ID)
			require.NoError(t, err)
			require.Equal(t, "stopped", receipt.Status)
			require.Equal(t, reason, receipt.Reason)
			require.Nil(t, receipt.AttemptedAt)
			_, err = store.Read(ctx, "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, request.ID)
			require.ErrorIs(t, err, inventory.ErrNotFound)
			require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(ctx))
			receipt, err = store.Read(ctx, "admin", f.scope, f.id, request.ID)
			require.NoError(t, err)
			require.Equal(t, "stopped", receipt.Status)
			_, err = store.Read(ctx, "admin", f.scope, f.id, uuid.NewString())
			require.ErrorIs(t, err, inventory.ErrNotFound)
		})
	}
}
