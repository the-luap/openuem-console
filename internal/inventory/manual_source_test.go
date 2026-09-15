package inventory_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

func TestManualExecutionRejectsUnsupportedMixedProfileAndOversizedConfiguration(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	store := manualStore(t, f, nil)
	p, id := manualTask(t, f, f.scope)
	review, err := store.Review(ctx, "admin", f.scope, f.id, "task", int64(id))
	require.NoError(t, err)
	require.NoError(t, f.client.Task.UpdateOneID(id).SetScript(strings.Repeat("x", (128<<10)+1)).Exec(ctx))
	_, err = store.Request(ctx, "admin", f.scope, f.id, uuid.NewString(), "task", int64(id), review.Source.Revision)
	require.ErrorIs(t, err, inventory.ErrManualUnsupported)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM uem_manual_execution").Scan(&count))
	require.Zero(t, count)
	require.NoError(t, f.client.Task.UpdateOneID(id).SetScript("Write-Output owned").Exec(ctx))
	netbird, err := f.client.Task.Create().SetName("Owned mixed task").SetType(task.TypeNetbirdRegister).SetAgentType(task.AgentTypeAny).SetTenant(org.TenantID).SetProfileID(p).Save(ctx)
	require.NoError(t, err)
	review, err = store.Review(ctx, "admin", f.scope, f.id, "profile", int64(p))
	require.NoError(t, err)
	require.Equal(t, 2, review.Source.TaskCount)
	_, err = store.Review(ctx, "admin", f.scope, f.id, "task", int64(netbird.ID))
	require.ErrorIs(t, err, inventory.ErrManualUnsupported)
	for _, kind := range []string{"wrong-provider", "unsupported", "wrong-platform-family", "too-many"} {
		t.Run(kind, func(t *testing.T) {
			switch kind {
			case "wrong-provider":
				require.NoError(t, f.client.Task.UpdateOneID(netbird.ID).SetTenant(org.TenantID+10000).Exec(ctx))
			case "unsupported":
				require.NoError(t, f.client.Task.UpdateOneID(netbird.ID).SetTenant(org.TenantID).SetType(task.TypeWingetUpdate).SetAgentType(task.AgentTypeWindows).Exec(ctx))
			case "wrong-platform-family":
				require.NoError(t, f.client.Task.UpdateOneID(netbird.ID).SetType(task.TypeUnixScript).Exec(ctx))
			case "too-many":
				require.NoError(t, f.client.Task.UpdateOneID(netbird.ID).SetType(task.TypeNetbirdInstall).SetAgentType(task.AgentTypeAny).Exec(ctx))
				_, err = f.db.ExecContext(ctx, "INSERT INTO tasks(profile_tasks,name,type,agent_type) SELECT $1,'Owned bounded task','powershell_script','windows' FROM generate_series(1,999)", p)
				require.NoError(t, err)
			}
			review, err = store.Review(ctx, "admin", f.scope, f.id, "profile", int64(p))
			require.ErrorIs(t, err, inventory.ErrManualUnsupported)
			require.Nil(t, review)
			page, err := store.Choices(ctx, "admin", f.scope, f.id, "profile", "")
			require.NoError(t, err)
			require.Empty(t, page.Sources)
		})
	}
	global := ownedTagProfile(t, f, access.Scope{}, "Global provider profile")
	require.NoError(t, f.client.Task.UpdateOneID(netbird.ID).SetType(task.TypeNetbirdRegister).SetTenant(org.TenantID).SetProfileID(global.ID).Exec(ctx))
	_, err = store.Review(ctx, "admin", f.scope, f.id, "profile", int64(global.ID))
	require.ErrorIs(t, err, inventory.ErrManualUnsupported)
	for _, scope := range []access.Scope{{}, org, {SiteID: f.scope.SiteID}} {
		_, err = store.Review(ctx, "admin", scope, f.id, "task", int64(id))
		require.ErrorIs(t, err, inventory.ErrManualInvalid)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = store.Review(cancelled, "admin", f.scope, f.id, "task", int64(id))
	require.ErrorIs(t, err, context.Canceled)
	for _, bad := range []string{"", uuid.Nil.String(), "not-a-request"} {
		_, err = store.Request(ctx, "admin", f.scope, f.id, bad, "task", int64(id), strings.Repeat("a", 64))
		require.ErrorIs(t, err, inventory.ErrManualInvalid)
	}
}

func TestManualExecutionConstructorNeedsIndependentAttemptConnection(t *testing.T) {
	f, _ := tagFixture(t)
	publish := func(context.Context, string, string, *taskexecution.Payload) error { return nil }
	_, err := inventory.NewManualExecutionStore(nil, f.permissions, false, "", publish)
	require.ErrorIs(t, err, inventory.ErrManualInvalid)
	_, err = inventory.NewManualExecutionStore(f.db, nil, false, "", publish)
	require.ErrorIs(t, err, inventory.ErrManualInvalid)
	_, err = inventory.NewManualExecutionStore(f.db, f.permissions, false, "", nil)
	require.ErrorIs(t, err, inventory.ErrManualInvalid)
	f.db.SetMaxOpenConns(1)
	_, err = inventory.NewManualExecutionStore(f.db, f.permissions, false, "", publish)
	require.ErrorIs(t, err, inventory.ErrManualInvalid)
	f.db.SetMaxOpenConns(8)
}
