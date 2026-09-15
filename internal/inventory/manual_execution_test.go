package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/taskexecution"
	"github.com/stretchr/testify/require"
)

func manualStore(t *testing.T, f *refreshFixture, publish inventory.ManualPublisher) *inventory.ManualExecutionStore {
	t.Helper()
	if publish == nil {
		publish = func(context.Context, string, string, *taskexecution.Payload) error { return nil }
	}
	store, err := inventory.NewManualExecutionStore(f.db, f.permissions, false, strings.Repeat("k", 32), publish)
	require.NoError(t, err)
	return store
}

func manualTask(t *testing.T, f *refreshFixture, scope access.Scope) (int, int) {
	t.Helper()
	p := ownedTagProfile(t, f, scope, "Owned manual profile")
	task, err := f.client.Task.Create().SetName("Owned manual task").SetType(task.TypePowershellScript).SetAgentType(task.AgentTypeWindows).SetScript("Write-Output 'Owned command'").SetVersion(3).SetProfileID(p.ID).Save(t.Context())
	require.NoError(t, err)
	return p.ID, task.ID
}

func TestManualExecutionScopeReviewQueueAndSingleDispatch(t *testing.T) {
	f, org := tagFixture(t)
	ctx := t.Context()
	sent := 0
	store := manualStore(t, f, func(ctx context.Context, device, id string, payload *taskexecution.Payload) error {
		sent++
		require.Equal(t, f.id, device)
		require.NotEmpty(t, id)
		require.NotEmpty(t, payload.Data)
		return nil
	})
	for _, sourceScope := range []access.Scope{{}, org, f.scope} {
		profileID, taskID := manualTask(t, f, sourceScope)
		for _, kind := range []string{"task", "profile"} {
			id := int64(taskID)
			if kind == "profile" {
				id = int64(profileID)
			}
			for _, actor := range []string{"tag-admin", "tag-viewer", "tag-operator", "viewer", "missing"} {
				_, err := store.Review(ctx, actor, f.scope, f.id, kind, id)
				require.ErrorIs(t, err, access.ErrDenied)
			}
			review, err := store.Review(ctx, "admin", f.scope, f.id, kind, id)
			require.NoError(t, err)
			require.Equal(t, sourceScope, review.Source.Scope)
			require.Equal(t, int64(profileID), review.Source.ProfileID)
			require.Len(t, review.Source.Revision, 64)
			require.NotContains(t, fmt.Sprint(review), "Owned command")
			requestID := uuid.NewString()
			request, err := store.Request(ctx, "admin", f.scope, f.id, requestID, kind, id, review.Source.Revision)
			require.NoError(t, err)
			require.Equal(t, "queued", request.Status)
			require.Nil(t, request.AttemptedAt)
			again, err := store.Request(ctx, "admin", f.scope, f.id, requestID, kind, id, review.Source.Revision)
			require.NoError(t, err)
			require.Equal(t, request.ID, again.ID)
			_, err = store.Request(ctx, "admin", f.scope, f.id, uuid.NewString(), kind, id, review.Source.Revision)
			require.ErrorIs(t, err, inventory.ErrManualConflict)
			before := sent
			worked, err := store.DispatchOne(ctx)
			require.NoError(t, err)
			require.True(t, worked)
			require.Equal(t, before+1, sent)
			receipt, err := store.Read(ctx, "admin", f.scope, f.id, requestID)
			require.NoError(t, err)
			require.Equal(t, "accepted", receipt.Status)
			require.NotNil(t, receipt.AttemptedAt)
			again, err = store.Request(ctx, "admin", f.scope, f.id, requestID, kind, id, review.Source.Revision)
			require.NoError(t, err)
			require.Equal(t, "accepted", again.Status)
			worked, err = store.DispatchOne(ctx)
			require.NoError(t, err)
			require.False(t, worked)
			require.Equal(t, before+1, sent)
			auditStore, err := audit.NewStore(f.db, f.permissions)
			require.NoError(t, err)
			filter := audit.Filter{Scope: f.scope, Source: "manual-execution", Action: "inventory.execution.accepted", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
			data, err := auditStore.ExportJSON(ctx, "admin", filter)
			require.NoError(t, err)
			require.Contains(t, string(data), requestID)
			require.NotContains(t, string(data), "Owned command")
		}
	}
}

func TestManualExecutionRejectionUncertaintyAndStoppedSource(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	_, taskID := manualTask(t, f, f.scope)
	for _, outcome := range []struct {
		err    error
		status string
	}{{inventory.ErrManualRejected, "rejected"}, {errors.New("private broker error"), "unconfirmed"}, {nil, "accepted"}} {
		sent := 0
		store := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error { sent++; return outcome.err })
		review, err := store.Review(ctx, "admin", f.scope, f.id, "task", int64(taskID))
		require.NoError(t, err)
		request, err := store.Request(ctx, "admin", f.scope, f.id, uuid.NewString(), "task", int64(taskID), review.Source.Revision)
		require.NoError(t, err)
		_, err = store.DispatchOne(ctx)
		require.NoError(t, err)
		receipt, err := store.Read(ctx, "admin", f.scope, f.id, request.ID)
		require.NoError(t, err)
		require.Equal(t, outcome.status, receipt.Status)
		_, err = store.DispatchOne(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, sent)
	}
	store := manualStore(t, f, func(context.Context, string, string, *taskexecution.Payload) error {
		t.Fatal("changed source was dispatched")
		return nil
	})
	review, err := store.Review(ctx, "admin", f.scope, f.id, "task", int64(taskID))
	require.NoError(t, err)
	request, err := store.Request(ctx, "admin", f.scope, f.id, uuid.NewString(), "task", int64(taskID), review.Source.Revision)
	require.NoError(t, err)
	require.NoError(t, f.client.Task.UpdateOneID(taskID).SetVersion(4).Exec(ctx))
	_, err = store.DispatchOne(ctx)
	require.NoError(t, err)
	receipt, err := store.Read(ctx, "admin", f.scope, f.id, request.ID)
	require.NoError(t, err)
	require.Equal(t, "stopped", receipt.Status)
	require.Equal(t, "source_changed", receipt.Reason)
	require.Nil(t, receipt.AttemptedAt)
}
