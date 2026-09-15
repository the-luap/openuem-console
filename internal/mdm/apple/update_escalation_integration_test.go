package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedUpdateEscalationFixture(t *testing.T) (updateScheduleFixture, *UpdatePlanGroupAssignment, UpdateEscalationRequest) {
	t.Helper()
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	definition := f.plan.Definition
	definition.Deadline = time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05")
	var err error
	f.plan, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	preview, err := f.store.PreviewUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	f.selection = updateGroupSelection(preview)
	original, err := f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection)
	require.NoError(t, err)
	drainTimeZoneInventory(t, f.store, f.device, "UTC", true)
	return f, original, UpdateEscalationRequest{PlanID: f.plan.ID, AssignmentID: original.ID, RequestKey: uuid.NewString(), Enabled: true}
}
func ownedEscalationDetails(t *testing.T, f updateScheduleFixture, original *UpdatePlanGroupAssignment) *UpdateEscalation {
	t.Helper()
	r, err := f.store.UpdateEscalationDetails(t.Context(), "admin", f.permissions, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	return r
}

// Advance only the persisted due time in an owned fixture, retaining correctly
// authenticated metadata. Production uses a five-minute interval.
func ownedEscalationDue(t *testing.T, f updateScheduleFixture, original *UpdatePlanGroupAssignment) {
	t.Helper()
	r := ownedEscalationDetails(t, f, original)
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	now, err := updateEscalationClock(t.Context(), tx, r)
	require.NoError(t, err)
	previous := r.StateRevision
	r.StateRevision++
	r.NextCheckAt = &now
	require.NoError(t, f.store.persistUpdateEscalation(t.Context(), tx, r, previous))
	require.NoError(t, tx.Commit())
}
func ownedEscalationProcess(t *testing.T, f updateScheduleFixture) UpdateEscalationProgress {
	t.Helper()
	p, err := f.store.ProcessDueUpdateEscalations(t.Context(), f.permissions, 25)
	require.NoError(t, err)
	return p
}
func TestUpdateEscalationConcurrentAdmissionAndWorkerPreserveIncidentAndAck(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	p0, a0, n0 := f.counts(t)
	var wg sync.WaitGroup
	results := make(chan *UpdateEscalationEvent, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			e, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
			results <- e
			failures <- err
		})
	}
	wg.Wait()
	require.NoError(t, <-failures)
	require.NoError(t, <-failures)
	first, second := <-results, <-results
	require.Equal(t, first.ID, second.ID)
	p, a, n := f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	passes := make(chan UpdateEscalationProgress, 2)
	for range 2 {
		wg.Go(func() {
			p, err := f.store.ProcessDueUpdateEscalations(ctx, f.permissions, 25)
			passes <- p
			failures <- err
		})
	}
	wg.Wait()
	require.NoError(t, <-failures)
	require.NoError(t, <-failures)
	pass1, pass2 := <-passes, <-passes
	require.Equal(t, 1, pass1.Processed+pass2.Processed)
	require.Equal(t, 1, pass1.Attention+pass2.Attention)
	r := ownedEscalationDetails(t, f, original)
	require.Equal(t, 1, r.OpenCount)
	require.Zero(t, r.AwaitingCount)
	require.NotEmpty(t, r.IncidentID)
	ackq := UpdateEscalationRequest{PlanID: q.PlanID, AssignmentID: q.AssignmentID, RequestKey: uuid.NewString(), ConfigurationRevision: 1, IncidentID: r.IncidentID, Reason: "Owned operator is coordinating the update."}
	ack, err := f.store.AcknowledgeUpdateEscalation(ctx, "operator", f.permissions, f.scope, ackq)
	require.NoError(t, err)
	require.Equal(t, r.IncidentID, ack.IncidentID)
	// A packet that omits TimeZone removes the projection; no guessed fallback.
	drainTimeZoneInventory(t, f.store, f.device, nil, false)
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Updated)
	unknown := ownedEscalationDetails(t, f, original)
	require.Equal(t, 1, unknown.OpenCount)
	require.Equal(t, 1, unknown.AwaitingCount)
	require.Equal(t, r.IncidentID, unknown.IncidentID)
	require.Equal(t, ack.ID, unknown.AcknowledgmentID)
	drainTimeZoneInventory(t, f.store, f.device, "UTC", true)
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Updated)
	recoveredEvidence := ownedEscalationDetails(t, f, original)
	require.Zero(t, recoveredEvidence.AwaitingCount)
	require.Equal(t, ack.ID, recoveredEvidence.AcknowledgmentID)
	require.Equal(t, r.IncidentID, recoveredEvidence.IncidentID)
	ownedEscalationDue(t, f, original)
	quiet := ownedEscalationProcess(t, f)
	require.Equal(t, 1, quiet.Processed)
	require.Zero(t, quiet.Attention+quiet.Updated+quiet.Cleared)
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, ownedExceptionRequest(t, f, "pause"))
	require.NoError(t, err)
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Cleared)
	cleared := ownedEscalationDetails(t, f, original)
	require.Zero(t, cleared.OpenCount)
	require.Empty(t, cleared.IncidentID)
	require.Empty(t, cleared.AcknowledgmentID)
	replay, err := f.store.AcknowledgeUpdateEscalation(ctx, "operator", f.permissions, f.scope, ackq)
	require.NoError(t, err)
	require.Equal(t, ack.ID, replay.ID)
	require.Empty(t, ownedEscalationDetails(t, f, original).AcknowledgmentID)
	events, next, err := f.store.UpdateEscalationEvents(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, "")
	require.NoError(t, err)
	require.Empty(t, next)
	require.Len(t, events, 6)
	require.Equal(t, "cleared", events[0].Kind)
	require.Equal(t, "exception_active", events[0].Snapshot.Devices[0].Decision.Reason)
	immutable, err := f.store.UpdateEscalationEventDetails(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, ack.ID)
	require.NoError(t, err)
	require.Equal(t, "attention", immutable.Snapshot.Devices[0].Decision.State)
	for _, value := range []any{r, ack, ackq} {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(raw))
		require.NotContains(t, fmt.Sprintf("%#v", value), f.device.ID)
	}
}
func TestUpdateEscalationPauseReplayAndChangedAuthorityRequireExplicitRearm(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	first, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Attention)
	r := ownedEscalationDetails(t, f, original)
	pause := q
	pause.RequestKey = uuid.NewString()
	pause.ConfigurationRevision = 1
	pause.Enabled = false
	_, err = f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, pause)
	require.NoError(t, err)
	paused := ownedEscalationDetails(t, f, original)
	require.Equal(t, "paused", paused.Phase)
	require.Equal(t, r.IncidentID, paused.IncidentID)
	require.Equal(t, 1, paused.OpenCount)
	require.Zero(t, ownedEscalationProcess(t, f).Processed)
	replay, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	require.Equal(t, first.ID, replay.ID)
	require.False(t, ownedEscalationDetails(t, f, original).Enabled)
	rearm := q
	rearm.ConfigurationRevision = 2
	rearm.RequestKey = uuid.NewString()
	_, err = f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, rearm)
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	require.Equal(t, 1, ownedEscalationProcess(t, f).Blocked)
	blocked := ownedEscalationDetails(t, f, original)
	require.Equal(t, "authority_changed", blocked.Reason)
	require.Equal(t, r.IncidentID, blocked.IncidentID)
	_, err = f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, rearm)
	require.ErrorIs(t, err, ErrConflict)
	rearm.ConfigurationRevision = 3
	rearm.RequestKey = uuid.NewString()
	_, err = f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, rearm)
	require.NoError(t, err)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Processed)
	require.Equal(t, int64(2), ownedEscalationDetails(t, f, original).ActorRevision)
	_, err = f.store.UpdateEscalationDetails(ctx, "viewer", f.permissions, f.scope, q.PlanID, q.AssignmentID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.ConfigureUpdateEscalation(ctx, "viewer", f.permissions, f.scope, rearm)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.UpdateEscalationEventDetails(ctx, "admin", f.permissions, Scope{TenantID: 2, SiteID: 2}, q.PlanID, q.AssignmentID, first.ID)
	require.Error(t, err)
}
func TestUpdateEscalationAuditFailureRollsBackConfigurationAndWorker(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	_, err := f.store.db.Exec(`CREATE FUNCTION owned_escalation_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('apple.update.escalation.configured','apple.update.escalation.checked') THEN RAISE EXCEPTION 'owned escalation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_escalation_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_escalation_audit_failure()`)
	require.NoError(t, err)
	_, err = f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.Error(t, err)
	var count int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_escalations`).Scan(&count))
	require.Zero(t, count)
	_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_audit DISABLE TRIGGER owned_escalation_audit_failure`)
	require.NoError(t, err)
	_, err = f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_audit ENABLE TRIGGER owned_escalation_audit_failure`)
	require.NoError(t, err)
	p, err := f.store.ProcessDueUpdateEscalations(ctx, f.permissions, 25)
	require.Error(t, err)
	require.Equal(t, 1, p.Failed)
	r := ownedEscalationDetails(t, f, original)
	require.Nil(t, r.CheckedAt)
	require.Equal(t, int64(1), r.StateRevision)
	require.Zero(t, r.OpenCount)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_escalation_events`).Scan(&count))
	require.Equal(t, 1, count)
	_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_audit DISABLE TRIGGER owned_escalation_audit_failure`)
	require.NoError(t, err)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Attention)
}
func TestUpdateEscalationRunnerStartsImmediatelyAndJoinsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		runUpdateEscalations(ctx, nil, time.Hour, time.Second, func(pass context.Context, limit int) (UpdateEscalationProgress, error) {
			if limit != 25 {
				panic("unexpected owned worker limit")
			}
			close(entered)
			<-pass.Done()
			return UpdateEscalationProgress{}, pass.Err()
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not join cancellation")
	}
}
