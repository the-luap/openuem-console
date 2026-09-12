package apple

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestUpdateEscalationNewEpisodeRejectsStaleAckButReplaysOriginalReceipt(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	_, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Attention)
	r := ownedEscalationDetails(t, f, original)
	ackq := UpdateEscalationRequest{PlanID: q.PlanID, AssignmentID: q.AssignmentID, RequestKey: uuid.NewString(), ConfigurationRevision: 1, IncidentID: r.IncidentID, Reason: "Owned first incident"}
	ack, err := f.store.AcknowledgeUpdateEscalation(ctx, "operator", f.permissions, f.scope, ackq)
	require.NoError(t, err)
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions))
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Cleared)
	policy := original.Plan.Definition.Policy()
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	drainTimeZoneInventory(t, f.store, f.device, "UTC", true)
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Attention)
	current := ownedEscalationDetails(t, f, original)
	require.NotEqual(t, r.IncidentID, current.IncidentID)
	require.Empty(t, current.AcknowledgmentID)
	replay, err := f.store.AcknowledgeUpdateEscalation(ctx, "operator", f.permissions, f.scope, ackq)
	require.NoError(t, err)
	require.Equal(t, ack.ID, replay.ID)
	require.Empty(t, ownedEscalationDetails(t, f, original).AcknowledgmentID)
	changed := ackq
	changed.Reason = "Changed original intent"
	_, err = f.store.AcknowledgeUpdateEscalation(ctx, "operator", f.permissions, f.scope, changed)
	require.ErrorIs(t, err, ErrConflict)
	changed = ackq
	changed.RequestKey = uuid.NewString()
	_, err = f.store.AcknowledgeUpdateEscalation(ctx, "operator", f.permissions, f.scope, changed)
	require.ErrorIs(t, err, ErrConflict)
	changed.IncidentID = current.IncidentID
	_, err = f.store.AcknowledgeUpdateEscalation(ctx, "operator", f.permissions, f.scope, changed)
	require.NoError(t, err)
}
func TestUpdateEscalationOriginalHistorySurvivesPlanArchiveAndDeviceMove(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	_, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Attention)
	events, _, err := f.store.UpdateEscalationEvents(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, "")
	require.NoError(t, err)
	attention := events[0]
	definition := f.plan.Definition
	definition.Archived = true
	definition.Name = "Changed current plan name"
	_, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET site_id=2,name='Owned other-site name' WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Updated)
	r := ownedEscalationDetails(t, f, original)
	require.Equal(t, 1, r.OpenCount)
	require.Equal(t, 1, r.AwaitingCount)
	require.Equal(t, "device_unavailable", r.Snapshot.Devices[0].Decision.Reason)
	require.Equal(t, original.Plan.Definition.Name, r.Assignment.Plan.Definition.Name)
	historical, err := f.store.UpdateEscalationEventDetails(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, attention.ID)
	require.NoError(t, err)
	require.Equal(t, "attention", historical.Snapshot.Devices[0].Decision.State)
	review, err := f.store.ReviewUpdateGroupEscalation(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID)
	require.NoError(t, err)
	require.NotEqual(t, "Owned other-site name", review.Progress.Devices[0].Name)
}
func TestUpdateEscalationUnavailablePolicyBlocksWithoutReplacingSavedEvidence(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	_, err := f.store.ConfigureUpdateEscalation(t.Context(), "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Attention)
	previous := ownedEscalationDetails(t, f, original)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_update_policies SET details_url=repeat('x',9000) WHERE device_id=$1`, f.device.ID)
	require.NoError(t, err)
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Blocked)
	blocked := ownedEscalationDetails(t, f, original)
	require.Equal(t, "source_unavailable", blocked.Reason)
	require.Equal(t, previous.IncidentID, blocked.IncidentID)
	require.Equal(t, previous.Snapshot.AssessedAt, blocked.Snapshot.AssessedAt)
	require.Nil(t, blocked.NextCheckAt)
	require.Zero(t, ownedEscalationProcess(t, f).Processed)
	review, err := f.store.ReviewUpdateGroupEscalation(t.Context(), "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID)
	require.NoError(t, err)
	require.True(t, review.PreviewUnavailable)
	require.NotNil(t, review.Current)
	q.RequestKey = uuid.NewString()
	q.ConfigurationRevision = 1
	q.Enabled = false
	_, err = f.store.ConfigureUpdateEscalation(t.Context(), "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	require.Equal(t, "paused", ownedEscalationDetails(t, f, original).Phase)
}
func TestUpdateEscalationHistoryKeysetAndImmutableEventIntegrity(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	var first *UpdateEscalationEvent
	for i := range 27 {
		q.RequestKey = uuid.NewString()
		q.ConfigurationRevision = i
		q.Enabled = i%2 == 0
		e, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
		require.NoError(t, err)
		if first == nil {
			first = e
		}
	}
	items, next, err := f.store.UpdateEscalationEvents(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, "")
	require.NoError(t, err)
	require.Len(t, items, 25)
	require.NotEmpty(t, next)
	q.RequestKey = uuid.NewString()
	q.ConfigurationRevision = 27
	q.Enabled = false
	_, err = f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	older, last, err := f.store.UpdateEscalationEvents(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, next)
	require.NoError(t, err)
	require.Len(t, older, 2)
	require.Empty(t, last)
	require.Equal(t, first.ID, older[1].ID)
	monitors, cursor, err := f.store.UpdateEscalations(ctx, "operator", f.permissions, f.scope, "")
	require.NoError(t, err)
	require.Len(t, monitors, 1)
	require.Empty(t, cursor)
	monitors, cursor, err = f.store.UpdateEscalations(ctx, "operator", f.permissions, f.scope, monitors[0].ID)
	require.NoError(t, err)
	require.Empty(t, monitors)
	require.Empty(t, cursor)
	for _, query := range []string{`UPDATE mdm_apple_update_escalation_events SET actor='other' WHERE id=$1`, `DELETE FROM mdm_apple_update_escalation_events WHERE id=$1`} {
		_, err = f.store.db.Exec(query, first.ID)
		require.Error(t, err)
	}
	_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_update_escalation_events DISABLE TRIGGER mdm_apple_keep_update_escalation_event`)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_update_escalation_events SET encrypted_event=decode(repeat('00',40),'hex') WHERE id=$1`, first.ID)
	_, restoreErr := f.store.db.Exec(`ALTER TABLE mdm_apple_update_escalation_events ENABLE TRIGGER mdm_apple_keep_update_escalation_event`)
	require.NoError(t, err)
	require.NoError(t, restoreErr)
	_, err = f.store.UpdateEscalationEventDetails(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, first.ID)
	require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
	_, _, err = f.store.UpdateEscalationEvents(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID, first.ID)
	require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
	// A corrupted old configuration event does not rewrite the newest one.
	require.Equal(t, 28, ownedEscalationDetails(t, f, original).ConfigurationRevision)
}
func TestUpdateEscalationRequestValidationAndCurrentStateTampering(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	for _, condition := range []string{"bad-plan", "bad-assignment", "bad-key", "negative-revision", "too-large-revision", "configuration-reason", "configuration-incident", "initial-pause"} {
		bad := q
		switch condition {
		case "bad-plan":
			bad.PlanID = "invalid"
		case "bad-assignment":
			bad.AssignmentID = "invalid"
		case "bad-key":
			bad.RequestKey = "invalid"
		case "negative-revision":
			bad.ConfigurationRevision = -1
		case "too-large-revision":
			bad.ConfigurationRevision = 2147483647
		case "configuration-reason":
			bad.Reason = "unexpected"
		case "configuration-incident":
			bad.IncidentID = uuid.NewString()
		case "initial-pause":
			bad.Enabled = false
		}
		_, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, bad)
		require.Error(t, err, condition)
	}
	e, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_update_escalations SET next_check_at=next_check_at+interval '1 hour' WHERE id=$1`, e.WatchID)
	require.NoError(t, err)
	_, err = f.store.UpdateEscalationDetails(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID)
	require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
	_, err = f.store.ReviewUpdateGroupEscalation(ctx, "operator", f.permissions, f.scope, q.PlanID, q.AssignmentID)
	require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
	_, _, err = f.store.UpdateEscalations(ctx, "operator", f.permissions, f.scope, "")
	require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
	// A receipt retry authenticates immutable original intent, independent of the
	// current state; it cannot repair or silently replace a corrupt watch.
	replay, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	require.Equal(t, e.ID, replay.ID)
	_, err = f.store.UpdateEscalationDetails(ctx, "operator", f.permissions, f.scope, q.PlanID, original.ID)
	require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
}
func TestUpdateEscalationEventRejectsInconsistentDecisionOrIntent(t *testing.T) {
	for _, condition := range []string{"kind", "reason", "revision", "scope", "missing-key", "future-snapshot", "empty-incident", "foreign-target", "changed-original"} {
		t.Run(condition, func(t *testing.T) {
			r := ownedEscalationState()
			e := escalationEvent(r, "acknowledged", r.Actor, r.ActorRevision)
			e.ExpectedRevision = 1
			e.RequestKey = uuid.NewString()
			e.Reason = "Owned follow-up"
			require.NoError(t, validateUpdateEscalationEvent(e))
			switch condition {
			case "kind":
				e.Kind = "resolved"
			case "reason":
				e.Reason = ""
			case "revision":
				e.ExpectedRevision = 0
			case "scope":
				e.Scope.SiteID = 0
			case "missing-key":
				e.RequestKey = ""
			case "future-snapshot":
				e.CreatedAt = e.Snapshot.AssessedAt.Add(-time.Second)
			case "empty-incident":
				e.IncidentID = ""
			case "foreign-target":
				e.OpenTargets = []string{uuid.NewString()}
			case "changed-original":
				e.original = []string{uuid.NewString()}
			}
			require.ErrorIs(t, validateUpdateEscalationEvent(e), ErrUpdateEscalationIntegrity)
		})
	}
}
