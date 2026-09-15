package apple

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func ownedEscalationState() *UpdateEscalation {
	snapshot := ownedEscalationSnapshot()
	checked := snapshot.AssessedAt
	next := checked.Add(5 * time.Minute)
	id := snapshot.Devices[0].Decision.DeviceID
	return &UpdateEscalation{ID: "20000000-0000-4000-8000-000000000001", Scope: Scope{TenantID: 1, SiteID: 1}, PlanID: "30000000-0000-4000-8000-000000000001", AssignmentID: "40000000-0000-4000-8000-000000000001", ConfigurationRevision: 1, Actor: "owned-operator", ActorRevision: 1, Enabled: true, CreatedAt: checked.Add(-time.Hour), ConfiguredAt: checked.Add(-time.Hour), ConfigurationEventID: "50000000-0000-4000-8000-000000000001", StateRevision: 2, Phase: "watching", UpdatedAt: checked, CheckedAt: &checked, NextCheckAt: &next, IncidentID: "60000000-0000-4000-8000-000000000001", OpenCount: 1, Snapshot: snapshot, OpenTargets: []string{id}, original: []string{id}}
}

func TestUpdateEscalationStorageBindsConfigurationAndStateMetadata(t *testing.T) {
	box, err := newSecretBox(strings.Repeat("owned-test-key-", 4))
	require.NoError(t, err)
	s := &Store{secrets: box}
	original := ownedEscalationState()
	config, state, err := s.sealUpdateEscalation(original)
	require.NoError(t, err)
	var configuration updateEscalationConfigurationWire
	var saved updateEscalationStateWire
	require.NoError(t, s.openUpdateEscalationWire(config, updateEscalationConfigurationPurpose(original), 8192, &configuration))
	require.Equal(t, original.original, configuration.Original)
	require.NoError(t, s.openUpdateEscalationWire(state, updateEscalationStatePurpose(original), 131072, &saved))
	require.Equal(t, original.OpenTargets, saved.Open)
	for _, field := range []string{"scope", "plan", "assignment", "configuration", "owner", "grant", "enabled", "config-event", "created", "configured"} {
		t.Run("configuration/"+field, func(t *testing.T) {
			r := *original
			switch field {
			case "scope":
				r.Scope.SiteID++
			case "plan":
				r.PlanID = "30000000-0000-4000-8000-000000000002"
			case "assignment":
				r.AssignmentID = "40000000-0000-4000-8000-000000000002"
			case "configuration":
				r.ConfigurationRevision++
			case "owner":
				r.Actor = "other-operator"
			case "grant":
				r.ActorRevision++
			case "enabled":
				r.Enabled = false
			case "config-event":
				r.ConfigurationEventID = "50000000-0000-4000-8000-000000000002"
			case "created":
				r.CreatedAt = r.CreatedAt.Add(time.Second)
			case "configured":
				r.ConfiguredAt = r.ConfiguredAt.Add(time.Second)
			}
			require.ErrorIs(t, s.openUpdateEscalationWire(config, updateEscalationConfigurationPurpose(&r), 8192, &configuration), ErrUpdateEscalationIntegrity)
		})
	}
	for _, field := range []string{"scope", "configuration", "revision", "phase", "reason", "updated", "checked", "due", "incident", "ack", "open", "awaiting"} {
		t.Run("state/"+field, func(t *testing.T) {
			r := *original
			switch field {
			case "scope":
				r.Scope.SiteID++
			case "configuration":
				r.ConfigurationRevision++
			case "revision":
				r.StateRevision++
			case "phase":
				r.Phase = "paused"
			case "reason":
				r.Reason = "authority_changed"
			case "updated":
				r.UpdatedAt = r.UpdatedAt.Add(time.Second)
			case "checked":
				r.CheckedAt = nil
			case "due":
				r.NextCheckAt = nil
			case "incident":
				r.IncidentID = "60000000-0000-4000-8000-000000000002"
			case "ack":
				r.AcknowledgmentID = "70000000-0000-4000-8000-000000000001"
			case "open":
				r.OpenCount++
			case "awaiting":
				r.AwaitingCount++
			}
			require.ErrorIs(t, s.openUpdateEscalationWire(state, updateEscalationStatePurpose(&r), 131072, &saved), ErrUpdateEscalationIntegrity)
		})
	}
	raw, err := json.Marshal(original)
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(raw))
	require.NotContains(t, fmt.Sprintf("%#v", original), "owned-operator")
}

func TestUpdateEscalationStorageRejectsCounterAndLifecycleContradictions(t *testing.T) {
	for _, field := range []string{"missing-incident", "foreign-target", "open-count", "awaiting-count", "missing-check", "future-check", "early-due", "disabled-running", "blocked-reason", "duplicate-original"} {
		t.Run(field, func(t *testing.T) {
			r := ownedEscalationState()
			switch field {
			case "missing-incident":
				r.IncidentID = ""
			case "foreign-target":
				r.OpenTargets = []string{"10000000-0000-4000-8000-000000000002"}
			case "open-count":
				r.OpenCount = 0
			case "awaiting-count":
				r.AwaitingCount = 1
			case "missing-check":
				r.CheckedAt = nil
			case "future-check":
				future := r.UpdatedAt.Add(time.Second)
				r.CheckedAt = &future
			case "early-due":
				past := r.UpdatedAt.Add(-time.Second)
				r.NextCheckAt = &past
			case "disabled-running":
				r.Enabled = false
			case "blocked-reason":
				r.Phase = "blocked"
				r.NextCheckAt = nil
			case "duplicate-original":
				r.original = append(r.original, r.original[0])
			}
			require.ErrorIs(t, validateUpdateEscalationState(r), ErrUpdateEscalationIntegrity)
		})
	}
}

func TestUpdateEscalationEventCiphertextBindsEveryReceiptContext(t *testing.T) {
	box, err := newSecretBox(strings.Repeat("owned-event-key-", 4))
	require.NoError(t, err)
	s := &Store{secrets: box}
	r := ownedEscalationState()
	original := escalationEvent(r, "acknowledged", r.Actor, r.ActorRevision)
	original.RequestKey = "70000000-0000-4000-8000-000000000001"
	original.ExpectedRevision = 1
	original.Reason = "Owned event note"
	require.NoError(t, validateUpdateEscalationEvent(original))
	wire := updateEscalationEventWire{Version: 1, WatchCreatedAt: original.WatchCreatedAt, Enabled: original.Enabled, Phase: original.Phase, ExpectedRevision: original.ExpectedRevision, Reason: original.Reason, Original: original.original, Open: original.OpenTargets, Snapshot: escalationSnapshotWire(original.Snapshot)}
	encrypted, err := s.sealUpdateEscalationWire(wire, updateEscalationEventPurpose(original), 131072)
	require.NoError(t, err)
	var decoded updateEscalationEventWire
	require.NoError(t, s.openUpdateEscalationWire(encrypted, updateEscalationEventPurpose(original), 131072, &decoded))
	for _, field := range []string{"id", "watch", "tenant", "site", "plan", "assignment", "revision", "configuration", "kind", "actor", "grant", "key", "incident", "created"} {
		t.Run(field, func(t *testing.T) {
			e := *original
			switch field {
			case "id":
				e.ID = r.PlanID
			case "watch":
				e.WatchID = r.PlanID
			case "tenant":
				e.Scope.TenantID++
			case "site":
				e.Scope.SiteID++
			case "plan":
				e.PlanID = r.ID
			case "assignment":
				e.AssignmentID = r.ID
			case "revision":
				e.Revision++
			case "configuration":
				e.ConfigurationRevision++
			case "kind":
				e.Kind = "attention"
			case "actor":
				e.Actor = "another operator"
			case "grant":
				e.ActorRevision++
			case "key":
				e.RequestKey = r.ID
			case "incident":
				e.IncidentID = r.ID
			case "created":
				e.CreatedAt = e.CreatedAt.Add(time.Second)
			}
			require.ErrorIs(t, s.openUpdateEscalationWire(encrypted, updateEscalationEventPurpose(&e), 131072, &decoded), ErrUpdateEscalationIntegrity)
		})
	}
}
