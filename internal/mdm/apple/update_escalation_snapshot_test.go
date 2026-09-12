package apple

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func ownedEscalationSnapshot() *UpdateEscalationSnapshot {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	observed := now.Add(-time.Minute)
	latest := now.Add(-90 * time.Minute)
	d := UpdateGroupDeviceProgress{DeviceID: "10000000-0000-4000-8000-000000000001", Availability: "available", PolicyState: "matches", Result: "update_required", RecordedAt: &observed, ReportedVersion: "18.6.2", ReportedBuild: "22G100", ReportSource: "device_information", Deadline: &UpdateDeadlineAssessment{State: "elapsed", Earliest: &latest, Latest: &latest, AssessedAt: now, TimeZone: &TimeZoneObservation{Name: "UTC", Source: "device_information", RecordedAt: observed}}, Exception: &UpdateException{Kind: "resume", CreatedAt: now.Add(-30 * time.Minute)}}
	return escalationSnapshot(assessUpdateGroupEscalation(&UpdateGroupProgress{AssessedAt: now, Devices: []UpdateGroupDeviceProgress{d}}))
}

func TestUpdateEscalationSnapshotRetainsOriginalEvidenceAndSuppressesDiagnostics(t *testing.T) {
	snapshot := ownedEscalationSnapshot()
	wire := escalationSnapshotWire(snapshot)
	decoded, err := decodeEscalationSnapshot(wire, []string{snapshot.Devices[0].Decision.DeviceID})
	require.NoError(t, err)
	require.Equal(t, "18.6.2", decoded.Devices[0].Observation.Version)
	require.Equal(t, "22G100", decoded.Devices[0].Observation.Build)
	require.Equal(t, "attention", decoded.Devices[0].Decision.State)
	require.True(t, decoded.Devices[0].Deadline.Latest.Equal(*snapshot.Devices[0].Deadline.Latest))
	require.True(t, decoded.Devices[0].ExceptionEndedAt.Equal(*snapshot.Devices[0].ExceptionEndedAt))
	for _, v := range []any{snapshot, snapshot.Devices[0], snapshot.Devices[0].Decision} {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(raw))
		require.NotContains(t, fmt.Sprintf("%#v", v), "18.6.2")
	}
}

func TestUpdateEscalationSnapshotRejectsInconsistentEvidence(t *testing.T) {
	for _, state := range []string{"target", "reason", "future-os", "invalid-os", "old-zone", "missing-zone", "deadline", "ambiguity", "exception", "missing-packet", "duplicate-original"} {
		t.Run(state, func(t *testing.T) {
			snapshot := ownedEscalationSnapshot()
			wire := escalationSnapshotWire(snapshot)
			original := []string{snapshot.Devices[0].Decision.DeviceID}
			w := &wire.Devices[0]
			switch state {
			case "target":
				w.DeviceID = "10000000-0000-4000-8000-000000000002"
			case "reason":
				w.Reason = "target_reported"
			case "future-os":
				future := wire.AssessedAt.Add(time.Hour)
				w.RecordedAt = &future
			case "invalid-os":
				w.Version = "invalid"
			case "old-zone":
				old := wire.AssessedAt.Add(-25 * time.Hour)
				w.TimeZoneRecordedAt = &old
			case "missing-zone":
				w.TimeZoneRecordedAt = nil
			case "deadline":
				future := wire.AssessedAt.Add(time.Hour)
				w.Latest, w.Earliest = &future, &future
			case "ambiguity":
				w.Ambiguous = true
			case "exception":
				w.ExceptionEndedAt = &wire.AssessedAt
			case "missing-packet":
				w.RecordedAt = nil
			case "duplicate-original":
				original = append(original, original[0])
				wire.Devices = append(wire.Devices, wire.Devices[0])
			}
			_, err := decodeEscalationSnapshot(wire, original)
			require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
		})
	}
}
