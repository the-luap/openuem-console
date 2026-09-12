package apple

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestUpdatePilotEvidenceCapturesLockedOriginalPacketAndAdmissionBounds(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	ownedPilotOSReport(t, f, map[string]any{"version": "18.7.1", "build-version": "22H100"})
	tx, err := f.store.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	require.NoError(t, updateExceptionAuthority(ctx, tx, f.permissions, "operator", f.scope))
	progress, err := f.store.assessUpdateGroupProgressTransaction(ctx, tx, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	proof, err := f.store.captureUpdatePilotEvidence(ctx, tx, assessUpdatePilotReadiness(progress))
	require.NoError(t, err)
	require.Len(t, proof.Devices, 1)
	require.Equal(t, f.device.ID, proof.Devices[0].DeviceID)
	require.Equal(t, "18.7.1", proof.Devices[0].Observation.Version)
	require.Equal(t, "22H100", proof.Devices[0].Observation.Build)
	require.Equal(t, "declarative_status", proof.Devices[0].Observation.Source)
	require.NoError(t, validateUpdatePilotEvidence(decodePilotEvidence(pilotEvidenceWire(proof)), original, proof.AssessedAt))
	for _, condition := range []string{"missing-device", "extra-device", "foreign-device", "policy-token", "missing-build", "different-build", "old-report", "future-report", "stale-at-admission", "expired-at-admission", "before-exception-end", "assessment-after-admission"} {
		t.Run(condition, func(t *testing.T) {
			e := decodePilotEvidence(pilotEvidenceWire(proof))
			at := e.AssessedAt
			switch condition {
			case "missing-device":
				e.Devices = nil
			case "extra-device":
				e.Devices = append(e.Devices, e.Devices[0])
			case "foreign-device":
				e.Devices[0].DeviceID = uuid.NewString()
			case "policy-token":
				e.Devices[0].PolicyToken = strings.Repeat("a", 64)
			case "missing-build":
				e.Devices[0].Observation.Build = ""
			case "different-build":
				e.Devices[0].Observation.Build = "22H999"
			case "old-report":
				e.Devices[0].Observation.RecordedAt = original.CreatedAt.Add(-time.Second)
			case "future-report":
				e.Devices[0].Observation.RecordedAt = e.AssessedAt.Add(time.Second)
			case "stale-at-admission":
				at = at.Add(25 * time.Hour)
			case "expired-at-admission":
				e.Devices[0].IdentityExpiresAt = e.AssessedAt.Add(time.Second)
				require.NoError(t, validateUpdatePilotEvidence(e, original, at))
				at = at.Add(time.Second)
			case "before-exception-end":
				ended := e.AssessedAt
				e.Devices[0].ExceptionEndedAt = &ended
			case "assessment-after-admission":
				at = at.Add(-time.Second)
			}
			require.ErrorIs(t, validateUpdatePilotEvidence(e, original, at), ErrUpdatePromotionIntegrity)
		})
	}
	for _, value := range []any{proof, proof.Devices[0]} {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(raw))
		require.NotContains(t, fmt.Sprintf("%#v", value), f.device.ID)
	}
	require.NoError(t, tx.Commit())
}
