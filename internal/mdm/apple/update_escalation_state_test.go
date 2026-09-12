package apple

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateEscalationRetainsUnknownOpenTargetsWithoutReopeningAcknowledgedWork(t *testing.T) {
	one := "10000000-0000-4000-8000-000000000001"
	two := "10000000-0000-4000-8000-000000000002"
	decisions := []UpdateEscalationDecision{{DeviceID: one, State: "attention"}, {DeviceID: two, State: "unverified"}}
	open, awaiting, added, err := mergeUpdateEscalationTargets(nil, decisions)
	require.NoError(t, err)
	require.Equal(t, []string{one}, open)
	require.Empty(t, awaiting)
	require.True(t, added)
	decisions[0].State = "unverified"
	open, awaiting, added, err = mergeUpdateEscalationTargets(open, decisions)
	require.NoError(t, err)
	require.Equal(t, []string{one}, open)
	require.Equal(t, open, awaiting)
	require.False(t, added)
	decisions[0].State = "attention"
	open, awaiting, added, err = mergeUpdateEscalationTargets(open, decisions)
	require.NoError(t, err)
	require.Equal(t, []string{one}, open)
	require.Empty(t, awaiting)
	require.False(t, added)
	decisions[1].State = "attention"
	open, _, added, err = mergeUpdateEscalationTargets(open, decisions)
	require.NoError(t, err)
	require.Equal(t, []string{one, two}, open)
	require.True(t, added)
	decisions[0].State = "suppressed"
	open, _, added, err = mergeUpdateEscalationTargets(open, decisions)
	require.NoError(t, err)
	require.Equal(t, []string{two}, open)
	require.False(t, added)
	decisions[1].State = "pending"
	open, _, added, err = mergeUpdateEscalationTargets(open, decisions)
	require.NoError(t, err)
	require.Empty(t, open)
	require.False(t, added)
	decisions[0].State = "attention"
	_, _, added, err = mergeUpdateEscalationTargets(open, decisions)
	require.NoError(t, err)
	require.True(t, added)
}

func TestUpdateEscalationRejectsUnknownOrDuplicatedOriginalTargets(t *testing.T) {
	one := "10000000-0000-4000-8000-000000000001"
	two := "10000000-0000-4000-8000-000000000002"
	valid := UpdateEscalationDecision{DeviceID: one, State: "attention"}
	for _, tc := range []struct {
		previous  []string
		decisions []UpdateEscalationDecision
	}{
		{nil, nil},
		{[]string{two}, []UpdateEscalationDecision{valid}},
		{[]string{one, one}, []UpdateEscalationDecision{valid}},
		{nil, []UpdateEscalationDecision{valid, valid}},
		{nil, []UpdateEscalationDecision{{DeviceID: one, State: "unknown"}}},
		{nil, []UpdateEscalationDecision{{DeviceID: "invalid", State: "attention"}}},
	} {
		_, _, _, err := mergeUpdateEscalationTargets(tc.previous, tc.decisions)
		require.ErrorIs(t, err, ErrUpdateEscalationIntegrity)
	}
}
