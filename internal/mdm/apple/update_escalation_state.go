package apple

import (
	"errors"
	"slices"
)

var ErrUpdateEscalationIntegrity = errors.New("Apple update escalation evidence is unavailable")

// Unknown evidence retains an existing open target without creating a new
// alert. Suppression or a pending deadline removes that target from the open
// set without claiming installation. Only newly actionable targets should
// require a new acknowledgment; repeated checks are not new incidents.
func mergeUpdateEscalationTargets(previous []string, decisions []UpdateEscalationDecision) (open, awaiting []string, added bool, err error) {
	if len(previous) > 100 || len(decisions) < 1 || len(decisions) > 100 {
		return nil, nil, false, ErrUpdateEscalationIntegrity
	}
	prior := map[string]bool{}
	for _, id := range previous {
		if !profileRevisionUUID(id) || prior[id] {
			return nil, nil, false, ErrUpdateEscalationIntegrity
		}
		prior[id] = true
	}
	seen := map[string]bool{}
	for _, decision := range decisions {
		if !profileRevisionUUID(decision.DeviceID) || seen[decision.DeviceID] {
			return nil, nil, false, ErrUpdateEscalationIntegrity
		}
		seen[decision.DeviceID] = true
		switch decision.State {
		case "attention":
			open = append(open, decision.DeviceID)
			added = added || !prior[decision.DeviceID]
		case "unverified":
			if prior[decision.DeviceID] {
				open = append(open, decision.DeviceID)
				awaiting = append(awaiting, decision.DeviceID)
			}
		case "suppressed", "pending":
		default:
			return nil, nil, false, ErrUpdateEscalationIntegrity
		}
	}
	for id := range prior {
		if !seen[id] {
			return nil, nil, false, ErrUpdateEscalationIntegrity
		}
	}
	slices.Sort(open)
	slices.Sort(awaiting)
	return open, awaiting, added, nil
}
