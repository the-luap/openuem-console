package mdm_views

import "github.com/open-uem/openuem-console/internal/mdm/apple"

func UpdateEscalationPath(plan, assignment string) string {
	return UpdatePlanGroupHistoryPath(plan) + "/" + assignment + "/escalation"
}
func escalationRevision(r *apple.UpdateEscalation) int {
	if r == nil {
		return 0
	}
	return r.ConfigurationRevision
}
func escalationEnableValue(r *apple.UpdateEscalation) string {
	if r != nil && r.Phase == "watching" {
		return "no"
	}
	return "yes"
}
func escalationAction(r *apple.UpdateEscalation) string {
	if r == nil {
		return "Enable console monitoring"
	}
	if r.Phase == "watching" {
		return "Pause monitoring"
	}
	if r.Phase == "blocked" {
		return "Save monitoring change"
	}
	return "Enable and review monitoring authority"
}
func escalationPhase(phase string) string {
	switch phase {
	case "watching":
		return "Monitoring enabled"
	case "paused":
		return "Monitoring paused"
	case "blocked":
		return "Monitoring needs review"
	default:
		return "Monitoring has not been enabled"
	}
}
func escalationState(state string) string {
	switch state {
	case "attention":
		return "Needs attention"
	case "suppressed":
		return "Excluded from escalation"
	case "pending":
		return "Deadline pending"
	default:
		return "Evidence unverified"
	}
}
func escalationReason(reason string) string {
	switch reason {
	case "device_unavailable":
		return "The original enrollment is unavailable, inactive or has an expired identity."
	case "exception_active":
		return "An approved update exception is active."
	case "policy_different":
		return "The configured policy differs from the original assignment."
	case "policy_absent":
		return "No update policy is configured."
	case "policy_unverified":
		return "The current configured policy cannot be verified."
	case "target_reported":
		return "Fresh OS evidence reports the target or a newer version."
	case "os_unverified":
		return "A usable OS report after the original assignment and within the last 24 hours is required."
	case "deadline_unverified":
		return "The original deadline cannot be verified from a fresh reported time zone."
	case "deadline_pending":
		return "The latest estimated occurrence of the original deadline is still pending."
	case "awaiting_post_deadline_report":
		return "A fresh OS report at or after the latest estimated deadline is required."
	case "awaiting_post_exception_report":
		return "A fresh OS report after the exception ended is required."
	case "update_required_after_deadline":
		return "Fresh OS evidence after the estimated deadline still requires the original target, and the configured policy matches."
	case "authority_changed":
		return "The monitoring owner's permissions or scope changed. An authorized operator must review and enable monitoring again."
	case "source_unavailable":
		return "The original assignment or saved evidence could not be verified. Restore the source and review monitoring again."
	default:
		return "No verified reason is available."
	}
}
func escalationEventKind(kind string) string {
	switch kind {
	case "configured":
		return "Monitoring configuration recorded"
	case "attention":
		return "New attention required"
	case "updated":
		return "Assessment changed"
	case "cleared":
		return "No devices remain in this incident"
	case "acknowledged":
		return "Operator acknowledgment recorded"
	case "blocked":
		return "Monitoring stopped for review"
	default:
		return "Update monitoring event"
	}
}
