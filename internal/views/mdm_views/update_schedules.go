package mdm_views

import "time"

func UpdateSchedulePath(plan string) string { return "/ios/update-plans/" + plan + "/schedules" }
func updateScheduleDefaultTime() string {
	return time.Now().UTC().Add(15 * time.Minute).Format("2006-01-02T15:04:05Z")
}
func updateScheduleStatus(phase string) string {
	switch phase {
	case "scheduled":
		return "Scheduled"
	case "waiting":
		return "Waiting to retry"
	case "activated":
		return "Activated"
	case "blocked":
		return "Blocked; new review required"
	case "expired":
		return "Activation window expired"
	case "canceled":
		return "Canceled"
	default:
		return "Unavailable"
	}
}
func updateScheduleReason(reason string) string {
	switch reason {
	case "authority_changed":
		return "The creator's permissions changed before activation. Review the current selection and create a new schedule."
	case "scope_changed":
		return "The original site no longer belongs to the same organization."
	case "sources_changed":
		return "The enabled inventory sources changed. Review the group again before scheduling."
	case "review_changed":
		return "The plan, group, eligible selection or existing device policies changed. Review current state and create a new schedule."
	case "source_unavailable":
		return "A required plan, group or device source is unavailable. Review current state before scheduling again."
	case "activation_conflict":
		return "The activation could not retain the original reviewed request. Create a new schedule after reviewing current state."
	case "activation_window_expired":
		return "The activation window ended without a committed assignment. No device policies were changed by this schedule."
	case "canceled_by_operator":
		return "An operator canceled this schedule before activation."
	case "temporarily_unavailable":
		return "Temporary database contention prevented admission. The complete selection will be checked again on the next attempt."
	default:
		return ""
	}
}
