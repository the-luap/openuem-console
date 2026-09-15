package mdm_views

func UpdateGroupProgressPath(plan, assignment string) string {
	return UpdatePlanGroupHistoryPath(plan) + "/" + assignment + "/progress"
}
func updateGroupProgressResult(result string) string {
	switch result {
	case "target_reported":
		return "Target or newer OS reported"
	case "update_required":
		return "Update still required"
	default:
		return "Result unverified"
	}
}
func updateGroupProgressReason(reason string) string {
	switch reason {
	case "device_unavailable":
		return "The original native enrollment is unavailable in this site, inactive or has an expired identity."
	case "no_report":
		return "No usable OS observation is available. Wait for a fresh device inventory or declarative status report."
	case "before_assignment":
		return "This OS observation was recorded before the original assignment. It does not verify a result after admission."
	case "stale_report":
		return "This OS observation is more than 24 hours old. A fresh report is required."
	case "future_report":
		return "The observation timestamp is later than this assessment. Review the server clock and wait for fresh evidence."
	case "missing_build":
		return "The reported version matches the target, but its build was not reported together with that version. A fresh matching build is required."
	case "invalid_report":
		return "The OS observation is invalid. Wait for a valid device report."
	default:
		return ""
	}
}
func updateGroupPolicyStatus(status string) string {
	switch status {
	case "pending":
		return "Pending"
	case "enforced":
		return "Declaration reported active"
	case "waiting":
		return "Waiting"
	case "downloading":
		return "Downloading"
	case "prepared":
		return "Prepared"
	case "preparing":
		return "Preparing"
	case "installing":
		return "Installing"
	case "idle":
		return "Idle"
	case "failed":
		return "Failure reported"
	case "unavailable":
		return "Release unavailable"
	default:
		return "Other reported state"
	}
}
func updateGroupNotificationStatus(status string) string {
	switch status {
	case "queued":
		return "Queued"
	case "sent":
		return "Sent"
	case "acknowledged":
		return "Acknowledged"
	case "failed":
		return "Failed"
	case "not_now":
		return "Device deferred processing"
	case "expired":
		return "Expired"
	case "cancelled", "canceled":
		return "Canceled"
	default:
		return "Unavailable"
	}
}
func updateGroupReportSource(source string) string {
	switch source {
	case "device_information":
		return "Device Information response"
	case "declarative_status":
		return "Declarative status report"
	default:
		return "Unavailable"
	}
}
