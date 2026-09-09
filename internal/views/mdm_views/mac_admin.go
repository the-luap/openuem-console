package mdm_views

func macAdminState(value string) string {
	labels := map[string]string{"planned": "Waiting for setup inventory", "queued": "Queued", "sent": "Sent; response pending", "not_now": "Deferred by macOS", "accepted": "Account configuration acknowledged", "acknowledged": "Password command acknowledged", "uncertain": "Outcome unknown", "unknown": "Not yet reported", "present": "Account reported", "missing": "Configured account absent from report", "conflict": "Account identity conflict", "failed": "Failed; password outcome unverified", "expired": "Expired before confirmed execution", "cancelled": "Cancelled"}
	if label, ok := labels[value]; ok {
		return label
	}
	return Show(value)
}
func macAdminError(value string) string {
	switch value {
	case "setup_ended":
		return "Setup ended before account configuration could be sent. A new ADE enrollment is required."
	case "enrollment_ended":
		return "Management ended. Retained credentials remain available for recovery."
	case "history_limit":
		return "This enrollment reached the retained password limit. Automatic rotation has stopped."
	case "delivery_changed":
		return "Delivery prerequisites changed. Refresh inventory and check the current setup state."
	case "command_failed":
		return "macOS reported a command failure. Retained credentials must be treated as unverified."
	case "uncertain":
		return "The sent command expired without a terminal response. Further password changes are blocked."
	default:
		return "The administrator operation did not complete. Check command state and current inventory."
	}
}
