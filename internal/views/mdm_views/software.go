package mdm_views

import "github.com/open-uem/openuem-console/internal/mdm/apple"

func YesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}

func MacAppState(a apple.MacAppAssignment) string {
	if a.Status == "verified" {
		if a.Operation == "remove" {
			return "Removal observed"
		}
		return "Expected managed app version reported"
	}
	labels := map[string]string{"queued": "Queued for delivery", "sent": "Sent; response pending", "not_now": "Deferred by macOS", "verifying": "Waiting for application observations", "uncertain": "Outcome unknown; another operation is blocked", "drifted": "Current report differs from the requested state", "failed": "Operation failed", "cancelled": "Cancelled before confirmed execution", "expired": "Expired before confirmed execution", "not_managed": "Enrollment ended; history retained"}
	if label, ok := labels[a.Status]; ok {
		return label
	}
	return "State unavailable"
}

func MacAppObservationLabel(value string) string {
	labels := map[string]string{"unknown": "Not established", "absent": "Not reported", "managed": "Managed app", "uninstalled": "Managed app is uninstalled", "installed": "Installed", "pending": "Installation or download pending", "failed": "Installation failed or rejected", "conflict": "Conflicting app records"}
	if label, ok := labels[value]; ok {
		return label
	}
	return "Not established"
}

func MacAppError(value string) string {
	if value == "verification_timeout" {
		return "The Mac has not established the requested app state within one day. Further mutations remain blocked while status checks continue."
	}
	labels := map[string]string{"command_failed": "macOS rejected the command. Its installation effects are not verified.", "installation_failed": "macOS reported an installation failure or rejection.", "command_expired": "The command deadline passed without a terminal response.", "invalid_application_inventory": "The app inventory response could not be used. Request a fresh status.", "delivery_prerequisites_changed": "Approval or device prerequisites changed before delivery.", "cancelled_by_operator": "An operator cancelled the queued or deferred operation.", "deferred_beyond_deadline": "macOS deferred the operation beyond its delivery deadline.", "enrollment_ended": "The enrollment ended. This does not prove that an installer stopped."}
	return labels[value]
}
