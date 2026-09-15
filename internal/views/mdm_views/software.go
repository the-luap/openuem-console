package mdm_views

import (
	"strconv"
	"strings"

	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

type SoftwareDeviceSearch struct{ Query, Next string }
type SoftwareCatalogSearch struct{ Query, Platform string }

func WindowsSoftwareOperation(operation string) string {
	if operation == "remove" {
		return "Removal request"
	}
	return "Installation request"
}

func WindowsSoftwareRequestState(status string) string {
	switch status {
	case "prepared":
		return "Prepared; explicit review and dispatch required"
	case "dispatched":
		return "Dispatched; see delivery and observed outcome below"
	case "cancelled":
		return "Cancelled before delivery"
	case "expired":
		return "Expired without delivery"
	default:
		return "Request state unavailable"
	}
}

func WindowsSoftwareDispatchSupported(v apple.SoftwareVersion) bool {
	return (v.Kind == "windows-msi" || v.Kind == "windows-exe" || v.Kind == "windows-burn") && (v.Architecture == "x86_64" || v.Architecture == "arm64")
}

func WindowsSoftwareDispatchState(task registry.SoftwareTaskStatus) string {
	if task.Outcome != nil {
		switch task.Outcome.State {
		case "observed":
			if task.Operation == "remove" {
				return "Removal observed on the device"
			}
			return "Exact approved version observed on the device"
		case "not_started":
			return "Not started; device checks rejected execution"
		case "failed":
			return "Installer failed; review the reported observations"
		case "restart_required":
			if task.ReconciliationID != "" {
				return "Original execution required a restart; a later software check released the reservation"
			}
			return "Restart required; completion is not established and another operation is blocked"
		case "uncertain":
			if task.ReconciliationID != "" {
				return "Original execution remains uncertain; a later software check released the reservation"
			}
			return "Outcome uncertain; another operation is blocked"
		}
	}
	switch task.Status {
	case "pending":
		return "Queued; waiting for the agent"
	case "delivered":
		return "Delivered; execution result pending"
	case "cancelled":
		return "Cancelled before delivery"
	case "expired":
		return "Expired before delivery"
	case "uncertain":
		if task.ReconciliationID != "" {
			return "Original execution remains uncertain; a later software check released the reservation"
		}
		return "Delivery expired; execution is uncertain and another operation is blocked"
	}
	return "Outcome unavailable"
}

func WindowsSoftwareCheckEligible(task registry.SoftwareTaskStatus) bool {
	return task.DeliveredAt != nil && task.ReconciliationID == "" && (task.Status == "uncertain" || task.Status == "restart_required")
}

func WindowsSoftwareCheckState(check registry.SoftwareReconciliationStatus) string {
	if check.Outcome != nil {
		switch check.Outcome.State {
		case "observed":
			return "Requested software state observed after a later Windows restart"
		case "drifted":
			return "Different software state observed after a later Windows restart"
		case "unknown":
			return "Later Windows restart verified; exact software state could not be established"
		case "waiting_for_boot":
			return "No later Windows restart established for this check"
		case "unavailable":
			return "Required protected history or restart evidence was unavailable"
		}
	}
	switch check.Status {
	case "pending":
		return "Queued; waiting for a compatible agent"
	case "delivered":
		return "Delivered; read-only observation pending"
	case "cancelled":
		return "Cancelled before delivery"
	case "expired":
		return "Check expired; the original reservation is unchanged"
	}
	return "Software check state unavailable"
}

func WindowsSoftwareOutcomeReason(reason string) string {
	labels := map[string]string{"incompatible": "Device architecture or Windows version is incompatible", "version_conflict": "A different version was observed", "preflight": "Installer metadata could not be verified", "download": "Approved download could not be completed", "signature": "Native installer signature could not be verified", "changed_file": "The staged file changed", "execution": "Installer process did not complete successfully", "detection": "Exact software state could not be established", "interrupted": "Execution was interrupted", "journal": "Protected result history is unavailable", "unavailable": "Execution is currently unavailable"}
	if label, ok := labels[reason]; ok {
		return label
	}
	return "No additional reason reported"
}

func SoftwareVersionLabel(platform string) string {
	if platform == "macos" {
		return "Exact bundle version"
	}
	return "Approved package version"
}

func SoftwarePackageKind(kind string) string {
	switch kind {
	case "windows-winget":
		return "Windows · WinGet"
	case "windows-msi":
		return "Windows · MSI"
	case "windows-burn":
		return "Windows · Burn"
	case "windows-exe":
		return "Windows · EXE"
	default:
		return "macOS · PKG"
	}
}

func SoftwareExitCodes(codes []uint32) string {
	values := make([]string, 0, len(codes))
	for _, code := range codes {
		values = append(values, strconv.FormatUint(uint64(code), 10))
	}
	if len(values) == 0 {
		return "None"
	}
	return strings.Join(values, ", ")
}

func MacAppPriorState(a apple.MacAppPriorAttempt) string {
	if a.Recovery != nil {
		return "Old outcome unknown; stopping evidence recorded"
	}
	return MacAppState(apple.MacAppAssignment{Status: a.Status, Operation: a.Operation})
}

func MacAppEvidenceLabel(evidence string) string {
	if evidence == "device_erased" {
		return "Mac erased after dispatch"
	}
	if evidence == "installer_stopped" {
		return "Earlier operation confirmed stopped"
	}
	return "Evidence unavailable"
}

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
	if value == "previous_enrollment_unresolved" {
		return "Delivery was cancelled because an earlier enrollment has an unresolved operation or an active duplicate identity. Review previous enrollments before explicitly requesting another installation."
	}
	if value == "ade_revision_replaced" {
		return "The previous attempt was cancelled by an explicit correction of the required setup revision."
	}
	if value == "verification_timeout" {
		return "The Mac has not established the requested app state within one day. Further mutations remain blocked while status checks continue."
	}
	labels := map[string]string{"command_failed": "macOS rejected the command. Its installation effects are not verified.", "installation_failed": "macOS reported an installation failure or rejection.", "command_expired": "The command deadline passed without a terminal response.", "invalid_application_inventory": "The app inventory response could not be used. Request a fresh status.", "delivery_prerequisites_changed": "Approval or device prerequisites changed before delivery.", "cancelled_by_operator": "An operator cancelled the queued or deferred operation.", "deferred_beyond_deadline": "macOS deferred the operation beyond its delivery deadline.", "enrollment_ended": "The enrollment ended. This does not prove that an installer stopped."}
	return labels[value]
}
