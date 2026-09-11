package mdm_views

import (
	"strconv"
	"strings"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

type SoftwareDeviceSearch struct{ Query, Next string }
type SoftwareCatalogSearch struct{ Query, Platform string }

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
