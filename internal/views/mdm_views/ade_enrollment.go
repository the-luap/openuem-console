package mdm_views

import (
	"net/url"
	"strings"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

type ADEEnrollment struct {
	Profiles []apple.ADEEnrollmentProfile
	Targets  []apple.ADETarget
	Next     string
}

func adeTargetPage(server, after string) string {
	return "/ios/ade?" + url.Values{"server": {server}, "target_after": {after}}.Encode()
}

func adeEnrollmentState(state string) string {
	labels := map[string]string{"queued": "Waiting for publication", "publishing": "Publishing to Apple", "published": "Published", "unknown": "Publication outcome unknown", "disabled": "Disabled", "pending": "Waiting", "accepted": "Assignment accepted; verification pending", "observed": "Apple assignment verified", "throttled": "Waiting for Apple's retry deadline", "unavailable": "Apple verification unavailable", "failed": "Failed", "awaiting": "Waiting for MDM configuration", "releasing": "Release requested; awaiting device report", "complete": "MDM configuration hold released", "not_requested": "Configuration hold not requested", "cancelled": "Enrollment ended"}
	if label, ok := labels[state]; ok {
		return label
	}
	return strings.ReplaceAll(Show(state), "_", " ")
}

func adeProfileName(profiles []apple.ADEEnrollmentProfile, id string) string {
	if id == "" {
		return "Clear Apple profile assignment"
	}
	for _, p := range profiles {
		if p.ID == id {
			return p.Name
		}
	}
	return id
}

func adeSetupMessage(a *apple.ADEDeviceEnrollment) string {
	if a.SetupState == "complete" {
		return "The device reports that the MDM configuration hold has ended. This does not confirm completion of every Setup Assistant screen or local account setup."
	}
	if a.SetupState == "failed" {
		return "The configuration release command failed or expired. A retry first requests a fresh device report, then rechecks assigned configuration profiles."
	}
	if a.SetupError == "configuration_pending" {
		return "Waiting for current device and profile inventory and for all assigned configuration profiles to reach their requested state. Resolve failed assignments before setup can continue."
	}
	if a.SetupState == "cancelled" {
		return "This enrollment ended. A new activation requires a separate admission from the Automated Device Enrollment page."
	}
	return "OpenUEM records the device's reported MDM hold state. A delivery acknowledgement alone does not confirm that the hold has ended."
}

func stringsForADEError(code string) string {
	switch code {
	case "publication_uncertain", "publication_interrupted":
		return "Apple's publication outcome could not be confirmed. An explicit retry is required."
	case "push_expired":
		return "Renew the APNs certificate before publishing."
	case "throttled":
		return "Apple requested a later retry."
	case "token_expired", "token_rejected":
		return "Renew and verify this connection's Apple server token."
	case "account_changed":
		return "The Apple server identity no longer matches this connection."
	case "profile_invalid":
		return "The stored enrollment profile could not be validated."
	default:
		return "Apple verification is temporarily unavailable; publication will be retried."
	}
}
