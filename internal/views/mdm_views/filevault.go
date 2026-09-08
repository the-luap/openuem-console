package mdm_views

import (
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func FileVaultState(phase string) string {
	switch phase {
	case "preflight":
		return "Checking existing profiles"
	case "installing_escrow":
		return "Installing recovery escrow profile"
	case "verifying_escrow":
		return "Confirming recovery escrow profile"
	case "installing_enable":
		return "Installing deferred encryption profile"
	case "verifying_enable":
		return "Confirming encryption profile"
	case "active":
		return "Profiles confirmed"
	case "removing_enable", "verifying_enable_removal", "removing_escrow", "verifying_removal":
		return "Removing management profiles"
	case "removed":
		return "Management profiles removed"
	case "not_managed":
		return "Enrollment no longer managed"
	case "failed":
		return "Action required"
	default:
		return "Not configured"
	}
}

func FileVaultHelp(code string) string {
	switch code {
	case "":
		return ""
	case "conflicting_profile":
		return "Another FileVault profile or an unexpected profile revision is installed. Resolve the conflict, then retry."
	case "escrow_profile_missing":
		return "The Mac did not confirm the managed recovery escrow profile. Encryption activation was not queued."
	case "security_inventory_required":
		return "Refresh device and security inventory, then retry the policy."
	case "profile_missing", "profile_drifted":
		return "The installed profiles differ from this policy. Inspect the Mac and retry after resolving the difference."
	case "profile_still_present":
		return "The Mac still reports a FileVault management profile. Retry removal."
	case "invalid_recovery_envelope":
		return "The latest recovery envelope could not be accepted. Previously stored keys remain available."
	case "recovery_history_full":
		return "Recovery history has reached its limit. Previously stored keys remain available."
	default:
		return "The Mac did not complete the requested action. Check connectivity and retry the policy."
	}
}

func FileVaultEncryption(d *apple.Device) string {
	if !d.SecurityFresh(time.Now()) {
		return "Refresh security inventory"
	}
	if enabled, ok := d.SecurityInventory["FDE_Enabled"].(bool); ok {
		if enabled {
			return "Enabled, reported by macOS"
		}
		return "Not enabled, reported by macOS"
	}
	return "Not yet reported"
}

func FileVaultValidationState(v *apple.FileVault) string {
	if v == nil || v.Validation == nil {
		if v != nil && v.VerifiedAt != nil {
			return "Last validated on " + When(v.VerifiedAt)
		}
		return "Not yet validated against the Mac volume"
	}
	switch v.Validation.Status {
	case "queued":
		return "Waiting for the Mac to validate the current key"
	case "valid":
		return "Validated on " + When(v.Validation.CompletedAt)
	case "invalid":
		return "The Mac reported that this key does not unlock its volume"
	case "unavailable":
		return "The Mac could not complete the check. Inspect the agent and retry."
	case "unsupported":
		return "This check requires the current root Mac agent"
	case "expired":
		return "The verification request expired. Check agent connectivity and retry."
	case "rejected":
		return "The verification response could not be authenticated. Retry with the current agent."
	case "superseded":
		return "A newer recovery key replaced this request"
	default:
		return "Verification cancelled because the device or agent connection changed"
	}
}
