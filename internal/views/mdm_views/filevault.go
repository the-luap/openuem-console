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

func FileVaultRotationPending(v *apple.FileVault) bool {
	return v != nil && v.Rotation != nil && (v.Rotation.Status == "queued" || v.Rotation.Status == "uncertain")
}

func FileVaultRotationState(v *apple.FileVault) string {
	if v == nil || v.Rotation == nil {
		return "No rotation requested"
	}
	switch v.Rotation.Status {
	case "queued":
		return "Waiting for the Mac to replace its recovery key"
	case "rotated":
		return "New recovery key stored and validated on " + When(v.Rotation.CompletedAt)
	case "unverified":
		return "New recovery key stored; validate it against the Mac volume"
	case "uncertain":
		if !v.Rotation.ExecutionStopped {
			return "The result is uncertain and the agent has not confirmed that the command stopped. Key validation and another rotation remain blocked. After an interrupted agent, recovery may require a Mac restart and a report from the current agent. Retained recovery keys remain available."
		}
		return "The command has stopped, but its result is uncertain. Refresh security inventory, then validate the latest stored key. Another rotation remains blocked."
	case "resolved":
		return "Current recovery key independently validated; the uncertain attempt is resolved"
	case "invalid":
		return "The previous key did not unlock the volume. Rotation did not start. Refresh escrow and validate the current key."
	case "unavailable":
		return "The Mac could not start rotation. Check agent connectivity and validate the current key before retrying."
	case "unsupported":
		return "Rotation requires the current root Mac agent"
	case "expired":
		return "The request expired before delivery to the Mac"
	case "superseded":
		return "Returned key retained in history; a newer recovery observation remains current"
	case "rejected":
		return "The rotation response could not be authenticated. Recovery evidence is retained for investigation."
	default:
		return "Rotation cancelled because device authority, association or escrow policy changed"
	}
}
