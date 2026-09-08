package mdm_views

import "github.com/open-uem/openuem-console/internal/mdm/apple"

func IdentityRenewalState(r apple.IdentityRenewal) string {
	switch r.Status {
	case "queued":
		return "Replacement profile queued or awaiting certificate request"
	case "issued":
		if r.TokenUpdatedAt != nil {
			return "New push data received; awaiting command-channel confirmation"
		}
		return "Certificate issued; awaiting device confirmation"
	case "confirmed":
		return "New identity in use"
	default:
		return StateLabel(r.Status)
	}
}

func IdentityRenewalHelp(code string) string {
	switch code {
	case "identity_expired":
		return "The device identity has expired. Remove the existing enrollment profile on the device and enroll it again."
	case "profile_inventory_required":
		return "Waiting for enrollment profile metadata. Refresh profile inventory while the device is online. Older enrollments without saved metadata need iOS/iPadOS 17 or later to report the required payload UUIDs."
	case "profile_metadata_invalid":
		return "The saved enrollment profile metadata is inconsistent. Review the server enrollment record before retrying."
	case "push_certificate_expired":
		return "Renew the organization's Apple push certificate before device identity renewal can start."
	case "enrollment_settings_changed":
		return "The server address or Apple push topic differs from the installed enrollment. Restore the original enrollment settings before retrying."
	case "authority_unavailable":
		return "The enrollment certificate authority is unavailable. Check the server key configuration."
	case "authority_expiring":
		return "The enrollment certificate authority expires too soon to extend this identity. Plan a CA migration or device re-enrollment before expiry."
	case "command_failed":
		return "The device did not complete the replacement profile installation. Review the command error below. The previous identity remains active until its expiry; automatic retries wait at least six hours."
	case "authorization_expired":
		return "The certificate request deadline passed. Automatic renewal will retry while the current identity remains valid."
	case "candidate_expired":
		return "The issued certificate expired before the device confirmed it. Check the current identity expiry and enroll the device again if needed."
	case "enrollment_inactive":
		return "Renewal stopped because this enrollment is no longer active."
	default:
		return "Identity renewal needs attention. Review the enrollment and command status."
	}
}
