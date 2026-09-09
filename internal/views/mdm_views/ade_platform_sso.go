package mdm_views

import "github.com/open-uem/openuem-console/internal/mdm/apple"

func adePlatformSSOMessage(r *apple.ADEPlatformSSOStatus, setup string) string {
	if setup == "complete" {
		return "The Mac reported that the MDM setup hold ended. This panel retains the original enrollment requirement."
	}
	if r.Error == "provider_application_mismatch" {
		return "The required provider application differs from the reviewed version. Setup release remains held."
	}
	if r.ProfileVerified {
		return "The retained profile revision is verified by current inventory."
	}
	switch r.Error {
	case "profile_revision_mismatch":
		return "The assigned profile revision differs from the reviewed setup requirement. Send the retained revision again while setup remains held."
	case "profile_attention_required":
		return "The retained profile is missing or its installation needs attention. Review profile commands and current inventory before resending it."
	case "profile_prerequisites_required":
		return "Profile prerequisites are not ready. Check this Mac's platform, enrollment capabilities and current security inventory."
	default:
		return "Waiting for current inventory to verify the retained profile revision."
	}
}
