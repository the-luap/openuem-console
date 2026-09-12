package mdm_views

import (
	"strings"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func UpdateGroupRemovalHistoryPath(plan, assignment string) string {
	return UpdatePlanGroupHistoryPath(plan) + "/" + assignment + "/removals"
}

func UpdateGroupRemovalPreviewPath(plan, assignment string) string {
	return UpdatePlanGroupHistoryPath(plan) + "/" + assignment + "/removal"
}

func updateGroupRemovalFields(p apple.UpdateGroupRemovalPreview) string {
	fields := []string{}
	for _, device := range p.Devices {
		if device.Reason == "" {
			fields = append(fields, device.Selection.DeviceID+":"+device.Selection.PolicyToken)
		}
	}
	return strings.Join(fields, "\n")
}

func updateGroupRemovalCount(p apple.UpdateGroupRemovalPreview) int {
	count := 0
	for _, device := range p.Devices {
		if device.Reason == "" {
			count++
		}
	}
	return count
}

func updateGroupRemovalReason(reason string) string {
	switch reason {
	case "unavailable":
		return "The original enrollment is unavailable in this site. Current device details are withheld."
	case "not_managed":
		return "This original enrollment is no longer managed."
	case "identity_expired":
		return "This original enrollment's device identity has expired."
	case "absent":
		return "This device has no configured update policy to remove."
	case "different":
		return "This device has a different configured update policy. Review it separately on the device page."
	default:
		return "This original device cannot be included in the removal."
	}
}
