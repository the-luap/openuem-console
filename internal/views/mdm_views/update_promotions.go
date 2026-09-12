package mdm_views

import (
	"net/url"
	"strconv"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func UpdatePromotionPath(plan, assignment string) string {
	return UpdatePlanGroupHistoryPath(plan) + "/" + assignment + "/promotion"
}
func UpdatePromotionHistoryPath(plan, assignment string) string {
	return UpdatePlanGroupHistoryPath(plan) + "/" + assignment + "/promotions"
}
func UpdatePromotionGroupChoiceURL(info *partials.CommonInfo, pilot apple.UpdatePlanGroupAssignment, plan apple.UpdatePlan, after string) string {
	q := url.Values{"destination_plan": {plan.ID}, "revision": {strconv.Itoa(plan.Revision)}}
	if after != "" {
		q.Set("after", after)
	}
	return partials.GetNavigationUrl(info, UpdatePromotionPath(pilot.Plan.ID, pilot.ID)+"/groups") + "?" + q.Encode()
}
func updatePromotionReviewURL(info *partials.CommonInfo, pilot apple.UpdatePlanGroupAssignment, plan apple.UpdatePlan, group inventory.DeviceGroup) string {
	q := url.Values{"destination_plan": {plan.ID}, "revision": {strconv.Itoa(plan.Revision)}, "group": {group.ID}, "group_revision": {strconv.Itoa(group.Revision)}}
	return partials.GetNavigationUrl(info, UpdatePromotionPath(pilot.Plan.ID, pilot.ID)+"/review") + "?" + q.Encode()
}
func updatePilotDecision(p apple.UpdatePilotReadiness, id string) apple.UpdatePilotDeviceReadiness {
	for _, d := range p.Devices {
		if d.DeviceID == id {
			return d
		}
	}
	return apple.UpdatePilotDeviceReadiness{DeviceID: id, Reason: "os_unverified"}
}
func updatePilotReason(d apple.UpdatePilotDeviceReadiness) string {
	if d.Ready {
		return "Ready: a fresh OS report meets the original target, with matching policy values and no active exception or reported policy error."
	}
	switch d.Reason {
	case "device_unavailable":
		return "Blocked: the original enrollment is unavailable in this site, inactive or its identity has expired."
	case "exception_active":
		return "Blocked: a temporary update exception is active."
	case "policy_absent":
		return "Blocked: no update policy is currently configured."
	case "policy_different":
		return "Blocked: the current policy values differ from the original pilot."
	case "policy_unverified":
		return "Blocked: the current policy could not be verified."
	case "policy_error":
		return "Blocked: the current policy reports an error. Review the device before promoting the rollout."
	case "update_required":
		return "Blocked: the reported OS still requires the original update."
	case "awaiting_post_exception_report":
		return "Blocked: a fresh OS report is required after the latest exception ended."
	default:
		return "Blocked: a usable, fresh OS report after pilot admission is required."
	}
}
