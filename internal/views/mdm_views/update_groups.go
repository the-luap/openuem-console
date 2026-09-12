package mdm_views

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func UpdatePlanGroupHistoryPath(id string) string {
	return "/ios/update-plans/" + id + "/group-assignments"
}
func UpdatePlanGroupChoiceURL(info *partials.CommonInfo, plan apple.UpdatePlan, after string) string {
	q := url.Values{"revision": {strconv.Itoa(plan.Revision)}}
	if after != "" {
		q.Set("after", after)
	}
	return partials.GetNavigationUrl(info, "/ios/update-plans/"+plan.ID+"/groups") + "?" + q.Encode()
}
func updatePlanGroupPreviewURL(info *partials.CommonInfo, plan apple.UpdatePlan, group inventory.DeviceGroup) string {
	return partials.GetNavigationUrl(info, "/ios/update-plans/"+plan.ID+"/groups/"+group.ID+"/preview") + "?" + url.Values{"revision": {strconv.Itoa(plan.Revision)}, "group_revision": {strconv.Itoa(group.Revision)}}.Encode()
}
func updatePlanGroupFields(preview apple.UpdatePlanGroupPreview) string {
	fields := make([]string, len(preview.Targets))
	for i, target := range preview.Targets {
		fields[i] = target.Selection.DeviceID + ":" + target.Selection.PolicyToken
	}
	return strings.Join(fields, "\n")
}
func updatePlanGroupExclusion(reason string) string {
	switch reason {
	case "not_apple_mdm":
		return "This member is not managed through native Apple MDM."
	case "apple_channel_unavailable":
		return "This member has no current native Apple MDM channel in this site."
	case "different_platform":
		return "This member uses a different platform from the reviewed plan."
	case "update_prerequisite":
		return "This device does not meet the plan's update prerequisites. Review its current inventory and update authorization."
	case "release_unavailable":
		return "This exact release is unavailable for this device in the current Apple catalog, or the catalog needs a refresh."
	default:
		return "This member cannot receive the reviewed update plan."
	}
}
