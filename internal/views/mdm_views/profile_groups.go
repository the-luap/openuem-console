package mdm_views

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

type ProfileGroupChoice struct {
	ProfileID, ProfileName, Desired string
	Revision                        int
}

func profileGroupSiteSelected(info *partials.CommonInfo) bool {
	site, err := strconv.Atoi(info.SiteID)
	return err == nil && site > 0
}

func ProfileGroupChoiceURL(info *partials.CommonInfo, choice ProfileGroupChoice, after string) string {
	q := url.Values{"revision": {strconv.Itoa(choice.Revision)}, "desired": {choice.Desired}}
	if after != "" {
		q.Set("after", after)
	}
	return partials.GetNavigationUrl(info, "/ios/configurations/"+choice.ProfileID+"/groups") + "?" + q.Encode()
}

func profileGroupPreviewURL(info *partials.CommonInfo, choice ProfileGroupChoice, group inventory.DeviceGroup) string {
	q := url.Values{"revision": {strconv.Itoa(choice.Revision)}, "desired": {choice.Desired}, "group_revision": {strconv.Itoa(group.Revision)}}
	return partials.GetNavigationUrl(info, "/ios/configurations/"+choice.ProfileID+"/groups/"+group.ID+"/preview") + "?" + q.Encode()
}

func ProfileGroupHistoryPath(profile string) string {
	return "/ios/configurations/" + profile + "/group-assignments"
}

func profileGroupAction(desired string) string {
	if desired == "installed" {
		return "Apply profile"
	}
	if desired == "removed" {
		return "Remove profile"
	}
	return "Action unavailable"
}

func profileGroupDeviceFields(preview apple.ProfileGroupPreview) string {
	ids := make([]string, len(preview.Targets))
	for i, target := range preview.Targets {
		ids[i] = target.DeviceID
	}
	return strings.Join(ids, "\n")
}

func profileGroupExclusion(reason string) string {
	switch reason {
	case "not_apple_mdm":
		return "This member is not managed through native Apple MDM."
	case "apple_channel_unavailable":
		return "The native Apple management channel is no longer available in this site."
	case "profile_prerequisite":
		return "Profile prerequisites or reserved settings prevent this assignment. Review this device's inventory and existing profiles."
	case "ade_owned":
		return "An active automated enrollment requirement owns this profile. Review its setup workflow."
	default:
		return "This member cannot receive the selected action."
	}
}
