package mdm_views

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

type ProfileGroupChoice struct {
	Organization                    bool
	ProfileID, ProfileName, Desired string
	Revision                        int
}

func profileGroupSiteSelected(info *partials.CommonInfo) bool {
	site, err := strconv.Atoi(info.SiteID)
	return err == nil && site > 0
}

func ProfileGroupChoiceURL(info *partials.CommonInfo, choice ProfileGroupChoice, after string) string {
	q := url.Values{"revision": {strconv.Itoa(choice.Revision)}, "desired": {choice.Desired}}
	if choice.Organization {
		q.Set("source", "organization")
	}
	if after != "" {
		q.Set("after", after)
	}
	return partials.GetNavigationUrl(info, "/ios/configurations/"+choice.ProfileID+"/groups") + "?" + q.Encode()
}

func profileGroupPreviewURL(info *partials.CommonInfo, choice ProfileGroupChoice, group inventory.DeviceGroup) string {
	q := url.Values{"revision": {strconv.Itoa(choice.Revision)}, "desired": {choice.Desired}, "group_revision": {strconv.Itoa(group.Revision)}}
	if choice.Organization {
		q.Set("source", "organization")
	}
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

func profileOrganizationGroupsAllowed(info *partials.CommonInfo) bool {
	tenant, err := strconv.Atoi(info.TenantID)
	return err == nil && tenant > 0 && info.Principal.Can(access.ReadDevices, access.Scope{TenantID: tenant})
}
func profileGroupSourceChoiceURL(info *partials.CommonInfo, choice ProfileGroupChoice, organization bool) string {
	choice.Organization = organization
	return ProfileGroupChoiceURL(info, choice, "")
}
func profileGroupSourceKind(scope apple.Scope) string {
	if scope.TenantID > 0 && scope.SiteID == 0 {
		return "organization"
	}
	return "site"
}
func profileGroupManageURL(info *partials.CommonInfo, organization bool) string {
	if organization {
		return "/tenant/" + info.TenantID + "/device-groups"
	}
	return partials.GetNavigationUrl(info, "/device-groups")
}
