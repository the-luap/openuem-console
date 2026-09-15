package windows_views

import (
	"fmt"
	"net/url"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

type UpdatePolicyDraft struct {
	Form   url.Values           `json:"-" xml:"-" yaml:"-"`
	Policy windows.UpdatePolicy `json:"-" xml:"-" yaml:"-"`
	Error  string
}

func (UpdatePolicyDraft) String() string     { return "[protected Windows policy draft]" }
func (v UpdatePolicyDraft) GoString() string { return v.String() }

func updateTargetScope(info *partials.CommonInfo, device windows.DeviceMetadata) string {
	organization, site := fmt.Sprintf("Organization %d", device.TenantID), fmt.Sprintf("Site %d", device.SiteID)
	for _, t := range info.Tenants {
		if t.ID == device.TenantID {
			organization = t.Description
		}
	}
	for _, s := range info.Sites {
		if s.ID == device.SiteID {
			site = s.Description
		}
	}
	return organization + " / " + site
}

type UpdatePolicyField struct {
	Name, Label, Help string
	Minimum, Maximum  int
	Boolean           bool
}

// Form names match the typed policy JSON fields. Values are validated again by
// UpdatePolicy.Validate and the immutable store/compiler before queue admission.
func UpdatePolicyFields() []UpdatePolicyField {
	return []UpdatePolicyField{
		{Name: "quality_deferral_days", Label: "Quality update deferral (days)", Maximum: 30},
		{Name: "feature_deferral_days", Label: "Feature update deferral (days)", Maximum: 365},
		{Name: "quality_deadline_days", Label: "Quality update deadline (days)", Maximum: 30},
		{Name: "feature_deadline_days", Label: "Feature update deadline (days)", Maximum: 30},
		{Name: "quality_grace_days", Label: "Quality update grace period (days)", Maximum: 7, Help: "Requires a quality update deadline."},
		{Name: "feature_grace_days", Label: "Feature update grace period (days)", Maximum: 7, Help: "Requires a feature update deadline."},
		{Name: "quality_no_auto_reboot", Label: "Wait for quality deadline and grace period before automatic reboot", Boolean: true, Help: "Requires a quality update deadline."},
		{Name: "feature_no_auto_reboot", Label: "Wait for feature deadline and grace period before automatic reboot", Boolean: true, Help: "Requires a feature update deadline."},
		{Name: "active_hours_start", Label: "Active hours start (device-local hour)", Maximum: 23, Help: "Set both endpoints. An overnight range is allowed."},
		{Name: "active_hours_end", Label: "Active hours end (device-local hour)", Maximum: 23, Help: "The nonzero range must fit within the maximum active hours."},
		{Name: "active_hours_maximum", Label: "Maximum active-hours range (hours)", Minimum: 8, Maximum: 18},
		{Name: "notification_level", Label: "Notification level", Maximum: 2, Help: "0: default notifications; 1: restart warnings only; 2: no update notifications."},
		{Name: "exclude_drivers", Label: "Exclude drivers from quality updates", Boolean: true},
	}
}
