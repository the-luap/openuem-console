package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

var ErrUpdatePolicy = errors.New("invalid or unsupported native Windows update policy")

// UpdatePolicy is explicit intent. Nil leaves a setting unmanaged; zero remains
// an actual configured value. No compiler default silently changes device policy.
type UpdatePolicy struct {
	QualityDeferralDays *int  `json:"quality_deferral_days,omitempty"`
	FeatureDeferralDays *int  `json:"feature_deferral_days,omitempty"`
	QualityDeadlineDays *int  `json:"quality_deadline_days,omitempty"`
	FeatureDeadlineDays *int  `json:"feature_deadline_days,omitempty"`
	QualityGraceDays    *int  `json:"quality_grace_days,omitempty"`
	FeatureGraceDays    *int  `json:"feature_grace_days,omitempty"`
	QualityNoAutoReboot *bool `json:"quality_no_auto_reboot,omitempty"`
	FeatureNoAutoReboot *bool `json:"feature_no_auto_reboot,omitempty"`
	ActiveHoursStart    *int  `json:"active_hours_start,omitempty"`
	ActiveHoursEnd      *int  `json:"active_hours_end,omitempty"`
	ActiveHoursMaximum  *int  `json:"active_hours_maximum,omitempty"`
	NotificationLevel   *int  `json:"notification_level,omitempty"`
	ExcludeDrivers      *bool `json:"exclude_drivers,omitempty"`
}

type updateSetting struct {
	Name         string
	Value        int
	MinimumBuild uint32
	FeatureGrace bool
}

const updateConfigRoot = "./Device/Vendor/MSFT/Policy/Config/Update/"
const updateResultRoot = "./Device/Vendor/MSFT/Policy/Result/Update/"

func (UpdatePolicy) String() string     { return "[protected Windows update policy]" }
func (v UpdatePolicy) GoString() string { return v.String() }

func (policy UpdatePolicy) settings() ([]updateSetting, error) {
	settings := []updateSetting{}
	valid := true
	integer := func(name string, value *int, minimum, maximum int, build uint32, grace bool) {
		if value == nil {
			return
		}
		if *value < minimum || *value > maximum {
			valid = false
			return
		}
		settings = append(settings, updateSetting{name, *value, build, grace})
	}
	boolean := func(name string, value *bool, build uint32) {
		if value != nil {
			number := 0
			if *value {
				number = 1
			}
			integer(name, &number, 0, 1, build, false)
		}
	}
	// Stable ordering is shared by the immutable intent, configuration tree and
	// exact Config/Result read-back expectations. Ranges follow Microsoft's CSP.
	integer("DeferQualityUpdatesPeriodInDays", policy.QualityDeferralDays, 0, 30, 14393, false)
	integer("DeferFeatureUpdatesPeriodInDays", policy.FeatureDeferralDays, 0, 365, 14393, false)
	integer("ConfigureDeadlineForQualityUpdates", policy.QualityDeadlineDays, 0, 30, 18362, false)
	integer("ConfigureDeadlineForFeatureUpdates", policy.FeatureDeadlineDays, 0, 30, 18362, false)
	integer("ConfigureDeadlineGracePeriod", policy.QualityGraceDays, 0, 7, 18362, false)
	integer("ConfigureDeadlineGracePeriodForFeatureUpdates", policy.FeatureGraceDays, 0, 7, 17763, true)
	boolean("ConfigureDeadlineNoAutoRebootForQualityUpdates", policy.QualityNoAutoReboot, 22621)
	boolean("ConfigureDeadlineNoAutoRebootForFeatureUpdates", policy.FeatureNoAutoReboot, 22621)
	integer("ActiveHoursStart", policy.ActiveHoursStart, 0, 23, 14393, false)
	integer("ActiveHoursEnd", policy.ActiveHoursEnd, 0, 23, 14393, false)
	integer("ActiveHoursMaxRange", policy.ActiveHoursMaximum, 8, 18, 15063, false)
	integer("UpdateNotificationLevel", policy.NotificationLevel, 0, 2, 17763, false)
	boolean("ExcludeWUDriversInQualityUpdate", policy.ExcludeDrivers, 14393)
	if !valid || len(settings) == 0 || (policy.QualityGraceDays != nil || policy.QualityNoAutoReboot != nil) && policy.QualityDeadlineDays == nil || (policy.FeatureGraceDays != nil || policy.FeatureNoAutoReboot != nil) && policy.FeatureDeadlineDays == nil || (policy.ActiveHoursStart == nil) != (policy.ActiveHoursEnd == nil) {
		return nil, ErrUpdatePolicy
	}
	if policy.ActiveHoursStart != nil {
		maximum := 18
		if policy.ActiveHoursMaximum != nil {
			maximum = *policy.ActiveHoursMaximum
		}
		length := (*policy.ActiveHoursEnd - *policy.ActiveHoursStart + 24) % 24
		if length == 0 || length > maximum {
			return nil, ErrUpdatePolicy
		}
	}
	return settings, nil
}

func (policy UpdatePolicy) Validate() error {
	_, err := policy.settings()
	return err
}

// UpdatePolicyCommands returns separate configuration and verification trees.
// They must be delivered in separate steps: read-back cannot be inferred from a
// Replace acknowledgment or from a Get placed inside the same Atomic group.
func UpdatePolicyCommands(policy UpdatePolicy, remove bool) (CSPCommandSpec, CSPCommandSpec, error) {
	settings, err := policy.settings()
	if err != nil {
		return CSPCommandSpec{}, CSPCommandSpec{}, err
	}
	configure, verify := CSPCommandSpec{Kind: "Atomic"}, CSPCommandSpec{Kind: "Sequence"}
	for _, setting := range settings {
		command := CSPCommandSpec{Kind: "Replace", URI: updateConfigRoot + setting.Name, Format: "int", Data: &SyncMLData{Text: strconv.Itoa(setting.Value)}}
		if remove {
			command.Kind, command.Format, command.Data = "Delete", "", nil
		}
		configure.Commands = append(configure.Commands, command)
		verify.Commands = append(verify.Commands, CSPCommandSpec{Kind: "Get", URI: updateConfigRoot + setting.Name}, CSPCommandSpec{Kind: "Get", URI: updateResultRoot + setting.Name})
	}
	for _, tree := range []CSPCommandSpec{configure, verify} {
		if _, _, err := encodeCSPRequest(tree); err != nil {
			return CSPCommandSpec{}, CSPCommandSpec{}, ErrUpdatePolicy
		}
	}
	return configure, verify, nil
}

func canonicalUpdatePolicy(policy UpdatePolicy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding", ErrUpdatePolicy)
	}
	return encoded, nil
}
