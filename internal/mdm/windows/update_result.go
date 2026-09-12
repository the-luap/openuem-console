package windows

import (
	"strconv"
	"time"
)

type UpdateSettingOutcome struct {
	Name            string `json:"-" xml:"-"`
	Expected        int    `json:"-" xml:"-"`
	Configured      *int   `json:"-" xml:"-"`
	Effective       *int   `json:"-" xml:"-"`
	ConfigStatus    int    `json:"-" xml:"-"`
	EffectiveStatus int    `json:"-" xml:"-"`
	State           string `json:"-" xml:"-"`
	// EvidenceReceivedAt is the server's completion time for this read batch,
	// not a device clock or an assertion of a simultaneous policy snapshot.
	EvidenceReceivedAt *time.Time `json:"-" xml:"-"`
}

func (UpdateSettingOutcome) String() string     { return "[protected Windows update setting outcome]" }
func (v UpdateSettingOutcome) GoString() string { return v.String() }

func updateIntegerResult(operation cspOperationResult) (*int, bool) {
	value, valid := updateResultText(operation)
	if !valid {
		return nil, false
	}
	number, err := strconv.ParseInt(value, 10, 32)
	if err != nil || strconv.FormatInt(number, 10) != value {
		return nil, false
	}
	result := int(number)
	return &result, true
}

func evaluateUpdateReadback(policy UpdatePolicy, remove bool, state *cspSessionCommand) ([]UpdateSettingOutcome, string, error) {
	settings, err := policy.settings()
	if err != nil {
		return nil, "", err
	}
	return evaluateUpdateSettingsReadback(settings, remove, state)
}

// The complete policy is validated before partitioning. A batch may contain a
// dependent setting whose prerequisite was already queried in a previous batch.
func evaluateUpdateSettingsReadback(settings []updateSetting, remove bool, state *cspSessionCommand) ([]UpdateSettingOutcome, string, error) {
	if state == nil || state.StopReason != "" {
		return nil, "verification_incomplete", nil
	}
	byURI := map[string]cspOperationResult{}
	groups := 0
	for _, operation := range state.Operations {
		if operation.Kind == "Sequence" && operation.ParentID == "" && operation.Status == 200 {
			groups++
			continue
		}
		if operation.Kind != "Get" {
			return nil, "verification_failed", nil
		}
		if _, duplicate := byURI[operation.URI]; duplicate {
			return nil, "", ErrAuthoritySecret
		}
		byURI[operation.URI] = operation
	}
	if groups != 1 || len(byURI) != 2*len(settings) {
		return nil, "verification_incomplete", nil
	}
	results := []UpdateSettingOutcome{}
	phase := "verified"
	if remove {
		phase = "removed"
	}
	failed, drifted := false, false
	for _, setting := range settings {
		configured, hasConfig := byURI[updateConfigRoot+setting.Name]
		effective, hasEffective := byURI[updateResultRoot+setting.Name]
		if !hasConfig || !hasEffective {
			return nil, "", ErrAuthoritySecret
		}
		entry := UpdateSettingOutcome{Name: setting.Name, Expected: setting.Value, ConfigStatus: configured.Status, EffectiveStatus: effective.Status, State: "unreadable"}
		configValue, configOK := updateIntegerResult(configured)
		effectiveValue, effectiveOK := updateIntegerResult(effective)
		entry.Configured, entry.Effective = configValue, effectiveValue
		if remove {
			configAbsent := configured.Status == 404 && !configured.HasResult
			effectiveAbsent := effective.Status == 404 && !effective.HasResult
			if configAbsent && (effectiveOK || effectiveAbsent) {
				entry.State = "removed"
			} else if configOK {
				entry.State = "still_configured"
				drifted = true
			} else {
				failed = true
			}
		} else if configOK && effectiveOK {
			entry.State = "verified"
			if *configValue != setting.Value {
				entry.State = "configured_value_mismatch"
				drifted = true
			} else if *effectiveValue != setting.Value {
				entry.State = "effective_value_mismatch"
				drifted = true
			}
		} else if configured.Status == 404 || effective.Status == 404 {
			entry.State = "value_absent"
			drifted = true
		} else {
			failed = true
		}
		results = append(results, entry)
	}
	if failed {
		phase = "verification_failed"
	} else if drifted {
		phase = "drifted"
	}
	return results, phase, nil
}
