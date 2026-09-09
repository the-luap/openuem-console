package apple

import (
	"errors"
	"strings"
	"time"

	"howett.net/plist"
)

const systemExtensionPayloadType = "com.apple.system-extension-policy"

type systemExtensionPair struct{ Team, Bundle string }
type systemExtensionRules struct {
	Teams, SpecificTeams map[string]bool
	Removable, Protected map[systemExtensionPair]bool
}

func newSystemExtensionRules() *systemExtensionRules {
	return &systemExtensionRules{Teams: map[string]bool{}, SpecificTeams: map[string]bool{}, Removable: map[systemExtensionPair]bool{}, Protected: map[systemExtensionPair]bool{}}
}

func (r *systemExtensionRules) conflicts(other *systemExtensionRules) bool {
	for team := range r.Teams {
		if other.SpecificTeams[team] {
			return true
		}
	}
	for team := range r.SpecificTeams {
		if other.Teams[team] {
			return true
		}
	}
	for pair := range r.Removable {
		if other.Protected[pair] {
			return true
		}
	}
	for pair := range r.Protected {
		if other.Removable[pair] {
			return true
		}
	}
	return false
}

func (r *systemExtensionRules) collisionSensitive() bool {
	return len(r.Teams)+len(r.SpecificTeams)+len(r.Removable)+len(r.Protected) > 0
}

func systemExtensionBundleLines(raw string) ([]any, error) {
	if len(raw) > 16384 {
		return nil, errors.New("system extension lists must contain at most 16 KiB")
	}
	result := []any{}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		if !validMacAppIdentifier(value) {
			return nil, errors.New("system extension bundle identifiers must be valid identifiers of at most 255 characters")
		}
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	if len(result) > 128 {
		return nil, errors.New("a system extension list supports at most 128 bundle identifiers")
	}
	return result, nil
}

func buildSystemExtensionsPayload(payload, settings map[string]any, scope string) error {
	if scope != "System" {
		return errors.New("system extensions require System scope")
	}
	payload["PayloadType"] = systemExtensionPayloadType
	mode := stringValue(settings, "ApprovalMode")
	if mode == "block" {
		for _, key := range []string{"TeamIdentifier", "BundleIdentifiers", "AllowUserOverrides", "AllowedTypes", "RemovableBundleIdentifiers", "ProtectedBundleIdentifiers", "ProtectedUIBundleIdentifiers"} {
			if _, exists := settings[key]; exists {
				return errors.New("block policy cannot also select approval or removal rules")
			}
		}
		payload["AllowUserOverrides"] = false
		return nil
	}
	team := stringValue(settings, "TeamIdentifier")
	if !platformSSOTeamID.MatchString(team) {
		return errors.New("enter the developer's ten-character team identifier")
	}
	allow, ok := settings["AllowUserOverrides"].(bool)
	if !ok {
		return errors.New("select whether users may approve additional system extensions")
	}
	payload["AllowUserOverrides"] = allow
	switch mode {
	case "listed":
		bundles, err := systemExtensionBundleLines(stringValue(settings, "BundleIdentifiers"))
		if err != nil {
			return err
		}
		if len(bundles) == 0 {
			return errors.New("enter at least one approved system extension bundle identifier")
		}
		payload["AllowedSystemExtensions"] = map[string]any{team: bundles}
	case "team":
		if stringValue(settings, "BundleIdentifiers") != "" {
			return errors.New("team approval cannot also select individual extensions")
		}
		payload["AllowedTeamIdentifiers"] = []any{team}
	default:
		return errors.New("select a system extension approval policy")
	}
	if types, exists := settings["AllowedTypes"]; exists {
		payload["AllowedSystemExtensionTypes"] = map[string]any{team: types}
	}
	for key, field := range map[string]string{"RemovableSystemExtensions": "RemovableBundleIdentifiers", "NonRemovableSystemExtensions": "ProtectedBundleIdentifiers", "NonRemovableFromUISystemExtensions": "ProtectedUIBundleIdentifiers"} {
		raw, exists := settings[field]
		if !exists {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			return errors.New("system extension removal lists must be text")
		}
		bundles, err := systemExtensionBundleLines(value)
		if err != nil {
			return err
		}
		if len(bundles) > 0 {
			payload[key] = map[string]any{team: bundles}
		}
	}
	_, err := parseSystemExtensionPayload(payload, scope, nil)
	return err
}

func parseSystemExtensionPayload(payload map[string]any, scope string, d *Device) (*systemExtensionRules, error) {
	if stringValue(payload, "PayloadType") != systemExtensionPayloadType {
		return nil, nil
	}
	if scope != "System" {
		return nil, errors.New("system extension policies require System scope")
	}
	rules := newSystemExtensionRules()
	minimum := "10.15"
	if value, exists := payload["AllowUserOverrides"]; exists {
		if _, ok := value.(bool); !ok {
			return nil, errors.New("system extension approval switches must be booleans")
		}
	}
	if raw, exists := payload["AllowedTeamIdentifiers"]; exists {
		values, ok := raw.([]any)
		if !ok || len(values) > 64 {
			return nil, errors.New("allowed system extension teams must be an array of at most 64 identifiers")
		}
		for _, value := range values {
			team, ok := value.(string)
			if !ok || !platformSSOTeamID.MatchString(team) {
				return nil, errors.New("invalid system extension team identifier")
			}
			rules.Teams[team] = true
		}
	}
	for _, key := range []string{"AllowedSystemExtensions", "AllowedSystemExtensionTypes", "RemovableSystemExtensions", "NonRemovableSystemExtensions", "NonRemovableFromUISystemExtensions"} {
		raw, exists := payload[key]
		if !exists {
			continue
		}
		if key == "RemovableSystemExtensions" {
			if CompareVersions(minimum, "12.0") < 0 {
				minimum = "12.0"
			}
		}
		if key == "NonRemovableSystemExtensions" || key == "NonRemovableFromUISystemExtensions" {
			minimum = "15.0"
		}
		mapping, ok := raw.(map[string]any)
		if !ok || len(mapping) > 64 {
			return nil, errors.New("system extension rules must map at most 64 team identifiers to lists")
		}
		for team, rawValues := range mapping {
			if !platformSSOTeamID.MatchString(team) {
				return nil, errors.New("invalid system extension team identifier")
			}
			values, ok := rawValues.([]any)
			if !ok || len(values) > 128 {
				return nil, errors.New("system extension rule lists support at most 128 entries")
			}
			if key == "AllowedSystemExtensions" {
				rules.SpecificTeams[team] = true
			}
			for _, rawValue := range values {
				value, ok := rawValue.(string)
				if !ok {
					return nil, errors.New("system extension rule entries must be strings")
				}
				if key == "AllowedSystemExtensionTypes" {
					if value != "DriverExtension" && value != "NetworkExtension" && value != "EndpointSecurityExtension" {
						return nil, errors.New("unsupported system extension type")
					}
					continue
				}
				if !validMacAppIdentifier(value) {
					return nil, errors.New("invalid system extension bundle identifier")
				}
				pair := systemExtensionPair{team, value}
				if key == "RemovableSystemExtensions" {
					rules.Removable[pair] = true
				}
				if key == "NonRemovableSystemExtensions" {
					rules.Protected[pair] = true
				}
			}
		}
	}
	if rules.conflicts(rules) {
		return nil, errors.New("system extension rules cannot mix team-wide and individual approval for one team, or allow and prevent removal of the same extension")
	}
	if d != nil {
		if d.Family() != PlatformMacOS || !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, minimum) < 0 {
			return nil, errors.New("this system extension policy requires macOS " + minimum + " or later")
		}
		management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
		approved, _ := management["UserApprovedEnrollment"].(bool)
		userEnrollment, _ := management["IsUserEnrollment"].(bool)
		if userEnrollment || !approved || !d.SecurityFresh(time.Now()) {
			return nil, errors.New("system extension policies require fresh user-approved MDM security inventory")
		}
	}
	return rules, nil
}

func systemExtensionProfileRules(data []byte, scope string, d *Device) (*systemExtensionRules, error) {
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, errors.New("invalid saved system extension profile")
	}
	return systemExtensionRootRules(root, scope, d)
}

func systemExtensionRootRules(root map[string]any, scope string, d *Device) (*systemExtensionRules, error) {
	var combined *systemExtensionRules
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		rules, err := parseSystemExtensionPayload(payload, scope, d)
		if err != nil {
			return nil, err
		}
		if rules == nil {
			continue
		}
		if combined == nil {
			combined = newSystemExtensionRules()
		}
		if combined.conflicts(rules) {
			return nil, errors.New("system extension payloads in this profile contain conflicting approval or removal rules")
		}
		for team := range rules.Teams {
			combined.Teams[team] = true
		}
		for team := range rules.SpecificTeams {
			combined.SpecificTeams[team] = true
		}
		for pair := range rules.Removable {
			combined.Removable[pair] = true
		}
		for pair := range rules.Protected {
			combined.Protected[pair] = true
		}
	}
	return combined, nil
}
