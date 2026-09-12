package apple

import (
	"errors"

	"github.com/google/uuid"
	"howett.net/plist"
)

func buildGatekeeperPayload(payload, settings map[string]any, scope string) ([]any, error) {
	if scope != "System" {
		return nil, errors.New("the Gatekeeper editor creates a System profile")
	}
	if _, ok := settings["EnableAssessment"].(bool); !ok {
		return nil, errors.New("select an explicit Gatekeeper application policy")
	}
	payload["PayloadType"] = "com.apple.systempolicy.control"
	for _, key := range []string{"EnableAssessment", "AllowIdentifiedDevelopers", "EnableXProtectMalwareUpload"} {
		if value, exists := settings[key]; exists {
			payload[key] = value
		}
	}
	if err := validateGatekeeperPayload(payload, scope, nil); err != nil {
		return nil, err
	}
	if value, exists := settings["DisableOverride"]; exists {
		override := map[string]any{"PayloadType": "com.apple.systempolicy.managed", "PayloadIdentifier": stringValue(payload, "PayloadIdentifier") + ".override", "PayloadUUID": uuid.NewString(), "PayloadVersion": 1, "DisableOverride": value}
		if err := validateGatekeeperPayload(override, scope, nil); err != nil {
			return nil, err
		}
		return []any{override}, nil
	}
	return nil, nil
}

// The assessment payload is System-only; Finder override policy also supports
// User scope. Optional keys remain optional in uploaded profiles.
func validateGatekeeperPayload(payload map[string]any, scope string, d *Device) error {
	kind := stringValue(payload, "PayloadType")
	keys := []string{}
	switch kind {
	case "com.apple.systempolicy.control":
		if scope != "System" {
			return errors.New("Gatekeeper assessment requires System scope")
		}
		keys = []string{"EnableAssessment", "AllowIdentifiedDevelopers", "EnableXProtectMalwareUpload"}
	case "com.apple.systempolicy.managed":
		keys = []string{"DisableOverride"}
	default:
		return nil
	}
	minimum := "10.8"
	for _, key := range keys {
		if value, exists := payload[key]; exists {
			if _, ok := value.(bool); !ok {
				return errors.New("Gatekeeper switches must be booleans")
			}
			if key == "EnableXProtectMalwareUpload" {
				minimum = "15.0"
			}
		}
	}
	if d != nil && (d.Family() != PlatformMacOS || !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, minimum) < 0) {
		return errors.New("this Gatekeeper profile requires macOS " + minimum + " or later")
	}
	return nil
}

func validateGatekeeperProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved Gatekeeper profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validateGatekeeperPayload(payload, p.Scope, d); err != nil {
			return err
		}
	}
	return nil
}
