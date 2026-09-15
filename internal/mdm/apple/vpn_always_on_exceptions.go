package apple

import (
	"errors"
	"strings"
)

// Exception lists can permit traffic outside the tunnel. Preserve explicit
// values, reject ambiguous duplicates and check even currently ignored lists.
// The 64-entry and 255-byte bounds are OpenUEM admission limits.
func validateAlwaysOnExceptions(always map[string]any, advance func(string, string)) error {
	for _, key := range []string{"ServiceExceptions", "ApplicationExceptions", "AllowedCaptiveNetworkPlugins"} {
		value, exists := always[key]
		if !exists {
			continue
		}
		items, ok := value.([]any)
		if !ok || len(items) > 64 {
			return errors.New("Always On exception lists must be arrays of at most 64 entries")
		}
		if key == "ApplicationExceptions" {
			// Presence requires support, including an explicitly empty list.
			advance("", "13.6")
		}
		seen := map[string]bool{}
		for _, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				return errors.New("Always On exception entries must be dictionaries")
			}
			for field := range entry {
				allowed := key == "ServiceExceptions" && (field == "ServiceName" || field == "Action") ||
					key != "ServiceExceptions" && field == "BundleIdentifier" ||
					key == "ApplicationExceptions" && field == "LimitToProtocols"
				if !allowed {
					return errors.New("unsupported Always On exception field")
				}
			}
			var identity string
			if key == "ServiceExceptions" {
				identity = stringValue(entry, "ServiceName")
				switch identity {
				case "VoiceMail", "AirPrint":
				case "CellularServices":
					advance("", "11.3")
				case "DeviceCommunication":
					advance("", "17.4")
				default:
					return errors.New("Always On service exceptions require a supported service name")
				}
				if action := stringValue(entry, "Action"); action != "Allow" && action != "Drop" {
					return errors.New("Always On service exceptions require Allow or Drop")
				}
			} else {
				identity = stringValue(entry, "BundleIdentifier")
				if !validMacAppIdentifier(identity) {
					return errors.New("Always On app exceptions require an exact bundle identifier of at most 255 bytes")
				}
				if value, exists := entry["LimitToProtocols"]; exists {
					protocols, ok := value.([]any)
					// An omitted limit preserves Apple's unrestricted exception.
					// An explicit limit must unambiguously select the supported UDP.
					if !ok || len(protocols) != 1 || protocols[0] != "UDP" {
						return errors.New("Always On app protocol limits must contain UDP exactly once")
					}
				}
				identity = strings.ToLower(identity)
			}
			if seen[identity] {
				return errors.New("Always On exception lists must not repeat a service or bundle identifier")
			}
			seen[identity] = true
		}
	}
	return nil
}
