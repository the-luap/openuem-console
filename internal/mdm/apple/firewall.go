package apple

import (
	"errors"
	"regexp"
	"strings"

	"howett.net/plist"
)

const maxFirewallApplications = 64

var firewallBundleID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)

func buildFirewallPayload(payload, settings map[string]any, scope string) error {
	payload["PayloadType"] = "com.apple.security.firewall"
	for _, key := range []string{"EnableFirewall", "BlockAllIncoming", "EnableStealthMode", "AllowSigned", "AllowSignedApp"} {
		if value, ok := settings[key]; ok {
			payload[key] = value
		}
	}
	apps := []any{}
	for _, field := range []struct {
		key     string
		allowed bool
	}{{"AllowedApplications", true}, {"BlockedApplications", false}} {
		text, exists := settings[field.key]
		if !exists {
			continue
		}
		value, ok := text.(string)
		if !ok || len(value) > 16*1024 {
			return errors.New("firewall application lists must contain at most 16 KiB each")
		}
		for _, line := range strings.Split(value, "\n") {
			id := strings.TrimSpace(line)
			if id != "" {
				apps = append(apps, map[string]any{"BundleID": id, "Allowed": field.allowed})
			}
		}
	}
	if len(apps) > 0 {
		payload["Applications"] = apps
	}
	return validateFirewallPayload(payload, scope, nil)
}

// Firewall settings are device-channel only. Enforce field types for both the
// editor and uploaded profiles, then gate OS-specific keys at assignment time.
func validateFirewallPayload(payload map[string]any, scope string, d *Device) error {
	if scope != "System" {
		return errors.New("firewall profiles require System scope")
	}
	if _, ok := payload["EnableFirewall"].(bool); !ok {
		return errors.New("firewall profiles require an explicit EnableFirewall boolean")
	}
	minimum := "10.12"
	logging := false
	for _, key := range []string{"BlockAllIncoming", "EnableStealthMode", "AllowSigned", "AllowSignedApp", "EnableLogging"} {
		if value, exists := payload[key]; exists {
			if _, ok := value.(bool); !ok {
				return errors.New("firewall switches must be booleans")
			}
			if key == "AllowSigned" || key == "AllowSignedApp" {
				minimum = "12.3"
			}
			logging = logging || key == "EnableLogging"
		}
	}
	if value, exists := payload["LoggingOption"]; exists {
		if value != "throttled" && value != "brief" && value != "detail" {
			return errors.New("unsupported firewall logging option")
		}
		logging = true
	}
	if value, exists := payload["Applications"]; exists {
		apps, ok := value.([]any)
		if !ok || len(apps) > maxFirewallApplications {
			return errors.New("firewall profiles support at most 64 application rules")
		}
		seen := map[string]bool{}
		for _, item := range apps {
			app, ok := item.(map[string]any)
			if !ok {
				return errors.New("each firewall application rule must be a dictionary")
			}
			id := stringValue(app, "BundleID")
			if !firewallBundleID.MatchString(id) || seen[strings.ToLower(id)] {
				return errors.New("firewall application rules require unique bundle identifiers of 1 to 255 ASCII letters, digits, periods or hyphens")
			}
			if _, ok = app["Allowed"].(bool); !ok {
				return errors.New("each firewall application rule requires an Allowed boolean")
			}
			seen[strings.ToLower(id)] = true
		}
	}
	if d != nil {
		if d.Family() != PlatformMacOS || !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, minimum) < 0 {
			return errors.New("this firewall profile requires a Mac running macOS " + minimum + " or later")
		}
		if logging && (CompareVersions(d.OSVersion, "12.0") < 0 || CompareVersions(d.OSVersion, "15.0") >= 0) {
			return errors.New("firewall logging settings are available only on macOS 12 through 14")
		}
	}
	return nil
}

func validateFirewallProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved configuration profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, ok := item.(map[string]any)
		if ok && stringValue(payload, "PayloadType") == "com.apple.security.firewall" {
			if err := validateFirewallPayload(payload, p.Scope, d); err != nil {
				return err
			}
		}
	}
	return nil
}
