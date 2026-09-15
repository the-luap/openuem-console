package apple

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"howett.net/plist"
)

const privacyPayloadType = "com.apple.TCC.configuration-profile-policy"

type PrivacyService struct {
	Key, Name, Minimum     string
	DenyOnly, StandardUser bool
}

// These are Apple's service capabilities, not proof that a particular binary's
// signature satisfies the supplied code requirement on the managed Mac.
func PrivacyServices() []PrivacyService {
	return []PrivacyService{
		{"AddressBook", "Contacts", "10.14", false, false},
		{"Calendar", "Calendars", "10.14", false, false},
		{"Reminders", "Reminders", "10.14", false, false},
		{"Photos", "Photos", "10.14", false, false},
		{"Camera", "Camera", "10.14", true, false},
		{"Microphone", "Microphone", "10.14", true, false},
		{"Accessibility", "Accessibility", "10.14", false, false},
		{"PostEvent", "Send input events", "10.14", false, false},
		{"SystemPolicyAllFiles", "Full Disk Access", "10.14", false, false},
		{"SystemPolicySysAdminFiles", "System administration files", "10.14", false, false},
		{"AppleEvents", "Apple Events automation", "10.14", false, false},
		{"MediaLibrary", "Media library", "10.15", false, false},
		{"FileProviderPresence", "File Provider presence", "10.15", false, false},
		{"ListenEvent", "Input monitoring", "10.15", true, true},
		{"ScreenCapture", "Screen capture", "10.15", true, true},
		{"SpeechRecognition", "Speech recognition", "10.15", false, false},
		{"SystemPolicyDesktopFolder", "Desktop folder", "10.15", false, false},
		{"SystemPolicyDocumentsFolder", "Documents folder", "10.15", false, false},
		{"SystemPolicyDownloadsFolder", "Downloads folder", "10.15", false, false},
		{"SystemPolicyNetworkVolumes", "Network volumes", "10.15", false, false},
		{"SystemPolicyRemovableVolumes", "Removable volumes", "10.15", false, false},
		{"SystemPolicyAppBundles", "Update or delete other applications", "13.0", false, false},
		{"SystemPolicyAppData", "Other applications' data", "14.0", false, false},
		{"BluetoothAlways", "Bluetooth devices", "11.0", false, false},
	}
}

func privacyService(key string) (PrivacyService, bool) {
	for _, service := range PrivacyServices() {
		if service.Key == key {
			return service, true
		}
	}
	return PrivacyService{}, false
}

func privacyText(value any, maximum int, multiline bool) (string, bool) {
	s, ok := value.(string)
	if !ok || len(s) > maximum || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\r' || r == '\t')) {
			return "", false
		}
	}
	return s, true
}

func validatePrivacyIdentity(identity map[string]any, prefix string) error {
	identifier, ok := privacyText(identity[prefix+"Identifier"], 1024, false)
	if !ok {
		return errors.New("privacy policy requires a bounded application identifier or absolute binary path")
	}
	switch identity[prefix+"IdentifierType"] {
	case "bundleID":
		if !validMacAppIdentifier(identifier) {
			return errors.New("invalid privacy application bundle identifier")
		}
	case "path":
		if identifier == "/" || !strings.HasPrefix(identifier, "/") || path.Clean(identifier) != identifier {
			return errors.New("privacy binary paths must be absolute and contain no redundant path segments")
		}
	default:
		return errors.New("select a bundle identifier for an application or a path for a nonbundled binary")
	}
	if _, ok = privacyText(identity[prefix+"CodeRequirement"], 8192, true); !ok {
		return errors.New("provide the signed application's code requirement, up to 8192 bytes")
	}
	return nil
}

func buildPrivacyPayload(payload, settings map[string]any, scope string) error {
	identity := map[string]any{}
	for _, key := range []string{"Identifier", "IdentifierType", "CodeRequirement", "StaticCode", "Comment", "AEReceiverIdentifier", "AEReceiverIdentifierType", "AEReceiverCodeRequirement"} {
		if value, exists := settings[key]; exists {
			identity[key] = value
		}
	}
	switch settings["Policy"] {
	case "allow":
		identity["Allowed"] = true
	case "deny":
		identity["Allowed"] = false
	case "user":
		identity["Authorization"] = "AllowStandardUserToSetSystemService"
	default:
		return errors.New("select an explicit privacy policy")
	}
	payload["PayloadType"] = privacyPayloadType
	payload["Services"] = map[string]any{stringValue(settings, "Service"): []any{identity}}
	return validatePrivacyPayload(payload, scope, nil)
}

func validatePrivacyPayload(payload map[string]any, scope string, d *Device) error {
	if stringValue(payload, "PayloadType") != privacyPayloadType {
		return nil
	}
	if scope != "System" {
		return errors.New("privacy policies require System scope")
	}
	services, ok := payload["Services"].(map[string]any)
	if !ok || len(services) > len(PrivacyServices()) {
		return errors.New("privacy policies require a dictionary of supported services")
	}
	minimum := "10.14"
	for key, raw := range services {
		service, exists := privacyService(key)
		if !exists {
			return errors.New("unsupported privacy service")
		}
		if CompareVersions(service.Minimum, minimum) > 0 {
			minimum = service.Minimum
		}
		identities, ok := raw.([]any)
		if !ok || len(identities) > 128 {
			return errors.New("privacy services support at most 128 application rules")
		}
		for _, rawIdentity := range identities {
			identity, ok := rawIdentity.(map[string]any)
			if !ok {
				return errors.New("privacy application rules must be dictionaries")
			}
			if err := validatePrivacyIdentity(identity, ""); err != nil {
				return err
			}
			for _, k := range []string{"StaticCode"} {
				if value, exists := identity[k]; exists {
					if _, ok := value.(bool); !ok {
						return errors.New("privacy static code validation must be a boolean")
					}
				}
			}
			if value, exists := identity["Comment"]; exists {
				text, ok := value.(string)
				if !ok || len(text) > 1024 || !utf8.ValidString(text) {
					return errors.New("privacy comments must be text of at most 1024 bytes")
				}
			}
			allowed, hasAllowed := identity["Allowed"]
			authorization, hasAuthorization := identity["Authorization"]
			if hasAllowed == hasAuthorization {
				return errors.New("privacy rules require exactly one of Allowed or Authorization")
			}
			grant := false
			if hasAllowed {
				value, ok := allowed.(bool)
				if !ok {
					return errors.New("privacy Allowed must be a boolean")
				}
				grant = value
			}
			if hasAuthorization {
				if CompareVersions(minimum, "11.0") < 0 {
					minimum = "11.0"
				}
				switch authorization {
				case "Allow":
					grant = true
				case "Deny":
				case "AllowStandardUserToSetSystemService":
					if !service.StandardUser {
						return errors.New("standard-user privacy controls are limited to input monitoring and screen capture")
					}
				default:
					return errors.New("unsupported privacy authorization")
				}
			}
			if grant && service.DenyOnly {
				return errors.New("this privacy service cannot be granted by a configuration profile")
			}
			if key == "AppleEvents" {
				if err := validatePrivacyIdentity(identity, "AEReceiver"); err != nil {
					return err
				}
			} else {
				for _, k := range []string{"AEReceiverIdentifier", "AEReceiverIdentifierType", "AEReceiverCodeRequirement"} {
					if _, exists := identity[k]; exists {
						return errors.New("Apple Events receiver fields are valid only for the Apple Events service")
					}
				}
			}
			if d != nil && key == "Accessibility" && grant && CompareVersions(d.OSVersion, "27.0") >= 0 {
				return errors.New("Accessibility grants through profiles are unavailable on macOS 27 or later")
			}
		}
	}
	if d != nil {
		if d.Family() != PlatformMacOS || !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, minimum) < 0 {
			return fmt.Errorf("this privacy policy requires macOS %s or later", minimum)
		}
		management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
		approved, _ := management["UserApprovedEnrollment"].(bool)
		userEnrollment, _ := management["IsUserEnrollment"].(bool)
		if !approved || userEnrollment || !d.SecurityFresh(time.Now()) {
			return errors.New("privacy policies require fresh user-approved MDM security inventory")
		}
	}
	return nil
}

func validatePrivacyProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved privacy profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validatePrivacyPayload(payload, p.Scope, d); err != nil {
			return err
		}
	}
	return nil
}
