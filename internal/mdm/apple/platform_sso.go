package apple

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"howett.net/plist"
)

var platformSSOTeamID = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// The editor emits the macOS 14 PlatformSSO dictionary. Provider-specific
// extension data is preserved as plist values, never interpolated into XML.
func buildPlatformSSOPayload(payload, settings map[string]any, scope string) error {
	if scope != "System" {
		return errors.New("the Platform SSO editor creates a System profile")
	}
	payload["PayloadType"] = "com.apple.extensiblesso"
	payload["Type"] = "Redirect"
	for _, key := range []string{"ExtensionIdentifier", "TeamIdentifier", "URLs", "RegistrationToken", "ExtensionData"} {
		if value, exists := settings[key]; exists {
			payload[key] = value
		}
	}
	configuration := map[string]any{}
	for _, key := range []string{"AuthenticationMethod", "UseSharedDeviceKeys", "EnableCreateUserAtLogin", "AccountDisplayName"} {
		if value, exists := settings[key]; exists {
			configuration[key] = value
		}
	}
	if stringValue(configuration, "AuthenticationMethod") == "" {
		return errors.New("select the provider's supported Platform SSO authentication method")
	}
	payload["PlatformSSO"] = configuration
	return validatePlatformSSOPayload(payload, scope, nil)
}

func platformSSOURLKey(raw string) (string, error) {
	if !validMacAppText(raw, 2048) {
		return "", errors.New("SSO URL prefixes must contain 1 to 2048 characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("SSO URL prefixes require HTTP or HTTPS without credentials, query parameters or fragments")
	}
	return strings.ToLower(u.Scheme+"://"+u.Host) + u.EscapedPath(), nil
}

// Generic SSO extensions remain supported. Additional checks apply only when
// the payload requests Platform SSO; ordinary Kerberos/Credential profiles do
// not inherit Mac-only Platform SSO requirements.
func validatePlatformSSOPayload(payload map[string]any, scope string, d *Device) error {
	_, modern := payload["PlatformSSO"]
	_, legacy := payload["AuthenticationMethod"]
	_, token := payload["RegistrationToken"]
	if !modern && !legacy && !token {
		return nil
	}
	if stringValue(payload, "Type") != "Redirect" || !macAppIdentifierPattern.MatchString(stringValue(payload, "ExtensionIdentifier")) || len(stringValue(payload, "ExtensionIdentifier")) > 255 || !platformSSOTeamID.MatchString(stringValue(payload, "TeamIdentifier")) {
		return errors.New("Platform SSO requires Redirect type, an extension bundle identifier and a ten-character team identifier")
	}
	urls, ok := payload["URLs"].([]any)
	if !ok || len(urls) == 0 || len(urls) > 64 {
		return errors.New("Platform SSO requires 1 to 64 identity-provider URL prefixes")
	}
	seen := map[string]bool{}
	for _, value := range urls {
		raw, ok := value.(string)
		if !ok {
			return errors.New("SSO URL prefixes must be strings")
		}
		key, err := platformSSOURLKey(raw)
		if err != nil {
			return err
		}
		if seen[key] {
			return errors.New("SSO URL prefixes must be unique")
		}
		seen[key] = true
	}
	minimum := "13.0"
	method := stringValue(payload, "AuthenticationMethod")
	if legacy && method != "Password" && method != "UserSecureEnclaveKey" {
		return errors.New("unsupported legacy Platform SSO authentication method")
	}
	configuration := map[string]any{}
	if modern {
		if legacy {
			return errors.New("use one Platform SSO authentication configuration, not both legacy and modern keys")
		}
		configuration, ok = payload["PlatformSSO"].(map[string]any)
		if !ok {
			return errors.New("PlatformSSO must be a dictionary")
		}
		minimum = "14.0"
		method = stringValue(configuration, "AuthenticationMethod")
		if value, exists := configuration["AuthenticationMethod"]; exists && value != "Password" && value != "UserSecureEnclaveKey" && value != "SmartCard" {
			return errors.New("unsupported Platform SSO authentication method")
		}
		for _, key := range []string{"UseSharedDeviceKeys", "EnableCreateUserAtLogin", "EnableAuthorization", "EnableRegistrationDuringSetup", "EnableCreateFirstUserDuringSetup"} {
			if value, exists := configuration[key]; exists {
				if _, ok := value.(bool); !ok {
					return errors.New("Platform SSO switches must be booleans")
				}
				if key == "UseSharedDeviceKeys" && scope != "System" {
					return errors.New("shared Platform SSO device keys require System scope")
				}
				if key == "EnableRegistrationDuringSetup" || key == "EnableCreateFirstUserDuringSetup" {
					minimum = "26.0"
				}
			}
		}
		shared, _ := configuration["UseSharedDeviceKeys"].(bool)
		create, _ := configuration["EnableCreateUserAtLogin"].(bool)
		authorize, _ := configuration["EnableAuthorization"].(bool)
		if create && (!shared || method != "Password" && method != "SmartCard") {
			return errors.New("login-window account creation requires shared device keys and Password or SmartCard authentication")
		}
		if authorize && !shared {
			return errors.New("Platform SSO authorization requires shared device keys")
		}
		if value, exists := configuration["AccountDisplayName"]; exists {
			name, ok := value.(string)
			if !ok || !validMacAppText(name, 255) {
				return errors.New("Platform SSO account display name must contain 1 to 255 characters")
			}
		}
		if value, exists := configuration["LoginFrequency"]; exists {
			switch value.(type) {
			case int, int64, uint64:
			default:
				return errors.New("Platform SSO login frequency must be an integer")
			}
			if numberValue(value) < 3600 {
				return errors.New("Platform SSO login frequency must be at least 3600 seconds")
			}
		}
	}
	if token {
		value, ok := payload["RegistrationToken"].(string)
		if !ok || !validMacAppText(value, 8192) || method == "" {
			return errors.New("a registration token requires a supported Platform SSO authentication method and at most 8192 characters")
		}
	}
	if value, exists := payload["ExtensionData"]; exists {
		if _, ok := value.(map[string]any); !ok {
			return errors.New("SSO provider extension data must be a dictionary")
		}
	}
	if d != nil {
		if d.Family() != PlatformMacOS || !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, minimum) < 0 {
			return errors.New("this Platform SSO profile requires macOS " + minimum + " or later")
		}
		management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
		approved, _ := management["UserApprovedEnrollment"].(bool)
		if !approved || !d.SecurityFresh(time.Now()) {
			return errors.New("Platform SSO requires fresh user-approved MDM security inventory")
		}
	}
	return nil
}

func validatePlatformSSOProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved configuration profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, ok := item.(map[string]any)
		if ok && stringValue(payload, "PayloadType") == "com.apple.extensiblesso" {
			if err := validatePlatformSSOPayload(payload, p.Scope, d); err != nil {
				return err
			}
		}
	}
	return nil
}
