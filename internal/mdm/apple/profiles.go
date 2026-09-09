package apple

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"howett.net/plist"
)

const MaxProfileBytes = 2 << 20

// ParseProfile accepts unsigned XML or binary mobileconfig documents. Payload
// identifiers remain stable; every saved revision receives a fresh root UUID so
// ProfileList can distinguish the installed revision, not merely its identifier.
func ParseProfile(data []byte) (*Profile, error) {
	if len(data) == 0 || len(data) > MaxProfileBytes {
		return nil, errors.New("profile must contain between 1 byte and 2 MiB")
	}
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("upload an unsigned XML or binary .mobileconfig profile: %w", err)
	}
	if stringValue(root, "PayloadType") != "Configuration" {
		return nil, errors.New("root PayloadType must be Configuration")
	}
	scope := "System"
	if value, exists := root["PayloadScope"]; exists {
		if value != "System" && value != "User" {
			return nil, errors.New("PayloadScope must be System or User")
		}
		scope = value.(string)
	}
	id := stringValue(root, "PayloadIdentifier")
	if reservedFileVaultIdentifier(id) {
		return nil, errors.New("FileVault workflow identifiers are reserved")
	}
	if reservedMacBindingIdentifier(id) {
		return nil, ErrMacBinding
	}
	if id == "" || len(id) > 255 || strings.ContainsAny(id, "\x00\r\n") {
		return nil, errors.New("a valid PayloadIdentifier is required")
	}
	if numberValue(root["PayloadVersion"]) != 1 {
		return nil, errors.New("PayloadVersion must be 1")
	}
	items, ok := root["PayloadContent"].([]any)
	if !ok || len(items) == 0 || len(items) > 100 {
		return nil, errors.New("PayloadContent must contain 1 to 100 configuration payloads")
	}
	seen := map[string]bool{}
	types := map[string]bool{}
	for _, item := range items {
		p, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("every payload must be a dictionary")
		}
		kind := stringValue(p, "PayloadType")
		if kind == "" || kind == "Configuration" || kind == "com.apple.mdm" {
			return nil, errors.New("nested configuration and MDM enrollment payloads cannot be deployed as settings")
		}
		pid := stringValue(p, "PayloadIdentifier")
		if reservedFileVaultIdentifier(pid) {
			return nil, errors.New("FileVault workflow identifiers are reserved")
		}
		if reservedMacBindingIdentifier(pid) {
			return nil, ErrMacBinding
		}
		if kind == "com.apple.ManagedClient.preferences" {
			if domains, ok := p["PayloadContent"].(map[string]any); ok {
				for domain := range domains {
					if reservedMacBindingIdentifier(domain) {
						return nil, ErrMacBinding
					}
				}
			}
		}
		if pid == "" || seen[pid] {
			return nil, errors.New("each payload needs a unique PayloadIdentifier")
		}
		seen[pid] = true
		if _, err := uuid.Parse(stringValue(p, "PayloadUUID")); err != nil {
			return nil, errors.New("each payload needs a valid PayloadUUID")
		}
		if numberValue(p["PayloadVersion"]) != 1 {
			return nil, errors.New("each payload needs PayloadVersion 1")
		}
		types[kind] = true
		if kind == "com.apple.security.firewall" {
			if err := validateFirewallPayload(p, scope, nil); err != nil {
				return nil, err
			}
		}
		if kind == "com.apple.extensiblesso" {
			if err := validatePlatformSSOPayload(p, scope, nil); err != nil {
				return nil, err
			}
		}
		if scope == "User" {
			if err := validateUserPayload(p, nil); err != nil {
				return nil, err
			}
		}
	}
	if _, err := extensibleSSORootRoutes(root); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(stringValue(root, "PayloadDisplayName"))
	if name == "" {
		name = id
	}
	if len(name) > 255 {
		return nil, errors.New("profile display name is too long")
	}
	profileUUID := uuid.NewString()
	root["PayloadUUID"] = profileUUID
	root["PayloadScope"] = scope
	canonical, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	p := &Profile{ID: uuid.NewString(), Name: name, Identifier: id, UUID: profileUUID, Revision: 1, Payload: canonical, Scope: scope}
	for kind := range types {
		p.PayloadTypes = append(p.PayloadTypes, kind)
	}
	sort.Strings(p.PayloadTypes)
	return p, nil
}

func stringValue(m map[string]any, key string) string { v, _ := m[key].(string); return v }
func numberValue(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n >= 0 {
			return uint64(n)
		}
	case int:
		if n >= 0 {
			return uint64(n)
		}
	case uint:
		return uint64(n)
	case float64:
		if n >= 0 && n == float64(uint64(n)) {
			return uint64(n)
		}
	}
	return 0
}

// BuildProfile provides native editors for common Apple configurations while the
// upload path supports additional Apple payloads without a server release.
func BuildProfile(name, identifier, kind string, settings map[string]any) ([]byte, error) {
	scope := "System"
	if value, exists := settings["PayloadScope"]; exists {
		if value != "System" && value != "User" {
			return nil, errors.New("profile scope must be System or User")
		}
		scope = value.(string)
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(identifier) == "" {
		return nil, errors.New("name and identifier are required")
	}
	payload := map[string]any{"PayloadIdentifier": identifier + ".settings", "PayloadUUID": uuid.NewString(), "PayloadVersion": 1, "PayloadDisplayName": name}
	switch kind {
	case "macos-platform-sso":
		if err := buildPlatformSSOPayload(payload, settings, scope); err != nil {
			return nil, err
		}
	case "macos-firewall":
		if err := buildFirewallPayload(payload, settings, scope); err != nil {
			return nil, err
		}
	case "passcode":
		payload["PayloadType"] = "com.apple.mobiledevice.passwordpolicy"
		payload["forcePIN"] = true
		length := numberValue(settings["minLength"])
		if length < 4 || length > 16 {
			return nil, errors.New("passcode minimum length must be 4 to 16")
		}
		payload["minLength"] = length
		payload["allowSimple"] = false
		if v, ok := settings["requireAlphanumeric"].(bool); ok {
			payload["requireAlphanumeric"] = v
		}
	case "wifi":
		ssid := stringValue(settings, "SSID_STR")
		if ssid == "" || len(ssid) > 32 {
			return nil, errors.New("Wi-Fi SSID must contain 1 to 32 bytes")
		}
		security := stringValue(settings, "EncryptionType")
		if security != "WPA" && security != "WPA2" && security != "WPA3" && security != "None" {
			return nil, errors.New("unsupported Wi-Fi security type")
		}
		payload["PayloadType"] = "com.apple.wifi.managed"
		payload["SSID_STR"] = ssid
		payload["EncryptionType"] = security
		payload["AutoJoin"] = true
		if security != "None" {
			password := stringValue(settings, "Password")
			if len(password) < 8 || len(password) > 63 {
				return nil, errors.New("Wi-Fi password must contain 8 to 63 characters")
			}
			payload["Password"] = password
		}
	case "restrictions":
		payload["PayloadType"] = "com.apple.applicationaccess"
		for _, key := range []string{"allowCamera", "allowScreenShot", "allowCloudBackup", "allowAppInstallation", "allowAirDrop"} {
			if v, ok := settings[key].(bool); ok {
				payload[key] = v
			}
		}
		if len(payload) == 5 {
			return nil, errors.New("select at least one restriction")
		}
	default:
		return nil, errors.New("unknown profile editor")
	}
	return plist.Marshal(map[string]any{"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": identifier, "PayloadUUID": uuid.NewString(), "PayloadDisplayName": name, "PayloadScope": scope, "PayloadContent": []any{payload}}, plist.XMLFormat)
}
