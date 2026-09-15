package apple

import (
	"errors"
	"net/url"
	"strings"

	"howett.net/plist"
)

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

type extensibleSSORoute struct {
	Extension, Team string
	Platform        bool
}

// Extensible SSO routing is shared by Redirect and Credential payloads. Only
// scheme and host names are case-insensitive; distinct URL paths and wildcard
// host suffixes are not treated as overlapping reservations.
func extensibleSSORoutes(data []byte) (map[string]extensibleSSORoute, error) {
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	return extensibleSSORootRoutes(root)
}

func extensibleSSORootRoutes(root map[string]any) (map[string]extensibleSSORoute, error) {
	routes := map[string]extensibleSSORoute{}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if stringValue(payload, "PayloadType") != "com.apple.extensiblesso" {
			continue
		}
		kind := stringValue(payload, "Type")
		field := "URLs"
		if kind == "Credential" {
			field = "Hosts"
		} else if kind != "Redirect" {
			return nil, errors.New("Extensible SSO requires Redirect or Credential type")
		}
		values, ok := payload[field].([]any)
		if !ok || len(values) == 0 || len(values) > 1024 {
			return nil, errors.New("Extensible SSO requires 1 to 1024 URL prefixes or host names")
		}
		for _, value := range values {
			raw, ok := value.(string)
			if !ok {
				return nil, errors.New("SSO URL prefixes and host names must be strings")
			}
			var key string
			if kind == "Redirect" {
				var err error
				key, err = platformSSOURLKey(raw)
				if err != nil {
					return nil, err
				}
				key = "url:" + key
			} else {
				if !validMacAppText(raw, 2048) || strings.ContainsAny(raw, " /:@?#[]*\\") || strings.Trim(raw, ".") == "" || strings.Contains(raw, "..") {
					return nil, errors.New("SSO hosts must be host or domain names, optionally with a leading dot")
				}
				key = "host:" + strings.ToLower(raw)
			}
			if _, exists := routes[key]; exists {
				return nil, errors.New("SSO URL prefixes and host names must be unique across all payloads in a profile")
			}
			_, modern := payload["PlatformSSO"]
			_, legacy := payload["AuthenticationMethod"]
			routes[key] = extensibleSSORoute{Extension: stringValue(payload, "ExtensionIdentifier"), Team: stringValue(payload, "TeamIdentifier"), Platform: modern || legacy}
		}
	}
	return routes, nil
}
