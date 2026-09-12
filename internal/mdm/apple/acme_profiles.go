package apple

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

func buildACMECertificatePayload(payload, settings map[string]any, scope string) error {
	payload["PayloadType"] = "com.apple.security.acme"
	for _, key := range []string{"DirectoryURL", "ClientIdentifier", "KeyType", "KeySize", "HardwareBound", "Attest", "UsageFlags", "KeyIsExtractable", "AllowAllAppsAccess"} {
		if value, exists := settings[key]; exists {
			payload[key] = value
		}
	}
	text, ok := settings["SubjectLines"].(string)
	if !ok {
		return errors.New("ACME subject attributes must be text")
	}
	subject, err := certificateSubjectLines(text)
	if err != nil {
		return err
	}
	// The subject is required, even when the issuer accepts an empty name.
	payload["Subject"] = subject
	names := map[string]any{}
	for _, key := range []string{"rfc822Name", "dNSName", "uniformResourceIdentifier", "ntPrincipalName"} {
		if value, exists := settings[key]; exists {
			if !certificateText(value, 1024, true) {
				return errors.New("ACME alternative names must be bounded strings")
			}
			if value != "" {
				names[key] = value
			}
		}
	}
	if len(names) > 0 {
		payload["SubjectAltName"] = names
	}
	if value, exists := settings["ExtendedKeyUsageLines"]; exists {
		text, ok := value.(string)
		if !ok {
			return errors.New("ACME extended key usage must be text")
		}
		values, err := certificateNameLines(text)
		if err != nil {
			return err
		}
		if len(values) > 0 {
			payload["ExtendedKeyUsage"] = values
		}
	}
	return validateACMECertificatePayload(payload, scope, nil)
}

// The fixed Intel list is derived from Apple's T2 support article and its model
// identification pages. Never infer T2 support from an arbitrary model prefix,
// a macOS version or the presence of a generic SecureBoot dictionary.
// Sources: support.apple.com/103265, /108052, /102869, /108054, /102852, /102887.
func macHasT2(model string) bool {
	switch model {
	case "MacBookPro15,1", "MacBookPro15,2", "MacBookPro15,3", "MacBookPro15,4",
		"MacBookPro16,1", "MacBookPro16,2", "MacBookPro16,3", "MacBookPro16,4",
		"MacBookAir8,1", "MacBookAir8,2", "MacBookAir9,1",
		"iMac20,1", "iMac20,2", "iMacPro1,1", "Macmini8,1", "MacPro7,1":
		return true
	}
	return false
}

func validateACMECertificatePayload(payload map[string]any, scope string, d *Device) error {
	if stringValue(payload, "PayloadType") != "com.apple.security.acme" {
		return nil
	}
	if err := validateCertificateTarget(d, scope, "13.1", "16.0"); err != nil {
		return err
	}
	if _, err := acmeDirectory(stringValue(payload, "DirectoryURL")); err != nil {
		return err
	}
	if !certificateText(payload["ClientIdentifier"], 8192, false) {
		return errors.New("ACME requires a bounded client identifier issued for the target device")
	}
	hardware, ok := payload["HardwareBound"].(bool)
	if !ok {
		return errors.New("ACME HardwareBound must be an explicit boolean")
	}
	size, ok := certificateInteger(payload["KeySize"])
	if !ok {
		return errors.New("ACME key size must be an integer")
	}
	switch payload["KeyType"] {
	case "RSA":
		if hardware || size < 1024 || size > 4096 || size%8 != 0 {
			return errors.New("ACME RSA keys require 1024–4096 bits in multiples of 8 and HardwareBound=false")
		}
	case "ECSECPrimeRandom":
		if size != 192 && size != 256 && size != 384 && size != 521 || hardware && size != 256 && size != 384 {
			return errors.New("ACME EC keys require 192, 256, 384 or 521 bits; hardware-bound keys require 256 or 384")
		}
	default:
		return errors.New("ACME key type must be RSA or ECSECPrimeRandom")
	}
	attest := false
	for _, key := range []string{"Attest", "KeyIsExtractable", "AllowAllAppsAccess"} {
		value, exists := payload[key]
		if !exists {
			continue
		}
		enabled, ok := value.(bool)
		if !ok {
			return errors.New("ACME attestation and key access settings must be booleans")
		}
		if key == "Attest" {
			attest = enabled
		} else if d != nil && d.Family() != PlatformMacOS {
			return errors.New("ACME extractability and application access settings are Mac-only; omit them for iPhone and iPad")
		}
	}
	if attest && !hardware {
		return errors.New("ACME attestation requires a hardware-bound key")
	}
	if hardware && d != nil && d.Family() == PlatformMacOS {
		if CompareVersions(d.OSVersion, "14.0") < 0 {
			return errors.New("hardware-bound ACME keys require macOS 14 or later")
		}
		if !d.InventoryFresh(time.Now()) {
			return errors.New("refresh Mac inventory before assigning a hardware-bound ACME identity")
		}
		if !macHasT2(d.Model) && (d.AppleSilicon == nil || !*d.AppleSilicon) {
			return errors.New("hardware-bound ACME keys require an identified Apple silicon or T2 Mac")
		}
		// T2 Macs ignore Attest; Apple's payload permits it. The issuer must
		// enforce its own attestation policy. Delivery is not attestation proof.
	}
	if err := validateCertificateSubject(payload["Subject"]); err != nil {
		return err
	}
	if value, exists := payload["SubjectAltName"]; exists {
		if err := validateCertificateNames(value, false); err != nil {
			return err
		}
	}
	if value, exists := payload["UsageFlags"]; exists {
		usage, ok := certificateInteger(value)
		if !ok || usage & ^uint64(5) != 0 {
			return errors.New("ACME usage flags must be 0, 1, 4 or 5")
		}
	}
	if value, exists := payload["ExtendedKeyUsage"]; exists {
		values, ok := value.([]any)
		if !ok || len(values) > 64 {
			return errors.New("ACME extended key usage requires up to 64 numeric OIDs")
		}
		for _, value := range values {
			text, ok := value.(string)
			if !ok || !certificateOID(text, false) {
				return errors.New("invalid ACME extended key usage OID")
			}
		}
	}
	return nil
}

// The issuer namespace is the canonical directory URL, not its DNS resolution.
// No issuer discovery request or redirect is followed during profile management.
func acmeDirectory(raw string) (string, error) {
	u, err := certificateURL(raw, true)
	if err != nil {
		return "", errors.New("ACME requires an HTTPS directory URL without credentials or fragments")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if addr, err := netip.ParseAddr(u.Hostname()); err == nil {
		host = addr.String()
	}
	if host == "" {
		return "", errors.New("ACME directory requires a host")
	}
	port := u.Port()
	if port != "" {
		n, _ := strconv.Atoi(port) // certificateURL checked the range.
		port = strconv.Itoa(n)
	}
	if port == "443" {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if u.Path == "" {
		u.Path = "/"
	}
	// Percent-encoded unreserved characters name the same URI resource.
	// Preserve encoded reserved delimiters and path/query case distinctions.
	u.RawPath = acmeCanonicalEscapes(u.EscapedPath())
	return u.String(), nil
}

func acmeCanonicalEscapes(path string) string {
	var result strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '%' && i+2 < len(path) {
			n, err := strconv.ParseUint(path[i+1:i+3], 16, 8)
			if err == nil {
				b := byte(n)
				if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b)) {
					result.WriteByte(b)
				} else {
					result.WriteString(strings.ToUpper(path[i : i+3]))
				}
				i += 2
				continue
			}
		}
		result.WriteByte(path[i])
	}
	return result.String()
}

type acmeClient struct {
	Directory  string `json:"directory"`
	Identifier string `json:"identifier"`
}

func acmeProfileClients(p *Profile, d *Device) ([]acmeClient, error) {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return nil, errors.New("invalid saved ACME profile")
	}
	items, _ := root["PayloadContent"].([]any)
	if len(items) == 0 || len(items) > 100 {
		return nil, errors.New("ACME profile requires 1 to 100 payloads")
	}
	clients := []acmeClient{}
	seen := map[acmeClient]bool{}
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if stringValue(payload, "PayloadType") != "com.apple.security.acme" {
			continue
		}
		if err := validateACMECertificatePayload(payload, p.Scope, d); err != nil {
			return nil, err
		}
		directory, _ := acmeDirectory(stringValue(payload, "DirectoryURL"))
		client := acmeClient{Directory: directory, Identifier: stringValue(payload, "ClientIdentifier")}
		if !seen[client] {
			clients = append(clients, client)
			seen[client] = true
		}
	}
	return clients, nil
}

// Legacy indexing needs only issuer/client references. New schema requirements
// must not erase evidence of a previously delivered client identifier.
func acmeLegacyClients(data []byte) ([]acmeClient, error) {
	var root map[string]any
	if len(data) == 0 || len(data) > MaxProfileBytes {
		return nil, errors.New("invalid archived profile size")
	}
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, errors.New("invalid archived profile")
	}
	items, ok := root["PayloadContent"].([]any)
	if !ok || len(items) == 0 || len(items) > 100 {
		return nil, errors.New("invalid archived profile payloads")
	}
	clients := []acmeClient{}
	seen := map[acmeClient]bool{}
	for _, item := range items {
		payload, ok := item.(map[string]any)
		if !ok || stringValue(payload, "PayloadType") == "" {
			return nil, errors.New("invalid archived profile payload")
		}
		if stringValue(payload, "PayloadType") != "com.apple.security.acme" {
			continue
		}
		directory, err := acmeDirectory(stringValue(payload, "DirectoryURL"))
		if err != nil || !certificateText(payload["ClientIdentifier"], 8192, false) {
			return nil, errors.New("archived ACME profile has no usable client reference")
		}
		client := acmeClient{Directory: directory, Identifier: stringValue(payload, "ClientIdentifier")}
		if !seen[client] {
			clients = append(clients, client)
			seen[client] = true
		}
	}
	return clients, nil
}
