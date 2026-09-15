package apple

import (
	"errors"
	"net"
	"slices"
	"strings"
)

func vpnServerAddress(value any) bool {
	if !certificateText(value, 254, false) {
		return false
	}
	text := value.(string)
	if net.ParseIP(text) != nil {
		return true
	}
	text = strings.TrimSuffix(text, ".")
	if len(text) == 0 || len(text) > 253 {
		return false
	}
	for _, label := range strings.Split(text, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Every flag listed here is an integer on the wire, including explicit zero.
// Empty macOS versions identify settings unavailable on the Mac platform.
var ikev2FlagVersions = map[string][2]string{
	"ExtendedAuthEnabled": {"10.11", "8.0"}, "OnDemandEnabled": {"10.11", "8.0"}, "DisconnectOnIdle": {"10.11", "8.0"},
	"UseConfigurationAttributeInternalIPSubnet": {"10.11", "9.0"}, "DisableMOBIKE": {"10.11", "9.0"}, "DisableRedirect": {"10.11", "9.0"},
	"NATKeepAliveOffloadEnable": {"10.11", "9.0"}, "EnablePFS": {"10.11", "9.0"}, "EnableCertificateRevocationCheck": {"10.11", "9.0"},
	"EnableFallback": {"", "13.0"}, "OnDemandUserOverrideDisabled": {"", "14.0"},
	"IncludeAllNetworks": {"10.15", "14.0"}, "EnforceRoutes": {"11.0", "14.2"}, "ExcludeLocalNetworks": {"10.15", "14.2"},
	"ExcludeCellularServices": {"13.3", "16.4"}, "ExcludeAPNs": {"13.3", "16.4"}, "ExcludeDeviceCommunication": {"14.4", "17.4"},
	"PPKMandatory": {"15.0", "18.0"}, "EnforceStrictAlgorithmSelection": {"15.5", "18.5"}, "AllowPostQuantumKeyExchangeFallback": {"26.0", "26.0"},
}

func validateIKEv2Configuration(c map[string]any, scope string, d *Device, advance func(string, string)) error {
	advance("10.11", "8.0")
	if err := validateIKEv2OnDemand(c); err != nil {
		return err
	}
	if !vpnServerAddress(c["RemoteAddress"]) || !certificateText(c["LocalIdentifier"], 255, false) || !certificateText(c["RemoteIdentifier"], 255, false) {
		return errors.New("IKEv2 requires a server hostname or IP address and bounded local and remote identifiers")
	}
	if !slices.Contains([]string{"None", "SharedSecret", "Certificate"}, stringValue(c, "AuthenticationMethod")) {
		return errors.New("IKEv2 requires None, SharedSecret or Certificate authentication")
	}
	for key, limit := range map[string]int{"AuthName": 255, "AuthPassword": 4096, "Password": 4096, "SharedSecret": 4096, "ServerCertificateCommonName": 255, "ServerCertificateIssuerCommonName": 255, "ProviderBundleIdentifier": 255, "ProviderDesignatedRequirement": 8192} {
		if value, exists := c[key]; exists {
			if !certificateText(value, limit, key == "AuthPassword" || key == "Password" || key == "SharedSecret") {
				return errors.New("invalid IKEv2 account, certificate, provider or secret setting")
			}
			if key == "ProviderDesignatedRequirement" {
				advance("10.15", "8.0")
				if d != nil && d.Family() != PlatformMacOS {
					return errors.New("IKEv2 provider signature requirements require a Mac")
				}
			}
		}
	}
	if value, exists := c["CertificateType"]; exists {
		name, ok := value.(string)
		if !ok || !slices.Contains([]string{"RSA", "ECDSA256", "ECDSA384", "ECDSA521", "RSA-PSS"}, name) || !certificateText(c["ServerCertificateIssuerCommonName"], 255, false) {
			return errors.New("an explicit IKEv2 certificate type requires a supported algorithm and server certificate issuer name")
		}
	}
	for key, versions := range ikev2FlagVersions {
		if value, exists := c[key]; exists {
			flag, ok := certificateInteger(value)
			if !ok || flag > 1 {
				return errors.New("IKEv2 switches must be integer 0 or 1")
			}
			if versions[0] == "" && (scope == "User" || d != nil && d.Family() == PlatformMacOS) {
				return errors.New("this IKEv2 setting is unavailable on a Mac")
			}
			advance(versions[0], versions[1])
		}
	}
	minimum, maximum := "1.0", "1.2"
	for _, key := range []string{"TLSMinimumVersion", "TLSMaximumVersion"} {
		if value, exists := c[key]; exists {
			version, ok := value.(string)
			if !ok || !slices.Contains([]string{"1.0", "1.1", "1.2"}, version) {
				return errors.New("IKEv2 EAP TLS versions must be 1.0, 1.1 or 1.2")
			}
			if key == "TLSMinimumVersion" {
				minimum = version
			} else {
				maximum = version
			}
			advance("10.13", "11.0")
		}
	}
	if minimum > maximum {
		return errors.New("IKEv2 TLS minimum cannot exceed its maximum")
	}
	for _, key := range []string{"DisconnectOnIdleTimer", "NATKeepAliveInterval", "MTU"} {
		if value, exists := c[key]; exists {
			n, ok := certificateInteger(value)
			if !ok || n > 2147483647 || key == "NATKeepAliveInterval" && n < 20 || key == "MTU" && (n < 1280 || n > 1400) {
				return errors.New("invalid IKEv2 idle timer, NAT keepalive interval or MTU")
			}
			if key == "MTU" {
				advance("11.0", "14.0")
			}
			if key == "NATKeepAliveInterval" {
				advance("10.11", "9.0")
			}
		}
	}
	if value, exists := c["DeadPeerDetectionRate"]; exists {
		rate, ok := value.(string)
		if !ok || !slices.Contains([]string{"None", "Low", "Medium", "High"}, rate) {
			return errors.New("invalid IKEv2 dead peer detection rate")
		}
	}
	if value, exists := c["ProviderType"]; exists && value != "packet-tunnel" && value != "app-proxy" {
		return errors.New("invalid IKEv2 provider type")
	}
	ppk, hasPPK := c["PPK"]
	identifier, hasID := c["PPKIdentifier"]
	if hasPPK || hasID {
		data, ok := ppk.([]byte)
		if !hasPPK || !hasID || !ok || len(data) == 0 || len(data) > 4096 || !certificateText(identifier, 255, false) {
			return errors.New("IKEv2 post-quantum pre-shared keys require bounded key data and an identifier together")
		}
		advance("15.0", "18.0")
	}
	strict, _ := certificateInteger(c["EnforceStrictAlgorithmSelection"])
	ike := map[string]any{}
	if value, exists := c["IKESecurityAssociationParameters"]; exists {
		var ok bool
		ike, ok = value.(map[string]any)
		if !ok {
			return errors.New("IKEv2 security association parameters must be dictionaries")
		}
	}
	child := ike
	if value, exists := c["ChildSecurityAssociationParameters"]; exists {
		var ok bool
		child, ok = value.(map[string]any)
		if !ok {
			return errors.New("IKEv2 security association parameters must be dictionaries")
		}
	}
	ikeStrength, err := validateIKEv2SecurityAssociation(ike, strict == 1, d, advance)
	if err != nil {
		return err
	}
	childStrength, err := validateIKEv2SecurityAssociation(child, strict == 1, d, advance)
	if err != nil {
		return err
	}
	if strict == 1 && ikeStrength < childStrength {
		return errors.New("strict IKEv2 selection requires IKE encryption at least as strong as child encryption")
	}
	return nil
}

func validateIKEv2SecurityAssociation(sa map[string]any, strict bool, d *Device, advance func(string, string)) (int, error) {
	encryption, integrity, group := "AES-256", "SHA2-256", uint64(14)
	strengths := map[string]int{"DES": 56, "3DES": 112, "AES-128": 128, "AES-256": 256, "AES-128-GCM": 128, "AES-256-GCM": 256, "ChaCha20Poly1305": 256}
	if value, exists := sa["EncryptionAlgorithm"]; exists {
		var ok bool
		encryption, ok = value.(string)
		if !ok || strengths[encryption] == 0 {
			return 0, errors.New("unsupported IKEv2 encryption algorithm")
		}
	}
	if value, exists := sa["IntegrityAlgorithm"]; exists {
		var ok bool
		integrity, ok = value.(string)
		if !ok || !slices.Contains([]string{"SHA1-96", "SHA1-160", "SHA2-256", "SHA2-384", "SHA2-512"}, integrity) {
			return 0, errors.New("unsupported IKEv2 integrity algorithm")
		}
	}
	if value, exists := sa["DiffieHellmanGroup"]; exists {
		var ok bool
		group, ok = certificateInteger(value)
		if !ok || !slices.Contains([]uint64{1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 31, 32}, group) {
			return 0, errors.New("unsupported IKEv2 Diffie-Hellman group")
		}
	}
	legacy := encryption == "DES" || encryption == "3DES" || group < 14
	if strict && legacy || d != nil && versionPattern.MatchString(d.OSVersion) && CompareVersions(d.OSVersion, "26.0") >= 0 && (legacy || strings.HasPrefix(integrity, "SHA1-")) {
		return 0, errors.New("legacy IKEv2 algorithms are unavailable with strict selection or this OS version")
	}
	if value, exists := sa["LifeTimeInMinutes"]; exists {
		minutes, ok := certificateInteger(value)
		if !ok || minutes < 10 || minutes > 1440 {
			return 0, errors.New("IKEv2 security association lifetime must be 10 to 1440 minutes")
		}
	}
	if value, exists := sa["PostQuantumKeyExchangeMethods"]; exists {
		methods, ok := value.([]any)
		if !ok || len(methods) == 0 || len(methods) > 7 {
			return 0, errors.New("IKEv2 post-quantum exchanges require 1 to 7 methods")
		}
		for _, value := range methods {
			method, ok := certificateInteger(value)
			if !ok || method != 0 && method != 36 && method != 37 {
				return 0, errors.New("unsupported IKEv2 post-quantum key exchange method")
			}
		}
		advance("26.0", "26.0")
	}
	return strengths[encryption], nil
}
