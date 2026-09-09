package apple

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"howett.net/plist"
)

// Validate the outer VPN configuration and DNS settings. Protocol-specific
// authentication, routing and Always On tunnel settings have separate schemas;
// this check does not establish provider installation or tunnel connectivity.
func validateVPNPayload(payload map[string]any, scope string, d *Device) error {
	kind := stringValue(payload, "PayloadType")
	if kind != "com.apple.vpn.managed" && kind != "com.apple.vpn.managed.applayer" {
		return nil
	}
	if scope != "System" && scope != "User" {
		return errors.New("VPN profile scope must be System or User")
	}
	if !certificateText(payload["UserDefinedName"], 255, false) {
		return errors.New("VPN configurations require a connection name of up to 255 bytes")
	}
	protocol := stringValue(payload, "VPNType")
	key := protocol
	switch protocol {
	case "VPN", "IPSec", "IKEv2", "AlwaysOn", "TransparentProxy":
	case "L2TP":
		key = "PPP"
	default:
		return errors.New("unsupported VPN type")
	}
	if _, ok := payload[key].(map[string]any); !ok {
		return errors.New("the selected VPN type requires its configuration dictionary")
	}
	for _, key := range []string{"VPN", "IPSec", "IKEv2", "PPP", "AlwaysOn", "TransparentProxy", "DNS", "Proxies", "IPv4", "VendorConfig"} {
		if value, exists := payload[key]; exists {
			if _, ok := value.(map[string]any); !ok {
				return errors.New("VPN configuration sections must be dictionaries")
			}
		}
	}
	if protocol == "VPN" || protocol == "TransparentProxy" {
		if !certificateText(payload["VPNSubType"], 255, false) {
			return errors.New("provider VPN and transparent proxy configurations require a provider identifier")
		}
	}
	if value, exists := payload["VPNSubType"]; exists {
		if !certificateText(value, 255, true) || protocol == "IKEv2" && value != "" {
			return errors.New("invalid VPN provider identifier; IKEv2 requires an absent or empty subtype")
		}
	}
	macMinimum, phoneMinimum := "10.7", "4.0"
	advance := func(mac, phone string) {
		if CompareVersions(macMinimum, mac) < 0 {
			macMinimum = mac
		}
		if CompareVersions(phoneMinimum, phone) < 0 {
			phoneMinimum = phone
		}
	}
	appLayer := kind == "com.apple.vpn.managed.applayer"
	if appLayer {
		if protocol != "VPN" && protocol != "IPSec" && protocol != "IKEv2" {
			return errors.New("App-Layer VPN supports VPN, IPSec or IKEv2")
		}
		if _, err := certificateReferenceUUID(payload["VPNUUID"]); err != nil {
			return errors.New("App-Layer VPN requires a canonical nonzero connection UUID")
		}
		advance("10.9", "7.0")
	}
	if dns, exists := payload["DNS"].(map[string]any); exists {
		if err := validateVPNDNS(dns, advance); err != nil {
			return err
		}
	}
	_, transparent := payload["TransparentProxy"]
	if transparent {
		if appLayer {
			return errors.New("transparent proxy configuration is unavailable in App-Layer VPN")
		}
		advance("14.0", "4.0")
	}
	_, always := payload["AlwaysOn"]
	if always {
		if scope != "System" || appLayer {
			return errors.New("Always On VPN requires a System device profile")
		}
		advance("10.7", "8.0")
		if err := validateAlwaysOnStructure(payload["AlwaysOn"].(map[string]any)); err != nil {
			return err
		}
	}
	if d == nil {
		return nil
	}
	minimum := phoneMinimum
	switch d.Family() {
	case PlatformMacOS:
		minimum = macMinimum
		if always {
			return errors.New("Always On VPN requires an iPhone or iPad")
		}
	case PlatformIOS, PlatformIPadOS:
		if scope != "System" || transparent {
			return errors.New("User VPN profiles and transparent proxies require a Mac")
		}
	default:
		return errors.New("refresh inventory to identify the VPN target platform")
	}
	if !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, minimum) < 0 {
		return fmt.Errorf("this VPN configuration requires %s %s or later", d.Family(), minimum)
	}
	management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
	if enrolled, _ := management["IsUserEnrollment"].(bool); enrolled && !appLayer {
		return errors.New("regular VPN profiles are unavailable with User Enrollment")
	}
	if always {
		now := time.Now()
		if !d.Supervised || !d.SupervisedReported || d.InventoryAt == nil || d.InventoryAt.After(now) || now.Sub(*d.InventoryAt) > 24*time.Hour {
			return errors.New("Always On VPN requires fresh device inventory reporting supervision")
		}
	}
	return nil
}

func validateVPNDNS(dns map[string]any, advance func(string, string)) error {
	protocol := stringValue(dns, "DNSProtocol")
	if value, exists := dns["DNSProtocol"]; exists {
		if value != "Cleartext" && value != "HTTPS" && value != "TLS" {
			return errors.New("VPN DNS protocol must be Cleartext, HTTPS or TLS")
		}
		advance("11.0", "14.0")
	}
	if value, exists := dns["ServerURL"]; exists || protocol == "HTTPS" {
		url, ok := value.(string)
		if !ok {
			return errors.New("DNS over HTTPS requires an HTTPS resolver URL")
		}
		if _, err := certificateURL(url, true); err != nil {
			return errors.New("VPN DNS resolver URLs require HTTPS without credentials or fragments")
		}
		advance("11.0", "14.0")
	}
	if value, exists := dns["ServerName"]; exists || protocol == "TLS" {
		if !adCertificateServer(value) {
			return errors.New("DNS over TLS requires a fully qualified resolver name")
		}
		advance("11.0", "14.0")
	}
	for _, key := range []string{"ServerAddresses", "SearchDomains", "SupplementalMatchDomains"} {
		if value, exists := dns[key]; exists {
			list, ok := value.([]any)
			if !ok || len(list) == 0 || len(list) > 64 {
				return errors.New("VPN DNS lists require 1 to 64 entries")
			}
			for _, value := range list {
				if !certificateText(value, 254, key == "SupplementalMatchDomains") {
					return errors.New("invalid VPN DNS list entry")
				}
				text := value.(string)
				if text != strings.TrimSpace(text) || key == "ServerAddresses" && net.ParseIP(text) == nil {
					return errors.New("VPN DNS server addresses must be IPv4 or IPv6 literals; domains cannot have surrounding whitespace")
				}
			}
			advance("10.12", "10.0")
		}
	}
	if value, exists := dns["DomainName"]; exists {
		if !certificateText(value, 254, false) {
			return errors.New("invalid VPN DNS primary domain")
		}
		advance("10.12", "10.0")
	}
	if value, exists := dns["SupplementalMatchDomainsNoSearch"]; exists {
		flag, ok := certificateInteger(value)
		if !ok || flag > 1 {
			return errors.New("VPN DNS search behavior must be integer 0 or 1")
		}
		advance("10.12", "10.0")
	}
	if value, exists := dns["PayloadCertificateUUID"]; exists {
		if _, err := certificateReferenceUUID(value); err != nil {
			return err
		}
		advance("13.0", "16.0")
	}
	return nil
}

func validateAlwaysOnStructure(always map[string]any) error {
	tunnels, ok := always["TunnelConfigurations"].([]any)
	if !ok || len(tunnels) == 0 || len(tunnels) > 64 {
		return errors.New("Always On VPN requires 1 to 64 tunnel dictionaries")
	}
	for _, value := range tunnels {
		tunnel, ok := value.(map[string]any)
		if !ok || stringValue(tunnel, "ProtocolType") != "IKEv2" {
			return errors.New("each Always On tunnel must select IKEv2")
		}
		if value, exists := tunnel["Interfaces"]; exists {
			interfaces, ok := value.([]any)
			if !ok || len(interfaces) == 0 || len(interfaces) > 2 {
				return errors.New("Always On tunnel interfaces must select WiFi, Cellular or both")
			}
			seen := map[string]bool{}
			for _, value := range interfaces {
				name, ok := value.(string)
				if !ok || name != "WiFi" && name != "Cellular" || seen[name] {
					return errors.New("Always On tunnel interfaces must be unique WiFi or Cellular values")
				}
				seen[name] = true
			}
		}
	}
	return nil
}

func validateVPNProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved VPN profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validateVPNPayload(payload, p.Scope, d); err != nil {
			return err
		}
	}
	return nil
}
