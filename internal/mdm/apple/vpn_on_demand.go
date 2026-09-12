package apple

import (
	"errors"
	"net"
	"slices"
	"unicode/utf8"
)

// These are ordered rules: never sort, merge, deduplicate or insert defaults.
// Match patterns remain device-interpreted strings. This validates structure,
// actions and probes without claiming to simulate Apple's network decisions.
func validateIKEv2OnDemand(c map[string]any) error {
	value, exists := c["OnDemandRules"]
	if !exists {
		return nil
	}
	rules, ok := value.([]any)
	if !ok || len(rules) > 64 {
		return errors.New("IKEv2 on-demand rules must be an array of at most 64 entries")
	}
	for _, value := range rules {
		rule, ok := value.(map[string]any)
		if !ok {
			return errors.New("IKEv2 on-demand rules must be dictionaries")
		}
		for key := range rule {
			if !slices.Contains([]string{"Action", "ActionParameters", "DNSDomainMatch", "DNSServerAddressMatch", "InterfaceTypeMatch", "SSIDMatch", "URLStringProbe"}, key) {
				return errors.New("unsupported IKEv2 on-demand rule field")
			}
		}
		action := stringValue(rule, "Action")
		if !slices.Contains([]string{"Allow", "Connect", "Disconnect", "EvaluateConnection", "Ignore"}, action) {
			return errors.New("IKEv2 on-demand rules require a supported action")
		}
		for _, key := range []string{"DNSDomainMatch", "DNSServerAddressMatch"} {
			if value, exists := rule[key]; exists && !vpnOnDemandTextArray(value, false) {
				return errors.New("IKEv2 on-demand match lists require at most 64 bounded text values")
			}
		}
		if value, exists := rule["InterfaceTypeMatch"]; exists {
			if name, ok := value.(string); !ok || !slices.Contains([]string{"Ethernet", "WiFi", "Cellular"}, name) {
				return errors.New("IKEv2 on-demand interface must be Ethernet, WiFi or Cellular")
			}
		}
		if value, exists := rule["SSIDMatch"]; exists {
			ssids, ok := value.([]any)
			if !ok || len(ssids) > 64 {
				return errors.New("IKEv2 on-demand SSIDs must be an array of at most 64 entries")
			}
			for _, value := range ssids {
				ssid, ok := value.(string)
				if !ok || len(ssid) == 0 || len(ssid) > 32 || !utf8.ValidString(ssid) {
					return errors.New("IKEv2 on-demand SSIDs require 1 to 32 UTF-8 bytes")
				}
			}
		}
		if value, exists := rule["URLStringProbe"]; exists && !vpnOnDemandProbe(value) {
			return errors.New("IKEv2 on-demand probes require bounded HTTP or HTTPS URLs without credentials or fragments")
		}
		if value, exists := rule["ActionParameters"]; exists {
			if action != "EvaluateConnection" {
				return errors.New("IKEv2 on-demand action parameters require EvaluateConnection")
			}
			if err := validateVPNOnDemandParameters(value); err != nil {
				return err
			}
		}
	}
	return nil
}

func vpnOnDemandTextArray(value any, required bool) bool {
	items, ok := value.([]any)
	if !ok || len(items) > 64 || required && len(items) == 0 {
		return false
	}
	for _, value := range items {
		if !certificateText(value, 254, false) {
			return false
		}
	}
	return true
}

func vpnOnDemandProbe(value any) bool {
	raw, ok := value.(string)
	if !ok {
		return false
	}
	_, err := certificateURL(raw, false)
	return err == nil
}

func validateVPNOnDemandParameters(value any) error {
	parameters, ok := value.([]any)
	if !ok || len(parameters) > 64 {
		return errors.New("IKEv2 connection evaluations must be an array of at most 64 entries")
	}
	for _, value := range parameters {
		parameter, ok := value.(map[string]any)
		if !ok {
			return errors.New("IKEv2 connection evaluations must be dictionaries")
		}
		for key := range parameter {
			if !slices.Contains([]string{"Domains", "DomainAction", "RequiredDNSServers", "RequiredURLStringProbe"}, key) {
				return errors.New("unsupported IKEv2 connection evaluation field")
			}
		}
		action := stringValue(parameter, "DomainAction")
		if action != "ConnectIfNeeded" && action != "NeverConnect" || !vpnOnDemandTextArray(parameter["Domains"], true) {
			return errors.New("IKEv2 connection evaluations require domains and ConnectIfNeeded or NeverConnect")
		}
		if value, exists := parameter["RequiredDNSServers"]; exists {
			if action != "ConnectIfNeeded" || !vpnOnDemandTextArray(value, true) {
				return errors.New("IKEv2 required DNS servers require ConnectIfNeeded and a nonempty address list")
			}
			for _, server := range value.([]any) {
				if net.ParseIP(server.(string)) == nil {
					return errors.New("IKEv2 required DNS servers must be IP address literals")
				}
			}
		}
		if value, exists := parameter["RequiredURLStringProbe"]; exists && (action != "ConnectIfNeeded" || !vpnOnDemandProbe(value)) {
			return errors.New("IKEv2 required probes require ConnectIfNeeded and an HTTP or HTTPS URL without credentials or fragments")
		}
	}
	return nil
}
