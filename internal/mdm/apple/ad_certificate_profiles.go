package apple

import (
	"errors"
	"net"
	"strings"

	"howett.net/plist"
)

var adCertificateKeys = []string{"CertServer", "CertTemplate", "Description", "CertificateRenewalTimeInterval", "CertificateAuthority", "CertificateAcquisitionMechanism", "AllowAllAppsAccess", "PromptForCredentials", "KeyIsExtractable", "Keysize", "EnableAutoRenewal"}

func adCertificateServer(value any) bool {
	if !certificateText(value, 254, false) {
		return false
	}
	name := strings.TrimSuffix(value.(string), ".")
	if len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
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

func buildADCertificatePayload(payload, settings map[string]any, scope string) error {
	payload["PayloadType"] = "com.apple.ADCertificate.managed"
	for _, key := range adCertificateKeys {
		if value, exists := settings[key]; exists && value != "" {
			payload[key] = value
		}
	}
	return validateADCertificatePayload(payload, scope, nil)
}

func validateADCertificatePayload(payload map[string]any, scope string, d *Device) error {
	if stringValue(payload, "PayloadType") != "com.apple.ADCertificate.managed" {
		return nil
	}
	if scope != "System" && scope != "User" {
		return errors.New("Active Directory certificate scope must be System or User")
	}
	if !adCertificateServer(payload["CertServer"]) || !certificateText(payload["CertTemplate"], 255, false) {
		return errors.New("Active Directory certificates require a fully qualified DNS certificate server and a bounded template name")
	}
	minimum := "10.7"
	advance := func(version string) {
		if CompareVersions(minimum, version) < 0 {
			minimum = version
		}
	}
	for key, limit := range map[string]int{"Description": 1024, "CertificateAuthority": 2048} {
		if value, exists := payload[key]; exists {
			if !certificateText(value, limit, key == "Description") {
				return errors.New("invalid Active Directory certificate description or authority name")
			}
			if key == "CertificateAuthority" {
				advance("10.8")
			}
		}
	}
	if value, exists := payload["CertificateAcquisitionMechanism"]; exists {
		if value != "RPC" && value != "HTTP" {
			return errors.New("select RPC or HTTP for Active Directory certificate acquisition")
		}
		advance("10.8")
	}
	if value, exists := payload["CertificateRenewalTimeInterval"]; exists {
		days, ok := certificateInteger(value)
		if !ok || days > 3650 {
			return errors.New("certificate renewal notification must be 0 to 3650 days before expiry")
		}
	}
	if value, exists := payload["Keysize"]; exists {
		size, ok := certificateInteger(value)
		if !ok || size < 1024 || size > 8192 || size%8 != 0 {
			return errors.New("Active Directory RSA keys must be 1024 to 8192 bits in multiples of 8")
		}
		advance("10.11")
	}
	for key, version := range map[string]string{"AllowAllAppsAccess": "10.10", "KeyIsExtractable": "10.10", "PromptForCredentials": "10.8", "EnableAutoRenewal": "10.13.4"} {
		if value, exists := payload[key]; exists {
			enabled, ok := value.(bool)
			if !ok {
				return errors.New("Active Directory certificate switches must be booleans")
			}
			advance(version)
			if key == "PromptForCredentials" && (scope == "System" || enabled) {
				return errors.New("omit interactive credential prompting for MDM-delivered Active Directory certificates")
			}
			if key == "EnableAutoRenewal" && enabled && scope != "System" {
				return errors.New("automatic Active Directory certificate renewal requires System scope")
			}
		}
	}
	if d != nil && d.Family() != PlatformMacOS {
		return errors.New("Active Directory certificates require a Mac")
	}
	return validateCertificateTarget(d, scope, minimum, "999.0")
}

func validateADCertificateProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved Active Directory certificate profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validateADCertificatePayload(payload, p.Scope, d); err != nil {
			return err
		}
	}
	return nil
}
