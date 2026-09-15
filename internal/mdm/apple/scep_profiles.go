package apple

import (
	"encoding/hex"
	"errors"
	"strings"

	"howett.net/plist"
)

func buildSCEPCertificatePayload(payload, settings map[string]any, scope string) error {
	content := map[string]any{"URL": settings["URL"], "Key Type": "RSA", "Keysize": settings["Keysize"]}
	for _, key := range []string{"Name", "Challenge", "Key Usage", "Retries", "RetryDelay", "KeyIsExtractable", "AllowAllAppsAccess"} {
		if value, exists := settings[key]; exists {
			content[key] = value
		}
	}
	if raw, exists := settings["SubjectLines"]; exists {
		text, ok := raw.(string)
		if !ok {
			return errors.New("certificate subject must be text")
		}
		subject, err := certificateSubjectLines(text)
		if err != nil {
			return err
		}
		if len(subject) > 0 {
			content["Subject"] = subject
		}
	}
	names := map[string]any{}
	for _, key := range []string{"rfc822Name", "dNSName", "uniformResourceIdentifier", "ntPrincipalName"} {
		if raw, exists := settings[key]; exists {
			text, ok := raw.(string)
			if !ok {
				return errors.New("certificate name lists must be text")
			}
			values, err := certificateNameLines(text)
			if err != nil {
				return err
			}
			if len(values) == 1 {
				names[key] = values[0]
			} else if len(values) > 1 {
				names[key] = values
			}
		}
	}
	if len(names) > 0 {
		content["SubjectAltName"] = names
	}
	if raw, exists := settings["Fingerprint"]; exists {
		text, ok := raw.(string)
		if !ok || len(text) > 128 {
			return errors.New("CA fingerprint must be hexadecimal text")
		}
		text = strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(text))
		if text != "" {
			fingerprint, err := hex.DecodeString(text)
			if err != nil || len(fingerprint) != 16 && len(fingerprint) != 20 {
				return errors.New("enter a 20-byte SHA-1 or 16-byte MD5 CA fingerprint")
			}
			content["CAFingerprint"] = fingerprint
		}
	}
	payload["PayloadType"] = "com.apple.security.scep"
	payload["PayloadContent"] = content
	return validateSCEPCertificatePayload(payload, scope, nil)
}

func validateSCEPCertificatePayload(payload map[string]any, scope string, d *Device) error {
	if stringValue(payload, "PayloadType") != "com.apple.security.scep" {
		return nil
	}
	if err := validateCertificateTarget(nil, scope, "10.7", "4.0"); err != nil {
		return err
	}
	content, ok := payload["PayloadContent"].(map[string]any)
	if !ok {
		return errors.New("SCEP requires a configuration dictionary")
	}
	address, err := certificateURL(stringValue(content, "URL"), false)
	if err != nil {
		return err
	}
	for key, maximum := range map[string]int{"Name": 255, "Challenge": 8192} {
		if value, exists := content[key]; exists && !certificateText(value, maximum, true) {
			return errors.New("invalid SCEP authority name or challenge")
		}
	}
	if value, exists := content["Key Type"]; exists && value != "RSA" {
		return errors.New("SCEP key type must be RSA")
	}
	if value, exists := content["Keysize"]; exists {
		size, ok := certificateInteger(value)
		if !ok || size != 1024 && size != 2048 && size != 4096 {
			return errors.New("SCEP RSA keys must be 1024, 2048 or 4096 bits")
		}
	}
	minimum := "10.7"
	advance := func(version string) {
		if CompareVersions(minimum, version) < 0 {
			minimum = version
		}
	}
	if value, exists := content["Key Usage"]; exists {
		usage, ok := certificateInteger(value)
		if !ok || usage & ^uint64(5) != 0 {
			return errors.New("SCEP key usage must be 0, 1, 4 or 5")
		}
		advance("10.11")
	}
	for _, key := range []string{"Retries", "RetryDelay"} {
		if value, exists := content[key]; exists {
			n, ok := certificateInteger(value)
			maximum := uint64(100)
			if key == "RetryDelay" {
				maximum = 86400
			}
			if !ok || n > maximum {
				return errors.New("SCEP supports 0 to 100 retries and a delay of 0 to 86400 seconds")
			}
			advance("10.10")
		}
	}
	for key, version := range map[string]string{"KeyIsExtractable": "10.13.4", "AllowAllAppsAccess": "10.10"} {
		if value, exists := content[key]; exists {
			if _, ok := value.(bool); !ok {
				return errors.New("SCEP key access settings must be booleans")
			}
			advance(version)
		}
	}
	if value, exists := content["Subject"]; exists {
		if err := validateCertificateSubject(value); err != nil {
			return err
		}
	}
	if value, exists := content["SubjectAltName"]; exists {
		if err := validateCertificateNames(value, true); err != nil {
			return err
		}
	}
	if value, exists := content["CAFingerprint"]; exists {
		fingerprint, ok := value.([]byte)
		if !ok || len(fingerprint) != 16 && len(fingerprint) != 20 {
			return errors.New("SCEP requires a binary SHA-1 or MD5 CA fingerprint")
		}
	} else if address.Scheme == "http" {
		return errors.New("HTTP SCEP requires a CA fingerprint; use HTTPS or provide the approved CA fingerprint")
	}
	return validateCertificateTarget(d, scope, minimum, "4.0")
}

func validateSCEPCertificateProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved SCEP profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validateSCEPCertificatePayload(payload, p.Scope, d); err != nil {
			return err
		}
	}
	return nil
}
