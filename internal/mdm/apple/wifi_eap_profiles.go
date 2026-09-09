package apple

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"howett.net/plist"
)

func wifiServerName(value any) bool {
	if !certificateText(value, 255, false) {
		return false
	}
	name := value.(string)
	if strings.TrimSpace(name) != name || name == "*" {
		return false
	}
	for _, component := range strings.Split(name, ".") {
		if component == "" || strings.Contains(component, "*") && component != "*" {
			return false
		}
	}
	return true
}

func certificateCompositionSource(data []byte, scope string, identity bool) ([]map[string]any, error) {
	if len(data) == 0 || len(data) > MaxProfileBytes {
		return nil, errors.New("select a bounded certificate profile revision")
	}
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil || stringValue(root, "PayloadType") != "Configuration" || numberValue(root["PayloadVersion"]) != 1 {
		return nil, errors.New("invalid source certificate profile")
	}
	if _, err := certificateReferenceUUID(root["PayloadUUID"]); err != nil {
		return nil, errors.New("invalid source certificate profile identity")
	}
	storedScope := stringValue(root, "PayloadScope")
	if _, exists := root["PayloadScope"]; !exists {
		storedScope = "System"
	}
	if scope != storedScope || scope != "System" && scope != "User" {
		return nil, errors.New("source certificates and Wi-Fi must use the same profile scope")
	}
	items, ok := root["PayloadContent"].([]any)
	if !ok || len(items) == 0 || len(items) > 16 || identity && len(items) != 1 {
		return nil, errors.New("select one identity payload or 1 to 16 public certificate payloads")
	}
	result := make([]map[string]any, 0, len(items))
	ids := map[string]bool{}
	for _, item := range items {
		p, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid source certificate payload")
		}
		id, err := certificateReferenceUUID(p["PayloadUUID"])
		if err != nil || ids[id] || numberValue(p["PayloadVersion"]) != 1 || stringValue(p, "PayloadIdentifier") == "" {
			return nil, errors.New("source certificate payloads require unique identities and version 1")
		}
		ids[id] = true
		kind := stringValue(p, "PayloadType")
		if identity {
			switch kind {
			case "com.apple.security.scep":
				err = validateSCEPCertificatePayload(p, scope, nil)
			case "com.apple.security.acme":
				err = validateACMECertificatePayload(p, scope, nil)
			case "com.apple.security.pkcs12":
				err = validatePKCS12Payload(p, scope, nil)
			case "com.apple.ADCertificate.managed":
				if !certificateText(p["CertServer"], 512, false) || !certificateText(p["CertTemplate"], 512, false) {
					err = errors.New("Active Directory identities require a certificate server and template")
				}
			default:
				err = errors.New("select an ACME, SCEP, PKCS12 or Active Directory certificate identity profile")
			}
		} else {
			switch kind {
			case "com.apple.security.root", "com.apple.security.pem", "com.apple.security.pkcs1":
				err = validatePublicCertificatePayload(p, scope, nil)
			default:
				err = errors.New("select a profile containing only public trust certificates")
			}
		}
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}

func buildWiFiEAPTLSPayload(payload, settings map[string]any, scope string) ([]any, error) {
	ssid, ok := settings["SSID_STR"].(string)
	if !ok || len(ssid) == 0 || len(ssid) > 32 || !utf8.ValidString(ssid) || strings.ContainsAny(ssid, "\x00\r\n") {
		return nil, errors.New("Wi-Fi SSID must contain 1 to 32 UTF-8 bytes without line breaks")
	}
	security := stringValue(settings, "EncryptionType")
	if security != "WPA2" && security != "WPA3" {
		return nil, errors.New("select WPA2/WPA3 compatibility or WPA3-only Wi-Fi")
	}
	minimum, maximum := stringValue(settings, "TLSMinimumVersion"), stringValue(settings, "TLSMaximumVersion")
	if minimum != "1.2" && minimum != "1.3" || maximum != "1.2" && maximum != "1.3" || minimum > maximum {
		return nil, errors.New("select a TLS 1.2 or 1.3 range with minimum no greater than maximum")
	}
	namesText, ok := settings["ServerNameLines"].(string)
	if !ok {
		return nil, errors.New("enter the trusted RADIUS server certificate names")
	}
	names, err := certificateNameLines(namesText)
	if err != nil || len(names) == 0 {
		return nil, errors.New("enter 1 to 64 trusted RADIUS server certificate names")
	}
	for _, name := range names {
		if !wifiServerName(name) {
			return nil, errors.New("enter bounded server certificate names; a wildcard must occupy one whole name component")
		}
	}
	identityData, ok := settings["IdentityProfileData"].([]byte)
	if !ok {
		return nil, errors.New("select an identity certificate profile revision")
	}
	identities, err := certificateCompositionSource(identityData, scope, true)
	if err != nil {
		return nil, err
	}
	base := stringValue(payload, "PayloadIdentifier")
	identity := identities[0]
	identity["PayloadUUID"] = uuid.NewString()
	identity["PayloadIdentifier"] = base + ".identity"
	additional := []any{identity}
	eap := map[string]any{"AcceptEAPTypes": []any{13}, "TLSTrustedServerNames": names, "TLSMinimumVersion": minimum, "TLSMaximumVersion": maximum, "TLSCertificateIsRequired": true}
	for _, key := range []string{"UserName", "OuterIdentity"} {
		if value, exists := settings[key]; exists && value != "" {
			if !certificateText(value, 255, false) {
				return nil, errors.New("EAP identities must be bounded text")
			}
			eap[key] = value
		}
	}
	if minimum == "1.3" && stringValue(eap, "OuterIdentity") == "" {
		return nil, errors.New("TLS 1.3-only EAP requires an outer identity accepted by your RADIUS server")
	}
	if value, exists := settings["TrustProfileData"]; exists {
		data, ok := value.([]byte)
		if !ok {
			return nil, errors.New("select a public trust certificate profile revision")
		}
		certificates, err := certificateCompositionSource(data, scope, false)
		if err != nil {
			return nil, err
		}
		anchors := make([]any, 0, len(certificates))
		for i, cert := range certificates {
			cert["PayloadUUID"] = uuid.NewString()
			cert["PayloadIdentifier"] = base + ".anchor." + strconv.Itoa(i+1)
			additional = append(additional, cert)
			anchors = append(anchors, cert["PayloadUUID"])
		}
		eap["PayloadCertificateAnchorUUID"] = anchors
	}
	payload["PayloadType"] = "com.apple.wifi.managed"
	payload["SSID_STR"] = ssid
	payload["EncryptionType"] = security
	payload["PayloadCertificateUUID"] = identity["PayloadUUID"]
	payload["EAPClientConfiguration"] = eap
	for _, key := range []string{"AutoJoin", "HIDDEN_NETWORK"} {
		value, ok := settings[key].(bool)
		if !ok {
			return nil, errors.New("select explicit Wi-Fi auto-join and hidden-network options")
		}
		payload[key] = value
	}
	return additional, validateWiFiEAPPayload(payload, scope, nil)
}

func validateWiFiEAPPayload(payload map[string]any, scope string, d *Device) error {
	if stringValue(payload, "PayloadType") != "com.apple.wifi.managed" {
		return nil
	}
	if stringValue(payload, "EncryptionType") == "WPA3" {
		if err := validateCertificateTarget(d, scope, "13.0", "16.0"); err != nil {
			return errors.New("WPA3-only profiles require macOS 13 or iOS/iPadOS 16 or later")
		}
	}
	value, exists := payload["EAPClientConfiguration"]
	if !exists {
		return nil
	}
	if err := validateCertificateTarget(d, scope, "10.7", "4.0"); err != nil {
		return err
	}
	eap, ok := value.(map[string]any)
	if !ok {
		return errors.New("Wi-Fi EAP client configuration must be a dictionary")
	}
	types, ok := eap["AcceptEAPTypes"].([]any)
	if !ok || len(types) == 0 || len(types) > 7 {
		return errors.New("select 1 to 7 supported EAP types")
	}
	hasTLS := false
	seen := map[uint64]bool{}
	for _, value := range types {
		n, ok := certificateInteger(value)
		if !ok || seen[n] {
			return errors.New("EAP types must be unique supported integers")
		}
		seen[n] = true
		switch n {
		case 13:
			hasTLS = true
		case 17, 18, 21, 23, 25, 43:
		default:
			return errors.New("unsupported EAP type")
		}
	}
	minimum, maximum := "1.0", "1.2"
	explicit := false
	for key, target := range map[string]*string{"TLSMinimumVersion": &minimum, "TLSMaximumVersion": &maximum} {
		if value, exists := eap[key]; exists {
			version, ok := value.(string)
			if !ok || version != "1.0" && version != "1.1" && version != "1.2" && version != "1.3" {
				return errors.New("invalid EAP TLS version")
			}
			*target = version
			explicit = true
		}
	}
	if minimum > maximum {
		return errors.New("EAP TLS minimum must not exceed its maximum")
	}
	if explicit {
		mac, phone := "10.13", "11.0"
		if hasTLS && (minimum == "1.3" || maximum == "1.3") {
			mac, phone = "14.0", "17.0"
		}
		if err := validateCertificateTarget(d, scope, mac, phone); err != nil {
			return err
		}
	}
	for _, key := range []string{"TLSCertificateIsRequired", "TLSAllowTrustExceptions"} {
		if value, exists := eap[key]; exists {
			if _, ok := value.(bool); !ok {
				return errors.New("EAP certificate and trust switches must be booleans")
			}
			if key == "TLSCertificateIsRequired" {
				if err := validateCertificateTarget(d, scope, "10.7", "7.0"); err != nil {
					return err
				}
			}
			if d != nil && key == "TLSAllowTrustExceptions" && d.Family() != PlatformMacOS && CompareVersions(d.OSVersion, "8.0") >= 0 {
				return errors.New("omit TLSAllowTrustExceptions on iOS/iPadOS 8 or later")
			}
		}
	}
	if value, exists := eap["TLSTrustedServerNames"]; exists {
		names, ok := value.([]any)
		if !ok || len(names) == 0 || len(names) > 64 {
			return errors.New("enter 1 to 64 trusted RADIUS server certificate names")
		}
		for _, name := range names {
			if !wifiServerName(name) {
				return errors.New("invalid RADIUS server certificate name")
			}
		}
	}
	for _, key := range []string{"UserName", "OuterIdentity"} {
		if value, exists := eap[key]; exists && !certificateText(value, 255, true) {
			return errors.New("EAP identities must be bounded text")
		}
	}
	if minimum == "1.3" && stringValue(eap, "OuterIdentity") == "" {
		return errors.New("TLS 1.3-only EAP requires an outer identity")
	}
	return nil
}

func validateWiFiProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved Wi-Fi profile")
	}
	items, _ := root["PayloadContent"].([]any)
	kinds := map[string]string{}
	for _, item := range items {
		payload, _ := item.(map[string]any)
		kinds[strings.ToLower(stringValue(payload, "PayloadUUID"))] = stringValue(payload, "PayloadType")
	}
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validateWiFiEAPPayload(payload, p.Scope, d); err != nil {
			return err
		}
		if d != nil && stringValue(payload, "PayloadType") == "com.apple.wifi.managed" && kinds[strings.ToLower(stringValue(payload, "PayloadCertificateUUID"))] == "com.apple.ADCertificate.managed" && d.Family() != PlatformMacOS {
			return errors.New("Active Directory certificate identities require a Mac")
		}
	}
	return nil
}
