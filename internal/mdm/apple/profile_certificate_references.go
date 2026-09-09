package apple

import (
	"errors"
	"strings"

	"github.com/google/uuid"
)

// Apple network certificate references resolve payload UUIDs within the same
// configuration profile. Catalog IDs, root UUIDs and identities in a separately
// installed profile cannot satisfy these references. Resolve case-insensitively,
// but reject an ambiguous UUID even when its duplicate has another payload type.
func validateProfileCertificateReferences(root map[string]any) error {
	items, ok := root["PayloadContent"].([]any)
	if !ok || len(items) == 0 || len(items) > 100 {
		return errors.New("profile requires 1 to 100 payloads")
	}
	byUUID := map[string][]map[string]any{}
	for _, item := range items {
		payload, ok := item.(map[string]any)
		if !ok {
			return errors.New("every profile payload must be a dictionary")
		}
		id, err := certificateReferenceUUID(payload["PayloadUUID"])
		if err == nil {
			byUUID[id] = append(byUUID[id], payload)
		}
	}
	resolve := func(value any, identity bool) error {
		id, err := certificateReferenceUUID(value)
		if err != nil {
			return err
		}
		matches := byUUID[id]
		if len(matches) != 1 {
			return errors.New("certificate references must identify one unique certificate payload in the same profile")
		}
		kind := stringValue(matches[0], "PayloadType")
		if identity {
			switch kind {
			case "com.apple.security.acme", "com.apple.security.scep", "com.apple.security.pkcs12", "com.apple.ADCertificate.managed":
				return nil
			}
			return errors.New("client credentials must reference an ACME, SCEP, PKCS12 or Active Directory certificate identity payload")
		}
		switch kind {
		case "com.apple.security.root", "com.apple.security.pem", "com.apple.security.pkcs1":
			return nil
		}
		return errors.New("Wi-Fi trust anchors must reference public certificate payloads")
	}
	for _, item := range items {
		payload := item.(map[string]any)
		kind := stringValue(payload, "PayloadType")
		if kind == "com.apple.vpn.managed" || kind == "com.apple.vpn.managed.applayer" {
			for _, key := range []string{"VPN", "IPSec", "IKEv2", "TransparentProxy", "DNS"} {
				if value, exists := payload[key]; exists {
					configuration, ok := value.(map[string]any)
					if !ok {
						return errors.New("VPN protocol and DNS configurations must be dictionaries")
					}
					if reference, exists := configuration["PayloadCertificateUUID"]; exists {
						if err := resolve(reference, true); err != nil {
							return err
						}
					}
				}
			}
			continue
		}
		if stringValue(payload, "PayloadType") != "com.apple.wifi.managed" {
			continue
		}
		if value, exists := payload["PayloadCertificateUUID"]; exists {
			if err := resolve(value, true); err != nil {
				return err
			}
		}
		if value, exists := payload["EAPClientConfiguration"]; exists {
			eap, ok := value.(map[string]any)
			if !ok {
				return errors.New("Wi-Fi EAP client configuration must be a dictionary")
			}
			if value, exists := eap["PayloadCertificateAnchorUUID"]; exists {
				anchors, ok := value.([]any)
				if !ok || len(anchors) == 0 || len(anchors) > 64 {
					return errors.New("Wi-Fi certificate anchors require 1 to 64 certificate payload references")
				}
				seen := map[string]bool{}
				for _, anchor := range anchors {
					if err := resolve(anchor, false); err != nil {
						return err
					}
					id, _ := certificateReferenceUUID(anchor)
					if seen[id] {
						return errors.New("Wi-Fi certificate anchor references must be unique")
					}
					seen[id] = true
				}
			}
		}
	}
	return nil
}

func certificateReferenceUUID(value any) (string, error) {
	text, ok := value.(string)
	if !ok || len(text) != 36 {
		return "", errors.New("certificate references require a canonical payload UUID")
	}
	id, err := uuid.Parse(text)
	if err != nil || id == uuid.Nil || id.String() != strings.ToLower(text) {
		return "", errors.New("certificate references require a canonical payload UUID")
	}
	return id.String(), nil
}
