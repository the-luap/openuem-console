package apple

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"howett.net/plist"
)

// Only channel, OS and enrollment capability facts are generated. This is not a
// validator for every payload field or a guarantee of device-side acceptance.
//go:generate go run ../../../cmd/openuem-apple-profile-capabilities -output profile_capabilities.json

//go:embed profile_capabilities.json
var profileCapabilityData []byte

type profileCapability struct {
	Keys            []string `json:"keys"`
	Introduced      string   `json:"introduced"`
	Removed         string   `json:"removed"`
	DeviceChannel   bool     `json:"device_channel"`
	UserChannel     bool     `json:"user_channel"`
	Supervised      bool     `json:"supervised"`
	RequiresDEP     bool     `json:"requires_dep"`
	UserApprovedMDM bool     `json:"user_approved_mdm"`
}

var profileCapabilities = func() struct {
	Revision string                         `json:"revision"`
	MacOS    map[string][]profileCapability `json:"macos"`
} {
	var result struct {
		Revision string                         `json:"revision"`
		MacOS    map[string][]profileCapability `json:"macos"`
	}
	if err := json.Unmarshal(profileCapabilityData, &result); err != nil {
		panic("invalid embedded Apple profile capabilities")
	}
	return result
}()

func userPayloadCapability(kind string) error {
	for _, capability := range profileCapabilities.MacOS[kind] {
		if capability.UserChannel {
			return nil
		}
	}
	return fmt.Errorf("payload %s is not supported on the macOS user channel", kind)
}

func validateUserPayload(payload map[string]any, d *Device) error {
	if err := validatePublicCertificatePayload(payload, "User", d); err != nil {
		return err
	}
	if err := validateGatekeeperPayload(payload, "User", d); err != nil {
		return err
	}
	kind := stringValue(payload, "PayloadType")
	if kind == "com.apple.extensiblesso" {
		if err := validatePlatformSSOPayload(payload, "User", d); err != nil {
			return err
		}
	}
	if err := userPayloadCapability(kind); err != nil {
		return err
	}
	variants := profileCapabilities.MacOS[kind]
	selected := variants
	if len(variants) > 1 {
		// Apple uses the same type for several MCX payloads with different
		// channels. Resolve every setting by its schema, not by that type alone.
		selected = nil
		for key := range payload {
			if slices.Contains([]string{"PayloadType", "PayloadIdentifier", "PayloadUUID", "PayloadVersion", "PayloadDisplayName", "PayloadDescription", "PayloadOrganization", "PayloadEnabled"}, key) {
				continue
			}
			found := false
			for _, v := range variants {
				if slices.Contains(v.Keys, key) {
					selected = append(selected, v)
					found = true
				}
			}
			if !found {
				return fmt.Errorf("setting %s has no known user-channel schema for %s", key, kind)
			}
		}
		if len(selected) == 0 {
			return errors.New("user-channel payload requires at least one supported setting")
		}
	}
	for _, v := range selected {
		if !v.UserChannel {
			return fmt.Errorf("payload %s contains a device-channel setting", kind)
		}
		if d == nil {
			continue
		}
		if !versionPattern.MatchString(v.Introduced) || CompareVersions(d.OSVersion, v.Introduced) < 0 || (v.Removed != "" && v.Removed != "n/a" && (!versionPattern.MatchString(v.Removed) || CompareVersions(d.OSVersion, v.Removed) >= 0)) {
			return fmt.Errorf("payload %s is unavailable on this macOS version", kind)
		}
		if v.RequiresDEP {
			return fmt.Errorf("payload %s requires Automated Device Enrollment", kind)
		}
		if v.Supervised && (!d.Supervised || !d.SupervisedReported) {
			return fmt.Errorf("payload %s requires reported supervision", kind)
		}
		if v.UserApprovedMDM {
			management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
			approved, _ := management["UserApprovedEnrollment"].(bool)
			if !approved || !d.SecurityFresh(time.Now()) {
				return fmt.Errorf("payload %s requires fresh user-approved MDM inventory", kind)
			}
		}
	}
	return nil
}

func validateUserProfile(p *Profile, d *Device) error {
	if p.Scope != "User" {
		return errors.New("select a User profile for this user channel")
	}
	if !d.Capabilities().UserChannel {
		return errors.New("user-channel profiles require a supported Mac enrollment and OS inventory")
	}
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved user profile")
	}
	items, ok := root["PayloadContent"].([]any)
	if !ok || len(items) == 0 {
		return errors.New("empty user profile")
	}
	for _, item := range items {
		payload, ok := item.(map[string]any)
		if !ok {
			return errors.New("invalid user payload")
		}
		if err := validateUserPayload(payload, d); err != nil {
			return err
		}
	}
	return nil
}
