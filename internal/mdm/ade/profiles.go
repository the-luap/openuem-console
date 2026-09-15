package ade

import (
	"bytes"
	"context"
	"encoding/json"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// EnrollmentService adds enrollment operations to the inventory-only service.
// Callers must persist authorization and intent before invoking a mutation.
// An error after transmission may leave an unknown remote outcome; DefineProfile
// must never be retried as though profile creation were idempotent.
type EnrollmentService interface {
	Service
	DefineProfile(context.Context, EnrollmentProfile) (string, error)
	Profile(context.Context, string) (EnrollmentProfile, error)
	AssignProfile(context.Context, string, []string) (AssignmentResult, error)
	ClearProfile(context.Context, []string) (AssignmentResult, error)
	DeviceDetails(context.Context, []string) (map[string]DeviceDetail, error)
}

var _ EnrollmentService = (*Client)(nil)

// EnrollmentProfile contains the supported enrollment options. Definition and
// assignment are separate operations: defining a profile never assigns devices.
// URL can contain an admission selector and is intentionally absent from String.
type EnrollmentProfile struct {
	Name                  string   `json:"profile_name"`
	URL                   string   `json:"url"`
	Department            string   `json:"department,omitempty"`
	SupportPhone          string   `json:"support_phone_number,omitempty"`
	SupportEmail          string   `json:"support_email_address,omitempty"`
	OrganizationMagic     string   `json:"org_magic,omitempty"`
	AllowPairing          bool     `json:"allow_pairing"`
	Supervised            bool     `json:"is_supervised"`
	Mandatory             bool     `json:"is_mandatory"`
	Removable             bool     `json:"is_mdm_removable"`
	AwaitDeviceConfigured bool     `json:"await_device_configured"`
	AutoAdvance           bool     `json:"auto_advance_setup"`
	IgnoreBackupProfile   bool     `json:"do_not_use_profile_from_backup"`
	SkipSetupItems        []string `json:"skip_setup_items,omitempty"`
}

func (EnrollmentProfile) String() string     { return "[private Automated Device Enrollment profile]" }
func (p EnrollmentProfile) GoString() string { return p.String() }

// Validate checks protocol bounds. Platform/OS eligibility, scope and the
// enrollment callback's organization binding must be checked by the caller.
func (p EnrollmentProfile) Validate() error {
	for _, field := range []struct {
		value string
		max   int
	}{{p.Name, 125}, {p.Department, 125}, {p.SupportPhone, 50}, {p.SupportEmail, 250}, {p.OrganizationMagic, 256}} {
		if !human(field.value, field.max*4) || utf8.RuneCountInString(field.value) > field.max || strings.TrimSpace(field.value) != field.value {
			return ErrService
		}
	}
	if p.Name == "" || !p.Removable && !p.Supervised || len(p.SkipSetupItems) > 64 {
		return ErrService
	}
	u, err := url.Parse(p.URL)
	if err != nil || len(p.URL) > 2000 || !opaque(p.URL, 2000) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" {
		return ErrService
	}
	if p.SupportEmail != "" {
		a, err := mail.ParseAddress(p.SupportEmail)
		if err != nil || a.Name != "" || a.Address != p.SupportEmail {
			return ErrService
		}
	}
	seen := make(map[string]bool)
	for _, item := range p.SkipSetupItems {
		if !validSkipSetupItem(item) || seen[item] {
			return ErrService
		}
		seen[item] = true
	}
	return nil
}

// Names come from Apple's SkipKeys schema. Inclusion here does not imply that a
// pane exists or is skippable on every platform/version.
// https://developer.apple.com/documentation/devicemanagement/skipkeys
func validSkipSetupItem(item string) bool {
	const items = " Accessibility AccessibilityAppearance ActionButton Android Appearance AppleID AppStore Biometric CameraButton DeviceFeaturesTour DeviceToDeviceMigration Diagnostics DisplayTone EnableLockdownMode FileVault HomeButtonSensitivity iCloudDiagnostics iCloudStorage iMessageAndFaceTime Intelligence Keyboard LiquidGlass Location MessagingActivationUsingPhoneNumber Multitasking OnBoarding OSShowcase Passcode Payment Privacy Restore RestoreCompleted Safety SafetyAndHandling ScreenSaver ScreenTime SIMSetup Siri SoftwareUpdate SpokenLanguage TapToSetup TermsOfAddress Tips TOS TVHomeScreenSync TVProviderSignIn TVRoom UnlockWithWatch UpdateCompleted Wallpaper WatchMigration WebContentFiltering Welcome Zoom "
	return opaque(item, 64) && !strings.ContainsAny(item, " \t\r\n") && strings.Contains(items, " "+item+" ")
}

func validProfileID(id string) bool {
	if !opaque(id, 128) {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}

func serialSet(serials []string) (map[string]bool, error) {
	if len(serials) == 0 || len(serials) > PageLimit {
		return nil, ErrService
	}
	seen := make(map[string]bool, len(serials))
	for _, serial := range serials {
		if !ValidSerial(serial) || seen[serial] {
			return nil, ErrService
		}
		seen[serial] = true
	}
	return seen, nil
}

func (c *Client) DefineProfile(ctx context.Context, profile EnrollmentProfile) (string, error) {
	if err := profile.Validate(); err != nil {
		return "", err
	}
	body, err := json.Marshal(profile)
	if err != nil {
		return "", ErrService
	}
	defer clear(body)
	var response struct {
		ID      string            `json:"profile_uuid"`
		Devices map[string]string `json:"devices"`
	}
	if err := c.request(ctx, "POST", "/profile", body, &response); err != nil {
		return "", err
	}
	if !validProfileID(response.ID) || len(response.Devices) != 0 {
		return "", ErrService
	}
	return response.ID, nil
}

// Profile reads supported profiles without silently discarding unsupported
// behavior such as a different enrollment web flow or trust-anchor override.
func (c *Client) Profile(ctx context.Context, id string) (EnrollmentProfile, error) {
	if !validProfileID(id) {
		return EnrollmentProfile{}, ErrService
	}
	var fields map[string]json.RawMessage
	if err := c.request(ctx, "GET", "/profile?profile_uuid="+url.QueryEscape(id), nil, &fields); err != nil {
		return EnrollmentProfile{}, err
	}
	profile := EnrollmentProfile{AllowPairing: true, Removable: true}
	known, _ := json.Marshal(profile)
	var supported map[string]json.RawMessage
	_ = json.Unmarshal(known, &supported)
	// Include fields omitted by the JSON encoder when empty.
	for _, key := range []string{"department", "support_phone_number", "support_email_address", "org_magic", "skip_setup_items"} {
		supported[key] = nil
	}
	for key, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return EnrollmentProfile{}, ErrService
		}
		if _, ok := supported[key]; ok {
			continue
		}
		switch key {
		case "profile_uuid":
			var returned string
			if json.Unmarshal(value, &returned) != nil || returned != id {
				return EnrollmentProfile{}, ErrService
			}
		case "devices":
			var serials []string
			if json.Unmarshal(value, &serials) != nil {
				return EnrollmentProfile{}, ErrService
			}
			// The 1000-device request limit is not a limit on the number of
			// devices assigned to a profile. Response bytes/nodes are bounded
			// independently by the shared JSON decoder.
			seen := make(map[string]bool, len(serials))
			for _, serial := range serials {
				if !ValidSerial(serial) || seen[serial] {
					return EnrollmentProfile{}, ErrService
				}
				seen[serial] = true
			}
		case "is_multi_user", "is_return_to_service":
			var enabled *bool
			if json.Unmarshal(value, &enabled) != nil || enabled == nil || *enabled {
				return EnrollmentProfile{}, ErrService
			}
		case "anchor_certs", "supervising_host_certs":
			var certificates []string
			if json.Unmarshal(value, &certificates) != nil || len(certificates) != 0 {
				return EnrollmentProfile{}, ErrService
			}
		case "configuration_web_url", "language", "region":
			var text string
			if json.Unmarshal(value, &text) != nil || text != "" {
				return EnrollmentProfile{}, ErrService
			}
		default:
			return EnrollmentProfile{}, ErrService
		}
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return EnrollmentProfile{}, ErrService
	}
	defer clear(body)
	if decodeJSON(body, &profile) != nil || profile.Validate() != nil {
		return EnrollmentProfile{}, ErrService
	}
	return profile, nil
}

// AssignmentResult reports Apple's per-device response, not observed activation
// or successful enrollment. Only the literal SUCCESS denotes accepted work.
// RetryAfter applies to THROTTLED entries; callers persist it across restarts.
type AssignmentResult struct {
	Devices    map[string]string
	RetryAfter time.Duration
}

func (c *Client) AssignProfile(ctx context.Context, profileID string, serials []string) (AssignmentResult, error) {
	if !validProfileID(profileID) {
		return AssignmentResult{}, ErrService
	}
	return c.changeProfile(ctx, "POST", profileID, serials)
}

// ClearProfile affects future activation. It neither removes an installed MDM
// profile nor erases a device and must not be presented as either operation.
func (c *Client) ClearProfile(ctx context.Context, serials []string) (AssignmentResult, error) {
	return c.changeProfile(ctx, "DELETE", "", serials)
}

func (c *Client) changeProfile(ctx context.Context, method, profileID string, serials []string) (AssignmentResult, error) {
	requested, err := serialSet(serials)
	if err != nil {
		return AssignmentResult{}, err
	}
	body, err := json.Marshal(struct {
		ProfileID string   `json:"profile_uuid,omitempty"`
		Devices   []string `json:"devices"`
	}{profileID, serials})
	if err != nil {
		return AssignmentResult{}, ErrService
	}
	var response struct {
		ProfileID    string            `json:"profile_uuid"`
		Devices      map[string]string `json:"devices"`
		RetrySeconds *uint64           `json:"retry_after_seconds"`
	}
	if err := c.request(ctx, method, "/profile/devices", body, &response); err != nil {
		return AssignmentResult{}, err
	}
	if response.ProfileID != profileID || len(response.Devices) != len(requested) {
		return AssignmentResult{}, ErrService
	}
	throttled := false
	for serial, status := range response.Devices {
		if !requested[serial] || !validDeviceStatus(status) {
			return AssignmentResult{}, ErrService
		}
		throttled = throttled || status == "THROTTLED"
	}
	result := AssignmentResult{Devices: response.Devices}
	if throttled {
		if response.RetrySeconds == nil || *response.RetrySeconds == 0 {
			return AssignmentResult{}, ErrService
		}
		result.RetryAfter = time.Duration(min(*response.RetrySeconds, uint64((1<<63-1)/int64(time.Second)))) * time.Second
	}
	return result, nil
}

func validDeviceStatus(status string) bool {
	if !opaque(status, 64) {
		return false
	}
	for _, c := range status {
		if !(c >= 'A' && c <= 'Z' || c == '_') {
			return false
		}
	}
	return true
}

type DeviceDetail struct {
	Device
	ResponseStatus string `json:"response_status"`
}

// DeviceDetails refreshes current assignment. Missing serials, inaccessible
// devices and unknown response statuses are never affirmative ownership proof.
// The caller must require an explicit SUCCESS and the intended profile UUID.
func (c *Client) DeviceDetails(ctx context.Context, serials []string) (map[string]DeviceDetail, error) {
	requested, err := serialSet(serials)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(struct {
		Devices []string `json:"devices"`
	}{serials})
	var response struct {
		Devices map[string]*DeviceDetail `json:"devices"`
	}
	if err := c.request(ctx, "POST", "/devices", body, &response); err != nil {
		return nil, err
	}
	if response.Devices == nil || len(response.Devices) > len(requested) {
		return nil, ErrService
	}
	result := make(map[string]DeviceDetail, len(response.Devices))
	for serial, device := range response.Devices {
		if !requested[serial] || device == nil || !validDeviceStatus(device.ResponseStatus) || device.Serial != "" && device.Serial != serial || !human(device.Model, 255) || !human(device.OS, 64) || !human(device.Family, 64) || !human(device.ProfileStatus, 64) || device.ProfileID != "" && !validProfileID(device.ProfileID) || device.Operation != "" {
			return nil, ErrService
		}
		device.Serial = serial
		result[serial] = *device
	}
	return result, nil
}
