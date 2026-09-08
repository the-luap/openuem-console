package apple

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

type Platform string

const (
	PlatformUnknown Platform = "unknown"
	PlatformIOS     Platform = "ios"
	PlatformIPadOS  Platform = "ipados"
	PlatformMacOS   Platform = "macos"
)

var (
	ipadModel = regexp.MustCompile(`^iPad([0-9]+,[0-9]+)?$`)
	iosModel  = regexp.MustCompile(`^(iPhone|iPod)([0-9]+,[0-9]+)?$`)
	macModel  = regexp.MustCompile(`^(Mac|MacBookPro|MacBookAir|MacBook|Macmini|MacPro|MacStudio|iMac|iMacPro|Xserve)([0-9]+,[0-9]+)?$`)
)

func DetectPlatform(model string) Platform {
	if ipadModel.MatchString(model) {
		return PlatformIPadOS
	}
	if iosModel.MatchString(model) {
		return PlatformIOS
	}
	if macModel.MatchString(model) {
		return PlatformMacOS
	}
	switch model {
	case "MacBook Pro", "MacBook Air", "Mac mini", "Mac Pro", "Mac Studio", "iMac Pro":
		return PlatformMacOS
	}
	return PlatformUnknown
}

// Family uses persisted platform evidence for database devices. Constructed
// values (for catalog queries, for example) derive it from the same model rules.
func (d Device) Family() Platform {
	if d.OSFamily != "" {
		return d.OSFamily
	}
	return DetectPlatform(d.Model)
}

func (d Device) Platform() string {
	switch d.Family() {
	case PlatformIOS:
		return "iOS"
	case PlatformIPadOS:
		return "iPadOS"
	case PlatformMacOS:
		return "macOS"
	default:
		return "Apple · Platform not yet identified"
	}
}

type DeviceCapabilities struct {
	DeviceChannel         bool   `json:"device_channel"`
	UserChannel           bool   `json:"user_channel"`
	Profiles              bool   `json:"profiles"`
	DeclarativeManagement bool   `json:"declarative_management"`
	SpecificOSUpdate      bool   `json:"specific_os_update"`
	UpdateReason          string `json:"update_reason,omitempty"`
}

// Version and enrollment requirements follow Apple's device-management schemas.
// This describes server-supported actions; enrollment and inventory are not proof
// that the device has completed a requested action.
func (d Device) Capabilities() DeviceCapabilities {
	c := DeviceCapabilities{}
	known := d.Family() == PlatformIOS || d.Family() == PlatformIPadOS || d.Family() == PlatformMacOS
	validVersion := versionPattern.MatchString(d.OSVersion)
	c.DeviceChannel = known
	c.UserChannel = d.PerUserConnections && d.Family() == PlatformMacOS && validVersion && CompareVersions(d.OSVersion, "10.7") >= 0
	c.Profiles = validVersion && ((d.Family() == PlatformMacOS && CompareVersions(d.OSVersion, "10.7") >= 0) || ((d.Family() == PlatformIOS || d.Family() == PlatformIPadOS) && CompareVersions(d.OSVersion, "4.0") >= 0))
	if d.Family() == PlatformMacOS {
		c.DeclarativeManagement = validVersion && CompareVersions(d.OSVersion, "13.0") >= 0
		c.SpecificOSUpdate = validVersion && CompareVersions(d.OSVersion, "14.0") >= 0 && d.Supervised && d.SupervisedReported
		switch {
		case !validVersion:
			c.UpdateReason = "Refresh inventory to identify the macOS version."
		case CompareVersions(d.OSVersion, "14.0") < 0:
			c.UpdateReason = "Declarative update enforcement requires macOS 14 or later."
		case !d.Supervised || !d.SupervisedReported:
			c.UpdateReason = "Declarative macOS updates require reported supervision."
		default:
			c.UpdateReason = d.macUpdateReason(time.Now())
		}
	} else if d.Family() == PlatformIOS || d.Family() == PlatformIPadOS {
		c.DeclarativeManagement = validVersion && CompareVersions(d.OSVersion, "15.0") >= 0
		c.SpecificOSUpdate = validVersion && CompareVersions(d.OSVersion, "17.0") >= 0
		if !c.SpecificOSUpdate {
			c.UpdateReason = "Update enforcement requires iOS/iPadOS 17 or later."
		}
	} else {
		c.UpdateReason = "Refresh inventory to identify the Apple platform before configuring updates."
	}
	return c
}

func reportedModel(info map[string]any, current string) (string, error) {
	for _, key := range []string{"ProductName", "Model", "ModelName"} {
		value := stringValue(info, key)
		if len(value) > 255 || strings.ContainsAny(value, "\x00\r\n") {
			return "", errors.New("invalid device model")
		}
		if next := DetectPlatform(value); next != PlatformUnknown {
			if old := DetectPlatform(current); old != PlatformUnknown && old != next {
				return "", errors.New("reported platform conflicts with this enrollment")
			}
			return value, nil
		}
	}
	// ModelName is absent from some phone check-ins, and an opaque Model can
	// accompany a recognized ProductName. Preserve known evidence on partial reads.
	if current != "" {
		return current, nil
	}
	for _, key := range []string{"ProductName", "Model", "ModelName"} {
		if value := stringValue(info, key); value != "" {
			return value, nil
		}
	}
	return "", nil
}

func deviceChannelMessage(message map[string]any) bool {
	for _, key := range []string{"UserID", "EnrollmentID", "EnrollmentUserID", "UserShortName", "UserLongName", "NotOnConsole", "AuthToken"} {
		if _, exists := message[key]; exists {
			return false
		}
	}
	return true
}

func (d Device) macUpdateReason(now time.Time) string {
	if !d.SecurityFresh(now) {
		return "Refresh Mac security inventory before enforcing an update."
	}
	management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
	if approved, _ := management["UserApprovedEnrollment"].(bool); !approved {
		return "The Mac has not reported user-approved device enrollment."
	}
	if user, _ := management["IsUserEnrollment"].(bool); user {
		return "Software update enforcement is unavailable for User Enrollment."
	}
	if d.AppleSilicon == nil {
		return "Refresh inventory to identify Apple silicon or Intel hardware."
	}
	if *d.AppleSilicon {
		if stringValue(d.SecurityInventory, "BootstrapTokenAllowedForAuthentication") != "allowed" {
			return "This Mac does not allow bootstrap-token authentication for updates."
		}
		if required, _ := d.SecurityInventory["BootstrapTokenRequiredForSoftwareUpdate"].(bool); !required {
			return "This Mac has not reported bootstrap-token update authorization."
		}
		if !d.BootstrapTokenEscrowed {
			return "Wait for this Mac to escrow its bootstrap token before enforcing updates."
		}
	}
	return ""
}

func inventoryQueriesFor(d Device) []string {
	queries := []string{"UDID", "DeviceName", "OSVersion", "BuildVersion", "ModelName", "Model", "ProductName", "SerialNumber"}
	if d.Family() == PlatformMacOS {
		if CompareVersions(d.OSVersion, "10.15") >= 0 {
			queries = append(queries, "IsSupervised")
		}
		if CompareVersions(d.OSVersion, "11.3") >= 0 {
			queries = append(queries, "ProvisioningUDID")
		}
		if CompareVersions(d.OSVersion, "12.0") >= 0 {
			queries = append(queries, "IsAppleSilicon", "SoftwareUpdateDeviceID")
		}
		if CompareVersions(d.OSVersion, "13.3") >= 0 {
			queries = append(queries, "BatteryLevel", "HasBattery")
		}
	} else if d.Family() == PlatformIOS || d.Family() == PlatformIPadOS {
		queries = append(queries, "IsSupervised", "DeviceCapacity", "AvailableDeviceCapacity", "BatteryLevel", "IsDeviceLocatorServiceEnabled", "IsActivationLockEnabled")
		if CompareVersions(d.OSVersion, "15.0") >= 0 {
			queries = append(queries, "SoftwareUpdateDeviceID")
		}
	}
	return queries
}

func (d Device) SecurityFresh(now time.Time) bool {
	return d.SecurityAt != nil && !d.SecurityAt.After(now) && now.Sub(*d.SecurityAt) <= 24*time.Hour
}

func inventoryKindsFor(d Device) []string {
	if !d.Capabilities().Profiles {
		return nil
	}
	kinds := []string{}
	if d.Family() == PlatformMacOS || CompareVersions(d.OSVersion, "5.0") >= 0 {
		kinds = append(kinds, "InstalledApplicationList")
	}
	kinds = append(kinds, "ProfileList")
	if d.Family() == PlatformMacOS {
		kinds = append(kinds, "SecurityInfo")
		if d.Capabilities().DeclarativeManagement {
			kinds = append(kinds, "DeclarativeManagement")
		}
		// Mac update selection uses GDMF with the reported update identifier.
		// AvailableOSUpdates needs a separate scan and omits DDM-managed updates.
	} else if d.SupervisedReported && d.Supervised && CompareVersions(d.OSVersion, "9.0") >= 0 && CompareVersions(d.OSVersion, "26.0") < 0 {
		kinds = append(kinds, "AvailableOSUpdates")
	}
	return kinds
}
