package windows

import (
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

const updateVersionURI = "./DevDetail/SwV"
const updateEditionURI = "./Device/Vendor/MSFT/WindowsLicensing/Edition"
const updateProductURI = "./DevDetail/Ext/Microsoft/OSPlatform"
const updateArchitectureURI = "./DevDetail/Ext/Microsoft/ProcessorArchitecture"

type UpdatePlatform struct {
	Version                 string
	Edition                 string
	EditionCode             uint32
	Product                 string
	Architecture            string
	Compatible              bool
	Reason                  string
	Release                 string
	SupportState            string
	SupportEndsOn           string
	CatalogDate             string
	ExtendedSecurityUpdates string
}

func (UpdatePlatform) String() string     { return "[protected Windows update platform evidence]" }
func (v UpdatePlatform) GoString() string { return v.String() }

func updatePlatformCommand() CSPCommandSpec {
	result := CSPCommandSpec{Kind: "Sequence"}
	for _, uri := range []string{updateVersionURI, updateEditionURI, updateProductURI, updateArchitectureURI} {
		result.Commands = append(result.Commands, CSPCommandSpec{Kind: "Get", URI: uri})
	}
	return result
}

func windowsVersion(value string) ([4]uint32, bool) {
	var result [4]uint32
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return result, false
	}
	for n, part := range parts {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(number, 10) != part {
			return result, false
		}
		result[n] = uint32(number)
	}
	return result, true
}

// WindowsLicensing/Edition returns the numeric GetProductInfo SKU. It has an
// unambiguous representation and is available before DeviceStatus/OS/Edition.
func updateEditionName(value string) (uint32, string) {
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(number, 10) != value {
		return 0, ""
	}
	names := map[uint32]string{48: "Professional", 49: "ProfessionalN", 164: "ProfessionalEducation", 165: "ProfessionalEducationN", 161: "ProfessionalWorkstation", 162: "ProfessionalWorkstationN", 4: "Enterprise", 27: "EnterpriseN", 125: "EnterpriseS", 126: "EnterpriseSN", 121: "Education", 122: "EducationN", 188: "IoTEnterprise", 191: "IoTEnterpriseS", 7: "ServerStandard", 8: "ServerDatacenter", 10: "ServerEnterprise", 12: "ServerDatacenterCore", 13: "ServerStandardCore", 14: "ServerEnterpriseCore", 79: "ServerStandardEvaluation", 80: "ServerDatacenterEvaluation"}
	return uint32(number), names[uint32(number)]
}

// Backported feature grace periods have build-specific revision floors. A newer
// unrelated build number cannot satisfy an older release's servicing threshold.
func updateFeatureGraceAvailable(version [4]uint32) bool {
	switch version[2] {
	case 17763:
		return version[3] >= 1852
	case 18363:
		return version[3] >= 1474
	case 19041, 19042:
		return version[3] >= 906
	default:
		return version[2] >= 19043
	}
}

func updateResultText(operation cspOperationResult) (string, bool) {
	if operation.Kind != "Get" || operation.Status != 200 || !operation.HasResult || operation.MoreData || operation.XML != "" || len(operation.Text) > 256 || operation.Format != "" && operation.Format != "chr" && operation.Format != "int" {
		return "", false
	}
	return operation.Text, true
}

func assessUpdatePlatform(policy UpdatePolicy, state *cspSessionCommand) UpdatePlatform {
	result := UpdatePlatform{Reason: "platform_evidence_missing"}
	if state == nil || cspOutcome(state) != "acknowledged" {
		return result
	}
	values := map[string]string{}
	for _, operation := range state.Operations {
		if operation.Kind == "Sequence" {
			continue
		}
		value, valid := updateResultText(operation)
		if !valid {
			return result
		}
		if _, duplicate := values[operation.URI]; duplicate {
			return result
		}
		values[operation.URI] = value
	}
	result.Version = values[updateVersionURI]
	result.EditionCode, result.Edition = updateEditionName(values[updateEditionURI])
	result.Product, result.Architecture = values[updateProductURI], values[updateArchitectureURI]
	if len(values) != 4 || result.Product == "" {
		return result
	}
	version, valid := windowsVersion(result.Version)
	if !valid || version[0] != 10 || version[1] != 0 {
		result.Reason = "unsupported_windows_version"
		return result
	}
	if strings.Contains(strings.ToLower(result.Product), "server") || strings.HasPrefix(result.Edition, "Server") {
		result.Reason = "windows_server_requires_separate_management"
		return result
	}
	if result.Edition == "" {
		result.Reason = "unsupported_or_unknown_edition"
		return result
	}
	if !updatePlatformRelease(&result, version[2], time.Now().UTC()) {
		result.Reason = "unrecognized_windows_release"
		return result
	}
	switch result.Architecture {
	case "0", "x86":
		result.Architecture = "x86"
	case "9", "amd64", "x64":
		result.Architecture = "amd64"
	case "12", "arm64":
		result.Architecture = "arm64"
	default:
		result.Reason = "unsupported_or_unknown_architecture"
		return result
	}
	if version[2] >= 22000 && result.Architecture == "x86" || version[2] < 16299 && result.Architecture == "arm64" {
		result.Reason = "unsupported_windows_architecture"
		return result
	}
	settings, err := policy.settings()
	if err != nil {
		result.Reason = "invalid_update_policy"
		return result
	}
	for _, setting := range settings {
		if version[2] < setting.MinimumBuild || setting.FeatureGrace && !updateFeatureGraceAvailable(version) {
			result.Reason = "setting_unavailable:" + setting.Name
			return result
		}
	}
	result.Compatible, result.Reason = true, ""
	return result
}

// Policy availability is separate from servicing support and ESU entitlement.
// Release/LTSC dates were checked against Microsoft's release-health tables on
// 2026-09-10. Unknown future builds require a catalog update before mutation.
func updatePlatformRelease(result *UpdatePlatform, build uint32, now time.Time) bool {
	result.CatalogDate = "2026-09-10"
	result.ExtendedSecurityUpdates = "not_assessed"
	zone, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		result.SupportState = "support_date_unavailable"
		return false
	}
	date := now.In(zone).Format("2006-01-02")
	releases := map[uint32]string{10240: "Windows 10 1507", 10586: "Windows 10 1511", 14393: "Windows 10 1607", 15063: "Windows 10 1703", 16299: "Windows 10 1709", 17134: "Windows 10 1803", 17763: "Windows 10 1809", 18362: "Windows 10 1903", 18363: "Windows 10 1909", 19041: "Windows 10 2004", 19042: "Windows 10 20H2", 19043: "Windows 10 21H1", 19044: "Windows 10 21H2", 19045: "Windows 10 22H2", 22000: "Windows 11 21H2", 22621: "Windows 11 22H2", 22631: "Windows 11 23H2", 26100: "Windows 11 24H2", 26200: "Windows 11 25H2", 28000: "Windows 11 26H1"}
	result.Release = releases[build]
	if result.Release == "" {
		result.SupportState = "unknown"
		return false
	}
	lt := result.Edition == "EnterpriseS" || result.Edition == "EnterpriseSN" || result.Edition == "IoTEnterpriseS"
	if lt {
		result.SupportEndsOn = map[uint32]string{10240: "2025-10-14", 14393: "2026-10-13", 17763: "2029-01-09", 19044: "2027-01-12", 26100: "2029-10-09"}[build]
		if result.Edition == "IoTEnterpriseS" {
			if build == 19044 {
				result.SupportEndsOn = "2032-01-13"
			}
			if build == 26100 {
				result.SupportEndsOn = "2034-10-10"
			}
		}
		if result.SupportEndsOn == "" {
			result.SupportState = "unknown_ltsc_release"
			return false
		}
	} else if build < 22000 {
		if build == 19045 {
			result.SupportEndsOn = "2025-10-14"
		} else {
			// Older general-channel releases already ended servicing before the
			// product-wide end date. Do not invent their individual end dates.
			result.SupportState = "historical_release_review"
			if date > "2025-10-14" {
				result.SupportState = "standard_support_ended"
			}
			return true
		}
	} else {
		if build == 28000 && result.Edition == "IoTEnterprise" {
			result.SupportState = "unsupported_edition_release"
			return false
		}
		pro := strings.HasPrefix(result.Edition, "Professional")
		dates := map[uint32][2]string{22000: {"2023-10-10", "2024-10-08"}, 22621: {"2024-10-08", "2025-10-14"}, 22631: {"2025-11-11", "2026-11-10"}, 26100: {"2026-10-13", "2027-10-12"}, 26200: {"2027-10-12", "2028-10-10"}, 28000: {"2028-03-14", "2029-03-13"}}
		index := 1
		if pro {
			index = 0
		}
		result.SupportEndsOn = dates[build][index]
	}
	result.SupportState = "within_published_support"
	if date > result.SupportEndsOn {
		result.SupportState = "standard_support_ended"
	}
	return true
}
