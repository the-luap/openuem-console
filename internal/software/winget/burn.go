package winget

import (
	"regexp"
	"slices"
	"strings"

	"github.com/open-uem/nats/enrollment"
	"gopkg.in/yaml.v3"
)

// BurnTarget records separately reviewed machine registration requirements.
// A Burn bundle is detected through its ARP entry, never as an MSI product.
type BurnTarget struct {
	Architecture string
	MinimumOS    string
	Detection    enrollment.SoftwareDetection
}

var burnBundleID = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)

// BurnPlan binds both operations to the same source-declared Burn executable. It never
// reads or invokes a machine's UninstallString, nor grants execution authority.
// Binary bundle-identity verification and console approval/provenance integration
// are required before enabling source-derived Burn dispatch.
func BurnPlan(snapshot Snapshot, index int, target BurnTarget, operation string) (enrollment.SoftwarePlan, error) {
	var empty enrollment.SoftwarePlan
	architecture := map[string]string{"amd64": "x64", "arm64": "arm64"}[target.Architecture]
	if architecture == "" || !target.Detection.Valid() || target.Detection.Kind != "uninstall-key" || target.Detection.RegistryView != "64" || !burnBundleID.MatchString(target.Detection.UninstallKey) || (operation != "install" && operation != "remove") {
		return empty, ErrInstaller
	}
	manifest, err := snapshot.Inspect()
	if err != nil {
		return empty, err
	}
	fields, err := installerFields(manifest, index, architecture, "burn")
	if err != nil {
		return empty, err
	}
	if !burnSwitches(fields["InstallerSwitches"]) {
		return empty, ErrInstaller
	}
	product := scalar(fields["ProductCode"])
	if node := fields["AppsAndFeaturesEntries"]; node != nil {
		if node.Kind != yaml.SequenceNode || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
			return empty, ErrInstaller
		}
		entry := mapping(node.Content[0])
		for key, value := range entry {
			if !slices.Contains([]string{"DisplayName", "DisplayVersion", "Publisher", "ProductCode", "UpgradeCode", "InstallerType"}, key) || scalar(value) == "" {
				return empty, ErrInstaller
			}
		}
		if value := scalar(entry["ProductCode"]); value != "" {
			if product != "" && product != value {
				return empty, ErrInstaller
			}
			product = value
		}
		if value := scalar(entry["DisplayVersion"]); value != "" && value != target.Detection.Version {
			return empty, ErrInstaller
		}
		if !optionalEnum(entry["InstallerType"], "burn") {
			return empty, ErrInstaller
		}
	}
	if product != target.Detection.UninstallKey {
		return empty, ErrInstaller
	}
	minimum, valid := minimumOS(target.MinimumOS, fields["MinimumOSVersion"])
	if !valid {
		return empty, ErrInstaller
	}
	artifact := enrollment.SoftwareArtifact{URL: scalar(fields["InstallerUrl"]), SHA256: strings.ToLower(scalar(fields["InstallerSha256"])), Format: "exe"}
	if !artifact.Valid() {
		return empty, ErrInstaller
	}
	// These are Burn's known silent defaults. Removal selects this bundle's
	// uninstall action while retaining its exact artifact and registration rule.
	args := []string{"/quiet", "/norestart"}
	if operation == "remove" {
		args = append([]string{"/uninstall"}, args...)
	}
	plan := enrollment.SoftwarePlan{Kind: "windows-burn", Operation: operation, Identifier: snapshot.Coordinate.Identifier, Version: snapshot.Coordinate.Version, Architecture: target.Architecture, MinimumOS: minimum, Artifact: artifact, Arguments: args, Detection: target.Detection, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
	if !plan.Valid() {
		return empty, ErrInstaller
	}
	return plan, nil
}

func burnSwitches(node *yaml.Node) bool {
	if node == nil {
		return true
	}
	if node.Kind != yaml.MappingNode {
		return false
	}
	for name, value := range mapping(node) {
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return false
		}
		switch name {
		case "Silent":
			quiet := false
			for _, arg := range installerSwitchWords(value.Value) {
				arg = lowerInstallerSwitch(arg)
				if !slices.Contains([]string{"/q", "/quiet", "/norestart"}, arg) {
					return false
				}
				quiet = quiet || arg != "/norestart"
			}
			if !quiet {
				return false
			}
		case "Custom":
			for _, arg := range installerSwitchWords(value.Value) {
				if lowerInstallerSwitch(arg) != "/norestart" {
					return false
				}
			}
		case "Upgrade":
			if value.Value != "" {
				return false
			}
		case "Interactive", "SilentWithProgress", "Log", "InstallLocation", "Repair":
			// These opt-in modes and parameters are never invoked by this adapter.
		default:
			return false
		}
	}
	return true
}
