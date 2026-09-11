package winget

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/open-uem/nats/enrollment"
	"gopkg.in/yaml.v3"
)

var ErrInstaller = errors.New("the WinGet installer cannot be translated without changing its declared behavior")

type MSITarget struct {
	Architecture string
	MinimumOS    string
	Detection    enrollment.SoftwareDetection
}

// MSIPlan translates only an explicitly selected machine MSI/WiX entry. Target
// requirements come from separately reviewed approval intent. A returned plan
// still needs current authorization, immutable approval and signed dispatch.
func MSIPlan(snapshot Snapshot, index int, target MSITarget, operation string) (enrollment.SoftwarePlan, error) {
	var empty enrollment.SoftwarePlan
	manifest, err := snapshot.Inspect()
	if err != nil {
		return empty, err
	}
	architecture := map[string]string{"amd64": "x64", "arm64": "arm64"}[target.Architecture]
	if index < 0 || index >= len(manifest.Installers) || architecture == "" || !target.Detection.Valid() || target.Detection.Kind != "msi-product" || (operation != "install" && operation != "remove") {
		return empty, ErrInstaller
	}
	root, selected := mapping(manifest.Root), mapping(manifest.Installers[index])
	fields := map[string]*yaml.Node{}
	for name, value := range root {
		if msiMetadata(name) {
			continue
		}
		if !msiField(name) || name == "Architecture" || name == "InstallerUrl" || name == "InstallerSha256" {
			return empty, ErrInstaller
		}
		fields[name] = value
	}
	for name, value := range selected {
		if !msiField(name) {
			return empty, ErrInstaller
		}
		fields[name] = value
	}
	// WinGet merges switch keys rather than replacing the entire map. Empty
	// installer dependency/return-code declarations also cannot erase retained
	// root behavior. Never lose requirements while constructing an effective view.
	for _, defaults := range []map[string]*yaml.Node{root, selected} {
		if node := defaults["Dependencies"]; node != nil && (node.Kind != yaml.MappingNode || len(node.Content) != 0) {
			return empty, ErrInstaller
		}
		for _, name := range []string{"InstallerSuccessCodes", "ExpectedReturnCodes"} {
			if node := defaults[name]; node != nil && (node.Kind != yaml.SequenceNode || len(node.Content) != 0) {
				return empty, ErrInstaller
			}
		}
	}
	var validSwitches bool
	fields["InstallerSwitches"], validSwitches = mergedSwitches(root["InstallerSwitches"], selected["InstallerSwitches"])
	if !validSwitches {
		return empty, ErrInstaller
	}
	if scalar(fields["Architecture"]) != architecture || scalar(fields["Scope"]) != "machine" || !slices.Contains([]string{"msi", "wix"}, scalar(fields["InstallerType"])) {
		return empty, ErrInstaller
	}
	if !optionalEnum(fields["UpgradeBehavior"], "install") || !optionalEnum(fields["ElevationRequirement"], "elevatesSelf", "elevationRequired") {
		return empty, ErrInstaller
	}
	for _, name := range []string{"InstallerAbortsTerminal", "InstallLocationRequired", "RequireExplicitUpgrade", "DownloadCommandProhibited", "DisplayInstallWarnings"} {
		if node := fields[name]; node != nil && (node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || node.Value != "false") {
			return empty, ErrInstaller
		}
	}
	if node := fields["Platform"]; node != nil {
		values, valid := scalarList(node)
		if !valid || len(values) != 1 || values[0] != "Windows.Desktop" {
			return empty, ErrInstaller
		}
	}
	if node := fields["InstallModes"]; node != nil {
		values, valid := scalarList(node)
		if !valid || !slices.Contains(values, "silent") {
			return empty, ErrInstaller
		}
		for _, value := range values {
			if !slices.Contains([]string{"silent", "silentWithProgress", "interactive"}, value) {
				return empty, ErrInstaller
			}
		}
	}
	if node := fields["UnsupportedOSArchitectures"]; node != nil {
		values, valid := scalarList(node)
		if !valid || slices.Contains(values, architecture) {
			return empty, ErrInstaller
		}
		for _, value := range values {
			if !slices.Contains([]string{"x86", "x64", "arm", "arm64"}, value) {
				return empty, ErrInstaller
			}
		}
	}
	if !msiSwitches(fields["InstallerSwitches"]) {
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
		if !optionalEnum(entry["InstallerType"], "msi", "wix") {
			return empty, ErrInstaller
		}
	}
	if product != target.Detection.ProductCode {
		return empty, ErrInstaller
	}
	minimum, valid := minimumOS(target.MinimumOS, fields["MinimumOSVersion"])
	if !valid {
		return empty, ErrInstaller
	}
	artifact := enrollment.SoftwareArtifact{URL: scalar(fields["InstallerUrl"]), SHA256: strings.ToLower(scalar(fields["InstallerSha256"])), Format: "msi"}
	if !artifact.Valid() {
		return empty, ErrInstaller
	}
	plan := enrollment.SoftwarePlan{Kind: "windows-msi", Operation: operation, Identifier: snapshot.Coordinate.Identifier, Version: snapshot.Coordinate.Version, Architecture: target.Architecture, MinimumOS: minimum, Artifact: artifact, Detection: target.Detection, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
	if operation == "remove" {
		plan.Artifact = enrollment.SoftwareArtifact{}
	}
	if !plan.Valid() {
		return empty, ErrInstaller
	}
	return plan, nil
}

func msiMetadata(name string) bool {
	// Agreement acceptance and market restrictions need a separate workflow; do
	// not classify them as ignorable descriptions. Complete source bytes survive.
	return slices.Contains([]string{"PackageIdentifier", "PackageVersion", "ManifestType", "ManifestVersion", "Installers", "PackageLocale", "DefaultLocale", "Publisher", "PublisherUrl", "PublisherSupportUrl", "PrivacyUrl", "Author", "PackageName", "PackageUrl", "License", "LicenseUrl", "Copyright", "CopyrightUrl", "ShortDescription", "Description", "Moniker", "Tags", "ReleaseNotes", "ReleaseNotesUrl", "Documentations", "Icons"}, name)
}

func msiField(name string) bool {
	return slices.Contains([]string{"Architecture", "InstallerType", "Scope", "MinimumOSVersion", "InstallerUrl", "InstallerSha256", "ProductCode", "AppsAndFeaturesEntries", "UpgradeBehavior", "ElevationRequirement", "Platform", "InstallModes", "InstallerSwitches", "UnsupportedOSArchitectures", "InstallerAbortsTerminal", "InstallLocationRequired", "RequireExplicitUpgrade", "DownloadCommandProhibited", "DisplayInstallWarnings", "Dependencies", "InstallerSuccessCodes", "ExpectedReturnCodes", "Commands", "Protocols", "FileExtensions", "ReleaseDate", "InstallationMetadata", "UnsupportedArguments"}, name)
}

func optionalEnum(node *yaml.Node, values ...string) bool {
	return node == nil || slices.Contains(values, scalar(node))
}

func mergedSwitches(root, selected *yaml.Node) (*yaml.Node, bool) {
	if root == nil && selected == nil {
		return nil, true
	}
	fields := map[string]*yaml.Node{}
	for _, node := range []*yaml.Node{root, selected} {
		if node == nil {
			continue
		}
		if node.Kind != yaml.MappingNode {
			return nil, false
		}
		for key, value := range mapping(node) {
			fields[key] = value
		}
	}
	merged := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for key, value := range fields {
		merged.Content = append(merged.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
	}
	return merged, true
}

func scalarList(node *yaml.Node) ([]string, bool) {
	if node.Kind != yaml.SequenceNode {
		return nil, false
	}
	values := make([]string, 0, len(node.Content))
	for _, value := range node.Content {
		text := scalar(value)
		if text == "" || slices.Contains(values, text) {
			return nil, false
		}
		values = append(values, text)
	}
	return values, true
}

func msiSwitches(node *yaml.Node) bool {
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
			for _, arg := range strings.Fields(value.Value) {
				arg = strings.ToLower(arg)
				if !slices.Contains([]string{"/q", "/qn", "/quiet", "/norestart"}, arg) {
					return false
				}
				quiet = quiet || arg != "/norestart"
			}
			if !quiet {
				return false
			}
		case "Custom":
			if text := strings.TrimSpace(value.Value); text != "" && text != "ALLUSERS=1" {
				return false
			}
		case "Upgrade":
			if value.Value != "" {
				return false
			}
		case "SilentWithProgress", "Interactive", "InstallLocation", "Log", "Repair":
			// These are opt-in modes/parameters. This adapter requests only silent
			// installation at the installer's default location, with no repair.
		default:
			return false
		}
	}
	return true
}

func minimumOS(requested string, node *yaml.Node) (string, bool) {
	parse := func(text string) ([4]uint32, bool) {
		var parts [4]uint32
		values := strings.Split(text, ".")
		if len(values) < 3 || len(values) > 4 {
			return parts, false
		}
		for i, value := range values {
			number, err := strconv.ParseUint(value, 10, 32)
			if err != nil || strconv.FormatUint(number, 10) != value {
				return parts, false
			}
			parts[i] = uint32(number)
		}
		return parts, true
	}
	a, valid := parse(requested)
	if !valid {
		return "", false
	}
	if node == nil {
		return requested, true
	}
	text := scalar(node)
	b, valid := parse(text)
	if !valid {
		return "", false
	}
	for i := range a {
		if b[i] > a[i] {
			return text, true
		}
		if b[i] < a[i] {
			return requested, true
		}
	}
	return requested, true
}
