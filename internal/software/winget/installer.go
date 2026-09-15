package winget

import (
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// installerFields applies the bounded shared machine-installer requirements.
// Each adapter still validates its own product identity, switches and artifact.
func installerFields(manifest *Manifest, index int, architecture string, installerTypes ...string) (map[string]*yaml.Node, error) {
	if index < 0 || index >= len(manifest.Installers) {
		return nil, ErrInstaller
	}
	root, selected := mapping(manifest.Root), mapping(manifest.Installers[index])
	fields := map[string]*yaml.Node{}
	for name, value := range root {
		if installerMetadata(name) {
			continue
		}
		if !installerField(name) || name == "Architecture" || name == "InstallerUrl" || name == "InstallerSha256" {
			return nil, ErrInstaller
		}
		fields[name] = value
	}
	for name, value := range selected {
		if !installerField(name) {
			return nil, ErrInstaller
		}
		fields[name] = value
	}
	// WinGet merges switch keys rather than replacing the entire map. Empty
	// installer dependency/return-code declarations also cannot erase retained
	// root behavior. Never lose requirements while constructing an effective view.
	for _, defaults := range []map[string]*yaml.Node{root, selected} {
		if node := defaults["Dependencies"]; node != nil && (node.Kind != yaml.MappingNode || len(node.Content) != 0) {
			return nil, ErrInstaller
		}
		for _, name := range []string{"InstallerSuccessCodes", "ExpectedReturnCodes"} {
			if node := defaults[name]; node != nil && (node.Kind != yaml.SequenceNode || len(node.Content) != 0) {
				return nil, ErrInstaller
			}
		}
	}
	var validSwitches bool
	fields["InstallerSwitches"], validSwitches = mergedSwitches(root["InstallerSwitches"], selected["InstallerSwitches"])
	if !validSwitches {
		return nil, ErrInstaller
	}
	if scalar(fields["Architecture"]) != architecture || scalar(fields["Scope"]) != "machine" || !slices.Contains(installerTypes, scalar(fields["InstallerType"])) {
		return nil, ErrInstaller
	}
	if !optionalEnum(fields["UpgradeBehavior"], "install") || !optionalEnum(fields["ElevationRequirement"], "elevatesSelf", "elevationRequired") {
		return nil, ErrInstaller
	}
	for _, name := range []string{"InstallerAbortsTerminal", "InstallLocationRequired", "RequireExplicitUpgrade", "DownloadCommandProhibited", "DisplayInstallWarnings"} {
		if node := fields[name]; node != nil && (node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || node.Value != "false") {
			return nil, ErrInstaller
		}
	}
	if node := fields["Platform"]; node != nil {
		values, valid := scalarList(node)
		if !valid || len(values) != 1 || values[0] != "Windows.Desktop" {
			return nil, ErrInstaller
		}
	}
	if node := fields["InstallModes"]; node != nil {
		values, valid := scalarList(node)
		if !valid || !slices.Contains(values, "silent") {
			return nil, ErrInstaller
		}
		for _, value := range values {
			if !slices.Contains([]string{"silent", "silentWithProgress", "interactive"}, value) {
				return nil, ErrInstaller
			}
		}
	}
	if node := fields["UnsupportedOSArchitectures"]; node != nil {
		values, valid := scalarList(node)
		if !valid || slices.Contains(values, architecture) {
			return nil, ErrInstaller
		}
		for _, value := range values {
			if !slices.Contains([]string{"x86", "x64", "arm", "arm64"}, value) {
				return nil, ErrInstaller
			}
		}
	}
	return fields, nil
}

// Windows command-line separators are ASCII space and tab. Unicode whitespace
// or line breaks must never turn an unsupported manifest token into quiet flags.
func installerSwitchWords(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == '\t' })
}

func lowerInstallerSwitch(value string) string {
	for i := range len(value) {
		if value[i] >= 0x80 {
			return ""
		}
	}
	return strings.ToLower(value)
}
