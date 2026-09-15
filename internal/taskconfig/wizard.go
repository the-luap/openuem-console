package taskconfig

import "github.com/open-uem/ent/task"

// WizardValue admits only the selectable legacy task families. Each lookup is
// independent; creation still validates the complete platform/configuration.
func WizardValue(stage, value string) bool {
	switch stage {
	case "types":
		return value == "windows" || value == "linux" || value == "macos" || value == "any"
	case "subtypes":
		switch value {
		case "package_type", "registry_type", "local_user_subtype", "local_group_subtype", "unix_local_user_subtype", "unix_local_group_subtype", "msi_type", "powershell_type", "unix_script_type", "flatpak_type", "brew_formula_type", "brew_cask_type", "netbird_type":
			return true
		}
	case "definition":
		if value == task.TypePowershellScript.String() || value == task.TypeUnixScript.String() {
			return false
		}
		for _, platform := range []string{"windows", "linux", "macos", "any"} {
			if (Config{TaskType: value, AgentsType: platform}).Supported() {
				return true
			}
		}
	}
	return false
}
