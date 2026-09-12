package handlers

import "github.com/labstack/echo/v4"

func appleSystemExtensionsSettings(c echo.Context, settings map[string]any) error {
	fields := []string{"team_identifier", "bundle_identifiers", "user_overrides", "driver_extensions", "network_extensions", "security_extensions", "removable_identifiers", "protected_identifiers", "protected_ui_identifiers"}
	f, err := adeEnrollmentForm(c, append([]string{"editor", "name", "identifier", "payload_scope", "approval_mode"}, fields...)...)
	if err != nil {
		return err
	}
	if f.Get("editor") != "macos-system-extensions" || f.Get("payload_scope") != "System" {
		return echo.NewHTTPError(400, "Select the System Extensions editor with System scope")
	}
	mode := f.Get("approval_mode")
	settings["ApprovalMode"] = mode
	if mode == "block" {
		for _, field := range fields {
			if _, exists := f[field]; exists {
				return echo.NewHTTPError(400, "The block policy cannot also submit extension approvals or removal rules")
			}
		}
		return nil
	}
	if mode != "listed" && mode != "team" {
		return echo.NewHTTPError(400, "Select a system extension approval policy")
	}
	if mode == "team" {
		if _, exists := f["bundle_identifiers"]; exists {
			return echo.NewHTTPError(400, "Team approval cannot also select individual extensions")
		}
	}
	settings["TeamIdentifier"] = f.Get("team_identifier")
	if mode == "listed" {
		settings["BundleIdentifiers"] = f.Get("bundle_identifiers")
	}
	switch f.Get("user_overrides") {
	case "true":
		settings["AllowUserOverrides"] = true
	case "false":
		settings["AllowUserOverrides"] = false
	default:
		return echo.NewHTTPError(400, "Select whether users may approve additional extensions")
	}
	types := []any{}
	for _, choice := range []struct{ field, kind string }{{"driver_extensions", "DriverExtension"}, {"network_extensions", "NetworkExtension"}, {"security_extensions", "EndpointSecurityExtension"}} {
		if _, exists := f[choice.field]; !exists {
			continue
		}
		if f.Get(choice.field) != "yes" {
			return echo.NewHTTPError(400, "Invalid system extension type selection")
		}
		types = append(types, choice.kind)
	}
	settings["AllowedTypes"] = types
	for key, field := range map[string]string{"RemovableBundleIdentifiers": "removable_identifiers", "ProtectedBundleIdentifiers": "protected_identifiers", "ProtectedUIBundleIdentifiers": "protected_ui_identifiers"} {
		settings[key] = f.Get(field)
	}
	return nil
}
