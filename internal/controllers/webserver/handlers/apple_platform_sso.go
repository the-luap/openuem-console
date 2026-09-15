package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"strings"
)

func applePlatformSSOSettings(c echo.Context, settings map[string]any) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "extension_identifier", "team_identifier", "sso_urls", "authentication_method", "registration_token", "account_display_name", "shared_device_keys", "create_user_at_login", "unattended_setup", "provider_data")
	if err != nil {
		return err
	}
	if f.Get("editor") != "macos-platform-sso" || f.Get("payload_scope") != "System" {
		return echo.NewHTTPError(400, "Select the System Platform SSO editor")
	}
	for key, field := range map[string]string{"ExtensionIdentifier": "extension_identifier", "TeamIdentifier": "team_identifier", "AuthenticationMethod": "authentication_method"} {
		settings[key] = f.Get(field)
	}
	for key, field := range map[string]string{"RegistrationToken": "registration_token", "AccountDisplayName": "account_display_name"} {
		if value := f.Get(field); value != "" {
			settings[key] = value
		}
	}
	for key, field := range map[string]string{"UseSharedDeviceKeys": "shared_device_keys", "EnableCreateUserAtLogin": "create_user_at_login", "UnattendedSetup": "unattended_setup"} {
		value, err := softwareCheckbox(f, field)
		if err != nil {
			return err
		}
		settings[key] = value
	}
	if len(f.Get("sso_urls")) > 16384 {
		return echo.NewHTTPError(400, "SSO URL prefixes must contain at most 16 KiB")
	}
	urls := []any{}
	for _, line := range strings.Split(f.Get("sso_urls"), "\n") {
		if value := strings.TrimSpace(line); value != "" {
			urls = append(urls, value)
		}
	}
	settings["URLs"] = urls
	provider, err := apple.ParsePlatformSSOProviderData(f.Get("provider_data"))
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if provider != nil {
		settings["ExtensionData"] = provider
	}
	return nil
}
