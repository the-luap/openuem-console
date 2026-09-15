package handlers

import "github.com/labstack/echo/v4"

func applePrivacySettings(c echo.Context, settings map[string]any) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "service", "application_identifier", "application_type", "code_requirement", "policy", "static_code", "comment", "receiver_identifier", "receiver_type", "receiver_requirement")
	if err != nil {
		return err
	}
	if f.Get("editor") != "macos-privacy" || f.Get("payload_scope") != "System" {
		return echo.NewHTTPError(400, "Select the System privacy profile editor")
	}
	for key, field := range map[string]string{"Service": "service", "Identifier": "application_identifier", "IdentifierType": "application_type", "CodeRequirement": "code_requirement", "Policy": "policy"} {
		settings[key] = f.Get(field)
	}
	if _, exists := f["static_code"]; exists {
		if f.Get("static_code") != "yes" {
			return echo.NewHTTPError(400, "Invalid static code validation option")
		}
		settings["StaticCode"] = true
	}
	if comment := f.Get("comment"); comment != "" {
		settings["Comment"] = comment
	}
	for key, field := range map[string]string{"AEReceiverIdentifier": "receiver_identifier", "AEReceiverIdentifierType": "receiver_type", "AEReceiverCodeRequirement": "receiver_requirement"} {
		if f.Get("service") == "AppleEvents" {
			settings[key] = f.Get(field)
		} else if _, exists := f[field]; exists {
			return echo.NewHTTPError(400, "Receiver fields apply only to Apple Events automation")
		}
	}
	return nil
}
