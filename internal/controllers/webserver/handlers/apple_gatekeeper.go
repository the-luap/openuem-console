package handlers

import "github.com/labstack/echo/v4"

func appleGatekeeperSettings(c echo.Context, settings map[string]any) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "app_sources", "finder_override", "malware_upload")
	if err != nil {
		return err
	}
	if f.Get("editor") != "macos-gatekeeper" || f.Get("payload_scope") != "System" {
		return echo.NewHTTPError(400, "Select the System Gatekeeper editor")
	}
	switch f.Get("app_sources") {
	case "identified":
		settings["EnableAssessment"], settings["AllowIdentifiedDevelopers"] = true, true
	case "store":
		settings["EnableAssessment"], settings["AllowIdentifiedDevelopers"] = true, false
	case "disabled":
		settings["EnableAssessment"] = false
	default:
		return echo.NewHTTPError(400, "Select the allowed application sources")
	}
	for key, field := range map[string]string{"DisableOverride": "finder_override", "EnableXProtectMalwareUpload": "malware_upload"} {
		switch f.Get(field) {
		case "":
		case "true":
			settings[key] = true
		case "false":
			settings[key] = false
		default:
			return echo.NewHTTPError(400, "Select an explicit Gatekeeper option")
		}
	}
	return nil
}
