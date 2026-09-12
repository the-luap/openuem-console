package handlers

import (
	"strconv"

	"github.com/labstack/echo/v4"
)

func appleSCEPSettings(c echo.Context, settings map[string]any) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "scep_url", "ca_name", "subject", "challenge", "key_size", "key_usage", "retries", "retry_delay", "fingerprint", "key_extractable", "all_apps_access", "san_email", "san_dns", "san_uri", "san_principal")
	if err != nil {
		return err
	}
	if f.Get("editor") != "apple-scep" || f.Get("payload_scope") != "System" && f.Get("payload_scope") != "User" {
		return echo.NewHTTPError(400, "Select the SCEP editor and System or User scope")
	}
	settings["URL"] = f.Get("scep_url")
	for key, field := range map[string]string{"Name": "ca_name", "SubjectLines": "subject", "Challenge": "challenge", "Fingerprint": "fingerprint", "rfc822Name": "san_email", "dNSName": "san_dns", "uniformResourceIdentifier": "san_uri", "ntPrincipalName": "san_principal"} {
		if value := f.Get(field); value != "" {
			settings[key] = value
		}
	}
	for key, field := range map[string]string{"Keysize": "key_size", "Key Usage": "key_usage", "Retries": "retries", "RetryDelay": "retry_delay"} {
		value := f.Get(field)
		if value == "" && key != "Keysize" {
			continue
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return echo.NewHTTPError(400, "Select valid SCEP key and retry options")
		}
		settings[key] = n
	}
	for key, field := range map[string]string{"KeyIsExtractable": "key_extractable", "AllowAllAppsAccess": "all_apps_access"} {
		switch f.Get(field) {
		case "":
		case "true":
			settings[key] = true
		case "false":
			settings[key] = false
		default:
			return echo.NewHTTPError(400, "Select an explicit SCEP key access option")
		}
	}
	return nil
}
