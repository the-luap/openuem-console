package handlers

import (
	"strconv"

	"github.com/labstack/echo/v4"
)

func appleADCertificateSettings(c echo.Context, settings map[string]any) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "certificate_server", "certificate_template", "description", "certificate_authority", "acquisition", "renewal_notice", "key_size", "key_extractable", "all_apps_access", "auto_renewal")
	if err != nil {
		return err
	}
	if f.Get("editor") != "apple-ad-certificate" || f.Get("payload_scope") != "System" && f.Get("payload_scope") != "User" {
		return echo.NewHTTPError(400, "Select the Active Directory certificate editor and System or User scope")
	}
	settings["CertServer"], settings["CertTemplate"] = f.Get("certificate_server"), f.Get("certificate_template")
	for key, field := range map[string]string{"Description": "description", "CertificateAuthority": "certificate_authority", "CertificateAcquisitionMechanism": "acquisition"} {
		if value := f.Get(field); value != "" {
			settings[key] = value
		}
	}
	for key, field := range map[string]string{"CertificateRenewalTimeInterval": "renewal_notice", "Keysize": "key_size"} {
		value := f.Get(field)
		if value == "" {
			continue
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || strconv.Itoa(n) != value {
			return echo.NewHTTPError(400, "Select a valid certificate notification interval and RSA key size")
		}
		settings[key] = n
	}
	for key, field := range map[string]string{"KeyIsExtractable": "key_extractable", "AllowAllAppsAccess": "all_apps_access", "EnableAutoRenewal": "auto_renewal"} {
		switch f.Get(field) {
		case "":
		case "true":
			settings[key] = true
		case "false":
			settings[key] = false
		default:
			return echo.NewHTTPError(400, "Select an explicit certificate key access and renewal option")
		}
	}
	return nil
}
