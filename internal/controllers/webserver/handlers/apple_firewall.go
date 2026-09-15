package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func appleFirewallSettings(c echo.Context, settings map[string]any) error {
	if err := c.Request().ParseForm(); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid firewall form")
	}
	for _, key := range []string{"EnableFirewall", "BlockAllIncoming", "EnableStealthMode", "AllowSigned", "AllowSignedApp", "AllowedApplications", "BlockedApplications"} {
		values := c.Request().PostForm[key]
		if len(values) > 1 {
			return echo.NewHTTPError(http.StatusBadRequest, "Repeated firewall setting")
		}
		value := ""
		if len(values) == 1 {
			value = values[0]
		}
		switch key {
		case "AllowedApplications", "BlockedApplications":
			settings[key] = value
		case "BlockAllIncoming", "EnableStealthMode":
			if value != "" && value != "true" {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid firewall switch")
			}
			settings[key] = value == "true"
		default:
			if value == "" && key != "EnableFirewall" {
				continue
			}
			if value != "true" && value != "false" {
				return echo.NewHTTPError(http.StatusBadRequest, "Select an explicit firewall setting")
			}
			settings[key] = value == "true"
		}
	}
	return nil
}
