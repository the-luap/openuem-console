package handlers

import (
	"errors"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func wifiProfileFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Organization profile management permission is required")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(404, "The selected certificate revision was not found in this organization")
	case errors.Is(err, apple.ErrWiFiProfile):
		return echo.NewHTTPError(400, "Review the Wi-Fi settings, matching certificate scopes, RADIUS names and TLS range. Select a profile with exactly one identity payload and, optionally, a profile containing only public trust certificates.")
	default:
		return echo.NewHTTPError(503, "The enterprise Wi-Fi profile could not be created. Reload the catalog before retrying.")
	}
}

func (h *Handler) appleCreateWiFiEAPTLS(c echo.Context, tenant int) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "ssid", "wifi_security", "tls_minimum", "tls_maximum", "server_names", "user_name", "outer_identity", "auto_join", "hidden_network", "identity_revision", "trust_revision")
	if err != nil {
		return err
	}
	if f.Get("editor") != "wifi-eap-tls" {
		return wifiProfileFailure(apple.ErrWiFiProfile)
	}
	identity, err := apple.ParseCertificateProfileReference(f.Get("identity_revision"))
	if err != nil {
		return wifiProfileFailure(err)
	}
	o := apple.WiFiEAPTLSOptions{Name: f.Get("name"), Identifier: f.Get("identifier"), Scope: f.Get("payload_scope"), SSID: f.Get("ssid"), EncryptionType: f.Get("wifi_security"), TLSMinimum: f.Get("tls_minimum"), TLSMaximum: f.Get("tls_maximum"), ServerNames: f.Get("server_names"), UserName: f.Get("user_name"), OuterIdentity: f.Get("outer_identity"), Identity: identity}
	if f.Get("trust_revision") != "existing" {
		trust, err := apple.ParseCertificateProfileReference(f.Get("trust_revision"))
		if err != nil {
			return wifiProfileFailure(err)
		}
		o.Trust = &trust
	}
	for field, target := range map[string]*bool{"auto_join": &o.AutoJoin, "hidden_network": &o.Hidden} {
		value := f.Get(field)
		if value != "true" && value != "false" {
			return wifiProfileFailure(apple.ErrWiFiProfile)
		}
		*target = value == "true"
	}
	if _, err = h.Apple.CreateWiFiEAPTLSProfile(c.Request().Context(), tenant, o, h.appleActor(c), h.Access); err != nil {
		return wifiProfileFailure(err)
	}
	return nil
}
