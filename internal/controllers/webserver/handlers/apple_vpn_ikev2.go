package handlers

import (
	"errors"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func ikev2ProfileFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Organization profile management permission is required")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(404, "The selected certificate revision was not found in this organization")
	case errors.Is(err, apple.ErrVPNProfile), errors.Is(err, apple.ErrWiFiProfile):
		return echo.NewHTTPError(400, "Review the VPN server, identifiers, authentication mode, matching certificate scopes and algorithm. Select exactly one identity payload and, optionally, a profile containing only public trust certificates.")
	default:
		return echo.NewHTTPError(503, "The IKEv2 profile could not be created. Reload the catalog before retrying.")
	}
}

func (h *Handler) appleCreateIKEv2Certificate(c echo.Context, tenant int) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "connection_name", "remote_address", "local_identifier", "remote_identifier", "authentication_mode", "certificate_type", "server_issuer", "server_name", "identity_revision", "trust_revision")
	if err != nil {
		return err
	}
	if f.Get("editor") != "vpn-ikev2-certificate" {
		return ikev2ProfileFailure(apple.ErrVPNProfile)
	}
	identity, err := apple.ParseCertificateProfileReference(f.Get("identity_revision"))
	if err != nil {
		return ikev2ProfileFailure(err)
	}
	o := apple.IKEv2CertificateOptions{Name: f.Get("name"), Identifier: f.Get("identifier"), Scope: f.Get("payload_scope"), ConnectionName: f.Get("connection_name"), RemoteAddress: f.Get("remote_address"), LocalIdentifier: f.Get("local_identifier"), RemoteIdentifier: f.Get("remote_identifier"), AuthenticationMode: f.Get("authentication_mode"), CertificateType: f.Get("certificate_type"), ServerCertificateIssuerCommonName: f.Get("server_issuer"), ServerCertificateCommonName: f.Get("server_name"), Identity: identity}
	if f.Get("trust_revision") != "existing" {
		trust, err := apple.ParseCertificateProfileReference(f.Get("trust_revision"))
		if err != nil {
			return ikev2ProfileFailure(err)
		}
		o.Trust = &trust
	}
	if _, err = h.Apple.CreateIKEv2CertificateProfile(c.Request().Context(), tenant, o, h.appleActor(c), h.Access); err != nil {
		return ikev2ProfileFailure(err)
	}
	return nil
}
