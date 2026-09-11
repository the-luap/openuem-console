package handlers

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (h *Handler) Auth(c echo.Context) error {
	cert, err := h.ClientIdentity.Certificate(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
	}

	caCert := h.CACert

	uid := cert.Subject.CommonName
	if uid == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Wrong certificate")
	}

	if len(cert.OCSPServer) == 0 {
		return echo.NewHTTPError(http.StatusUnauthorized, "No OCSP responders found in certificate")
	}
	issuer, err := getIssuerFromCert(cert, caCert)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Certificate did not pass verification")
	}
	if err := checkRevocation(c.Request().Context(), cert, issuer); err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Certificate revocation status could not be verified")
	}

	// Check if uid exists in database
	user, err := h.Model.GetUserById(uid)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not check if user exists")
	}
	if user == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Access is denied")
	}

	msg := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if msg != uid {
		err := h.SessionManager.Manager.RenewToken(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		h.SessionManager.Manager.Put(c.Request().Context(), "uid", uid)
		h.SessionManager.Manager.Put(c.Request().Context(), "username", user.Name)
		h.SessionManager.Manager.Put(c.Request().Context(), "usepasswd", user.Passwd)
		h.SessionManager.Manager.Put(c.Request().Context(), "email", user.Email)
		h.SessionManager.Manager.Put(c.Request().Context(), "user-agent", c.Request().UserAgent())
		h.SessionManager.Manager.Put(c.Request().Context(), "ip-address", c.Request().RemoteAddr)
		token, expiry, err := h.SessionManager.Manager.Commit(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		h.SessionManager.Manager.WriteSessionCookie(c.Request().Context(), c.Response().Writer, token, expiry)

		if err := h.Model.AddUserToSession(c.Request().Context(), token, uid, h.EncryptionMasterKey); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// if it's the first time let's confirm login and remove the cert password
		if err := h.Model.ConfirmLogIn(uid); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	if user.Use2fa {
		return c.Redirect(http.StatusFound, h.consoleOrigin())
	}

	if h.AuthLogger != nil {
		h.AuthLogger.Printf("user %s has logged in with a digital certificate", user.ID)
	}

	myTenant, err := h.Model.GetDefaultTenant()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	mySite, err := h.Model.GetDefaultSite(myTenant)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.Redirect(http.StatusFound, fmt.Sprintf("%s/tenant/%d/site/%d/dashboard", h.consoleOrigin(), myTenant.ID, mySite.ID))
}

func getIssuerFromCert(cert, caCert *x509.Certificate) (*x509.Certificate, error) {

	if cert == nil || caCert == nil {
		return nil, fmt.Errorf("certificate and issuer are required")
	}
	// Check if current certificate is valid for client auth and is issued by our CA
	trustedCAPool := x509.NewCertPool()
	trustedCAPool.AddCert(caCert)
	vOpts := x509.VerifyOptions{
		Roots:     trustedCAPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err := cert.Verify(vOpts)
	if err != nil {
		return nil, err
	}
	if len(chains) == 0 || len(chains[0]) < 2 || cert.IsCA {
		return nil, fmt.Errorf("an issued client certificate is required")
	}
	return chains[0][1], nil
}

// consoleOrigin uses trusted configuration, never request headers or a Referer.
func (h *Handler) consoleOrigin() string {
	if h.PublicOrigin != "" {
		return h.PublicOrigin
	}
	return fmt.Sprintf("https://%s:%s", h.ServerName, h.ConsolePort)
}
