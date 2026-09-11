package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

// Naming an account during recovery is not proof of its password, certificate
// or OpenID identity. Every public MFA step requires a fresh first-factor flow.
func (h *Handler) requirePrimaryAuthentication(c echo.Context) (*ent.User, error) {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	sm := h.SessionManager.Manager
	deny := func() (*ent.User, error) {
		return nil, echo.NewHTTPError(http.StatusForbidden, "Verify your primary sign-in method again before completing two-factor authentication.")
	}
	if sm.GetBool(ctx, "forgot") || !sm.GetBool(ctx, "authentication-pending") || sm.GetBool(ctx, "twofa") {
		return deny()
	}
	uid := sm.GetString(ctx, "uid")
	proof, err := loginproof.Read(sm.GetString(ctx, loginproof.SessionKey), uid, time.Now())
	if err != nil {
		return deny()
	}
	user, err := h.Model.Client.User.Get(ctx, uid)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "Sign-in account could not be checked.")
	}
	if !user.Use2fa || (user.Register != nats.REGISTER_COMPLETE && user.Register != nats.REGISTER_APPROVED && user.Register != nats.REGISTER_CERTIFICATE_SENT) {
		return deny()
	}
	settings, err := h.Model.Client.Authentication.Query().Only(ctx)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "Sign-in configuration could not be checked.")
	}
	switch proof.Method {
	case loginproof.Password:
		if !settings.UsePasswd || !user.Passwd || user.Openid || user.Hash == "" || proof.Credential != loginproof.Digest(user.Hash) {
			return deny()
		}
	case loginproof.Certificate:
		if !settings.UseCertificates || user.Passwd || user.Openid {
			return deny()
		}
	case loginproof.OpenID:
		if !settings.UseOIDC || !user.Openid || user.Passwd {
			return deny()
		}
		if err = h.validateOIDCSession(c, uid); err != nil {
			return nil, err
		}
		if proof.Credential != loginproof.Digest(sm.GetString(ctx, oidcSessionKey)) {
			return deny()
		}
	default:
		return deny()
	}
	return user, nil
}
