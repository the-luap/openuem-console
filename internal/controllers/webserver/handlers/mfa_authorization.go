package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

func mfaMutationError(err error) error {
	if errors.Is(err, models.ErrMFAState) || errors.Is(err, models.ErrLocalSignIn) {
		return echo.NewHTTPError(http.StatusConflict, "Account access or two-factor enrollment changed; sign in again.")
	}
	return echo.NewHTTPError(http.StatusServiceUnavailable, "Two-factor authentication could not be updated. Try again.")
}

func (h *Handler) oidcMFAAuthorization(c echo.Context, user *ent.User, pending bool) (oidcaccounts.MFAAuthorization, error) {
	sm := h.SessionManager.Manager
	ctx := c.Request().Context()
	raw := sm.GetString(ctx, oidcSessionKey)
	var identity oidcaccounts.Session
	if len(raw) > 8192 || json.Unmarshal([]byte(raw), &identity) != nil || sm.GetString(ctx, "uid") != user.ID || sm.GetBool(ctx, "forgot") || sm.GetBool(ctx, "authentication-pending") != pending {
		return oidcaccounts.MFAAuthorization{}, models.ErrMFAState
	}
	authorization := oidcaccounts.AccountMFA(identity)
	if pending {
		if sm.GetBool(ctx, "twofa") {
			return oidcaccounts.MFAAuthorization{}, models.ErrMFAState
		}
		authorization = oidcaccounts.PrimaryMFA(identity, sm.GetString(ctx, loginproof.SessionKey))
	} else if user.Use2fa && !sm.GetBool(ctx, "twofa") {
		return oidcaccounts.MFAAuthorization{}, models.ErrMFAState
	}
	if err := authorization.Validate(user, time.Now()); err != nil {
		return oidcaccounts.MFAAuthorization{}, models.ErrMFAState
	}
	return authorization, nil
}

func (h *Handler) localMFAAuthorization(c echo.Context, user *ent.User) (models.LocalMFAAuthorization, error) {
	raw := h.SessionManager.Manager.GetString(c.Request().Context(), loginproof.SessionKey)
	proof, err := loginproof.Read(raw, user.ID, time.Now())
	if err != nil {
		return models.LocalMFAAuthorization{}, models.ErrLocalSignIn
	}
	result := models.LocalMFAAuthorization{Proof: raw}
	if proof.Method == loginproof.Certificate {
		result.Certificate, err = clientidentity.ReadSessionCertificate(h.SessionManager.Manager.GetString(c.Request().Context(), clientidentity.SessionCertificateKey), user.ID, proof.Credential, time.Now())
		if err != nil {
			return models.LocalMFAAuthorization{}, models.ErrLocalSignIn
		}
	}
	return result, nil
}

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
		if err = h.Model.CheckLocalPrimary(ctx, user, proof.Method, nil, proof.Generation); err != nil {
			if errors.Is(err, models.ErrLocalSignIn) {
				return deny()
			}
			return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "Password sign-in verification is temporarily unavailable.")
		}
	case loginproof.Certificate:
		if !settings.UseCertificates || user.Passwd || user.Openid {
			return deny()
		}
		cert, err := clientidentity.ReadSessionCertificate(sm.GetString(ctx, clientidentity.SessionCertificateKey), uid, proof.Credential, time.Now())
		if err != nil {
			return deny()
		}
		if err = h.Model.CheckLocalPrimary(ctx, user, proof.Method, cert, proof.Generation); err != nil {
			if errors.Is(err, models.ErrLocalSignIn) {
				return deny()
			}
			return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "Certificate sign-in verification is temporarily unavailable.")
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
