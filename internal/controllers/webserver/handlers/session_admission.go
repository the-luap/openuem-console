package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

func sessionAdmissionError(err error, message string) error {
	if errors.Is(err, mfaadmission.ErrRejected) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Two-factor sign-in expired or was already used. Sign in again with a new code.")
	}
	if errors.Is(err, models.ErrLocalSignIn) || errors.Is(err, clientidentity.ErrCertificateBinding) || errors.Is(err, oidcaccounts.ErrIdentity) || errors.Is(err, oidcaccounts.ErrConflict) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Account access or sign-in requirements changed; sign in again.")
	}
	var response *echo.HTTPError
	if errors.As(err, &response) {
		return response
	}
	return echo.NewHTTPError(http.StatusInternalServerError, message)
}

func (h *Handler) establishUserSession(c echo.Context, user *ent.User, secondFactor bool, extra map[string]any, confirm func(context.Context) error) error {
	values := map[string]any{
		"uid": user.ID, "username": user.Name, "email": user.Email,
		"usepasswd": user.Passwd, "twofa": secondFactor,
		"user-agent": c.Request().UserAgent(), "ip-address": c.Request().RemoteAddr,
	}
	for key, value := range extra {
		values[key] = value
	}
	return h.SessionManager.Establish(c.Request().Context(), c.Response().Writer, values, func(ctx context.Context, token string) error {
		if err := h.Model.AddUserToSession(ctx, token, user.ID, h.EncryptionMasterKey); err != nil {
			return err
		}
		if confirm != nil {
			return confirm(ctx)
		}
		return nil
	})
}

// MFA completion may retain only an OpenID identity which still belongs to this
// account and passes current binding/policy validation. Other old state is cleared.
func (h *Handler) completeUserSession(c echo.Context, user *ent.User, secondFactor bool, evidence *mfaadmission.Evidence) error {
	if secondFactor != (evidence != nil) || user.Use2fa != secondFactor {
		return mfaadmission.ErrRejected
	}
	var extra map[string]any
	method := loginproof.Certificate
	if user.Passwd {
		method = loginproof.Password
	}
	confirm := func(ctx context.Context) error {
		if secondFactor {
			return h.Model.CompleteMFASignIn(ctx, user, method, evidence)
		}
		return h.Model.AdmitLocalSignIn(ctx, user, method, models.LocalSignInComplete)
	}
	if user.Openid {
		identity, err := h.validatedOIDCIdentity(c, user.ID)
		if err != nil {
			return err
		}
		extra = map[string]any{oidcSessionKey: h.SessionManager.Manager.GetString(c.Request().Context(), oidcSessionKey)}
		confirm = func(ctx context.Context) error {
			return h.OIDCAccounts.AdmitSession(ctx, *identity, user, evidence)
		}
	} else if method == loginproof.Certificate {
		proof, err := loginproof.Read(h.SessionManager.Manager.GetString(c.Request().Context(), loginproof.SessionKey), user.ID, time.Now())
		if err != nil || proof.Method != loginproof.Certificate {
			return clientidentity.ErrCertificateBinding
		}
		cert, err := clientidentity.ReadSessionCertificate(h.SessionManager.Manager.GetString(c.Request().Context(), clientidentity.SessionCertificateKey), user.ID, proof.Credential, time.Now())
		if err != nil {
			return err
		}
		confirm = func(ctx context.Context) error {
			return h.Model.AdmitCertificateSignIn(ctx, user, cert, models.LocalSignInComplete, evidence)
		}
	}
	return h.establishUserSession(c, user, secondFactor, extra, confirm)
}
