package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/sessiongeneration"
)

// validateLocalSession checks the currently configured local authentication
// policy against the method recorded at sign-in. It never confirms registration.
// Completed sessions must also retain the account and method generations
// recorded by their original admission.
func (h *Handler) validateLocalSession(ctx context.Context, c echo.Context, user *ent.User) error {
	password, recorded := h.SessionManager.Manager.Get(ctx, "usepasswd").(bool)
	if !recorded || user.Openid {
		return h.rejectLocalSession(c)
	}
	if h.SessionManager.Manager.GetBool(ctx, "twofa") && (!user.Use2fa || !user.TotpSecretConfirmed) {
		return h.rejectLocalSession(c)
	}
	method := loginproof.Certificate
	if password {
		method = loginproof.Password
	}
	stage := models.LocalSignInCurrentSession
	var err error
	if h.SessionManager.Manager.GetBool(ctx, "authentication-pending") {
		proof, proofErr := loginproof.Read(h.SessionManager.Manager.GetString(ctx, loginproof.SessionKey), user.ID, time.Now())
		if proofErr != nil || proof.Method != method || !user.Use2fa || h.SessionManager.Manager.GetBool(ctx, "twofa") || password && proof.Credential != loginproof.Digest(user.Hash) {
			return h.rejectLocalSession(c)
		}
		stage = models.LocalSignInPendingMFA
		if method == loginproof.Certificate {
			cert, readErr := clientidentity.ReadSessionCertificate(h.SessionManager.Manager.GetString(ctx, clientidentity.SessionCertificateKey), user.ID, proof.Credential, time.Now())
			if readErr != nil {
				return h.rejectLocalSession(c)
			}
			err = h.Model.AdmitCertificateSignIn(ctx, user, cert, stage, nil)
		}
	}
	if stage == models.LocalSignInCurrentSession {
		err = h.Model.CheckLocalSession(ctx, user, method, h.SessionManager.Manager.GetString(ctx, sessiongeneration.SessionKey))
	} else if method != loginproof.Certificate {
		err = h.Model.AdmitLocalSignIn(ctx, user, method, stage)
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, models.ErrLocalSignIn) {
		return h.rejectLocalSession(c)
	}
	return echo.NewHTTPError(http.StatusServiceUnavailable, "Local session verification is temporarily unavailable.")
}

func (h *Handler) rejectLocalSession(c echo.Context) error {
	ctx := c.Request().Context()
	_ = h.SessionManager.Manager.Clear(ctx)
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := h.SessionManager.Manager.Destroy(cleanup); err != nil {
		log.Print("[ERROR]: could not retire rejected local session")
	}
	return echo.NewHTTPError(http.StatusUnauthorized, "Account access or sign-in requirements changed. Sign in again.")
}
