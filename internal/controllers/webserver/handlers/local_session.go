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
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

// validateLocalSession checks the currently configured local authentication
// policy against the method recorded at sign-in. It never confirms registration.
// Credential-generation binding to the original sign-in is separate from this
// request-time policy check.
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
	if h.SessionManager.Manager.GetBool(ctx, "authentication-pending") {
		proof, err := loginproof.Read(h.SessionManager.Manager.GetString(ctx, loginproof.SessionKey), user.ID, time.Now())
		if err != nil || proof.Method != method || !user.Use2fa || h.SessionManager.Manager.GetBool(ctx, "twofa") || password && proof.Credential != loginproof.Digest(user.Hash) {
			return h.rejectLocalSession(c)
		}
		stage = models.LocalSignInPendingMFA
	}
	err := h.Model.AdmitLocalSignIn(ctx, user, method, stage)
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
