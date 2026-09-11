package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

func sessionAdmissionError(err error, message string) error {
	if errors.Is(err, models.ErrLocalSignIn) {
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
func (h *Handler) completeUserSession(c echo.Context, user *ent.User, secondFactor bool) error {
	var extra map[string]any
	method := loginproof.Certificate
	if user.Passwd {
		method = loginproof.Password
	}
	confirm := func(ctx context.Context) error {
		return h.Model.AdmitLocalSignIn(ctx, user, method, models.LocalSignInComplete)
	}
	if user.Openid {
		if err := h.validateOIDCSession(c, user.ID); err != nil {
			return err
		}
		extra = map[string]any{oidcSessionKey: h.SessionManager.Manager.GetString(c.Request().Context(), oidcSessionKey)}
		confirm = func(ctx context.Context) error { return h.Model.ConfirmOIDCLogIn(ctx, user.ID) }
	}
	return h.establishUserSession(c, user, secondFactor, extra, confirm)
}
