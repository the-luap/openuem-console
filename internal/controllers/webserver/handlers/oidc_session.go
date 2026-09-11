package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

const oidcSessionKey = "oidc-identity"

func (h *Handler) validateOIDCSession(c echo.Context, uid string) error {
	if h.OIDCAccounts == nil {
		return echo.NewHTTPError(503, "OpenID session verification is unavailable")
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	raw := h.SessionManager.Manager.GetString(ctx, oidcSessionKey)
	var session oidcaccounts.Session
	var err error
	if len(raw) > 8192 || json.Unmarshal([]byte(raw), &session) != nil || session.UserID != uid {
		err = oidcaccounts.ErrIdentity
	} else {
		err = h.OIDCAccounts.ValidateSession(ctx, session)
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, oidcaccounts.ErrIdentity) || errors.Is(err, oidcaccounts.ErrConflict) {
		_ = h.SessionManager.Manager.Clear(ctx)
		return echo.NewHTTPError(401, "OpenID access changed; sign in again")
	}
	return echo.NewHTTPError(503, "OpenID session verification is unavailable")
}
