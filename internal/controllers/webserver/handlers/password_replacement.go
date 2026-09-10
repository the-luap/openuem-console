package handlers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/models"
)

func (h *Handler) passwordReplacementProof(c echo.Context) (models.PasswordReplacementProof, error) {
	sm, ctx := h.SessionManager.Manager, c.Request().Context()
	proof := models.PasswordReplacementProof{
		Kind:           sm.GetString(ctx, "password-replacement-kind"),
		PasswordDigest: sm.GetString(ctx, "password-replacement-password"),
		SourceDigest:   sm.GetString(ctx, "password-replacement-source"),
		ExpiresAt:      time.Unix(sm.GetInt64(ctx, "password-replacement-expiry"), 0),
	}
	if !sm.GetBool(ctx, "forgot") || proof.Kind == "" || len(proof.PasswordDigest) != 64 || !proof.ExpiresAt.After(time.Now()) {
		return proof, echo.NewHTTPError(http.StatusForbidden, "Verify password replacement authorization before choosing a new password.")
	}
	return proof, nil
}

func (h *Handler) authorizePasswordReplacement(c echo.Context, user *ent.User, kind, source string, sourceExpiry time.Time) error {
	expires := time.Now().Add(15 * time.Minute)
	if !sourceExpiry.IsZero() && sourceExpiry.Before(expires) {
		expires = sourceExpiry
	}
	proof := &models.PasswordReplacementProof{Kind: kind, PasswordDigest: models.PasswordReplacementDigest(user.Hash), SourceDigest: source, ExpiresAt: expires}
	return h.createPasswordReplacementSession(c, user, proof)
}

// A pending recovery session identifies the account but has no replacement
// authority until its independent code is verified. Existing sessions are renewed
// and all previous replacement/MFA state is removed before recording a new flow.
func (h *Handler) createPasswordReplacementSession(c echo.Context, user *ent.User, proof *models.PasswordReplacementProof) error {
	sm, ctx := h.SessionManager.Manager, c.Request().Context()
	if err := sm.RenewToken(ctx); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Password replacement session could not be created.")
	}
	for _, key := range []string{"password-replacement-kind", "password-replacement-password", "password-replacement-source", "password-replacement-expiry", "twofa"} {
		sm.Remove(ctx, key)
	}
	sm.Put(ctx, "uid", user.ID)
	sm.Put(ctx, "username", user.Name)
	sm.Put(ctx, "user-agent", c.Request().UserAgent())
	sm.Put(ctx, "ip-address", c.Request().RemoteAddr)
	sm.Put(ctx, "usepasswd", user.Passwd)
	sm.Put(ctx, "email", user.Email)
	sm.Put(ctx, "forgot", true)
	if proof != nil {
		sm.Put(ctx, "password-replacement-kind", proof.Kind)
		sm.Put(ctx, "password-replacement-password", proof.PasswordDigest)
		sm.Put(ctx, "password-replacement-source", proof.SourceDigest)
		sm.Put(ctx, "password-replacement-expiry", proof.ExpiresAt.Unix())
	}
	token, expiry, err := sm.Commit(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Password replacement session could not be stored.")
	}
	sm.WriteSessionCookie(ctx, c.Response().Writer, token, expiry)
	if err = h.Model.AddUserToSession(token, user.ID, h.EncryptionMasterKey); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Password replacement session could not be associated.")
	}
	return nil
}
