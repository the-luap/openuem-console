package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/enttest"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/stretchr/testify/require"
)

func TestEmailConfirmationRejectsInvalidProofAndAccountState(t *testing.T) {
	for _, name := range []string{"valid", "wrong-subject", "wrong-issuer", "missing-expiry", "expired", "missing-issued", "long-lifetime", "future-issued", "future-not-before", "empty-id", "missing-key", "wrong-method", "oversized", "malformed", "revoked", "approved", "password", "openid", "verified", "missing-csrf", "missing-settings"} {
		t.Run(name, func(t *testing.T) {
			client := enttest.Open(t, "sqlite3", "file:email-confirmation?mode=memory&_fk=1")
			t.Cleanup(func() { client.Close() })
			ctx, err := locales.WithLocale(t.Context(), "en")
			require.NoError(t, err)
			create := client.User.Create().SetID("confirmation-user").SetName("Confirmation user").SetEmail("confirmation@example.test")
			switch name {
			case "revoked":
				create.SetRegister(openuem.REGISTER_REVOKED)
			case "approved":
				create.SetRegister(openuem.REGISTER_APPROVED)
			case "password":
				create.SetPasswd(true)
			case "openid":
				create.SetOpenid(true)
			case "verified":
				create.SetEmailVerified(true)
			}
			before, err := create.Save(ctx)
			require.NoError(t, err)
			if name != "missing-settings" {
				require.NoError(t, client.Settings.Create().Exec(ctx))
			}
			h := &Handler{Model: &models.Model{Client: client}, JWTKey: strings.Repeat("j", 32)}
			claims := jwt.RegisteredClaims{ID: before.ID, Subject: "Email Confirmation", Issuer: "OpenUEM", IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
			method := jwt.SigningMethodHS512
			switch name {
			case "wrong-subject":
				claims.Subject = "New password"
			case "wrong-issuer":
				claims.Issuer = "Other issuer"
			case "missing-expiry":
				claims.ExpiresAt = nil
			case "expired":
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			case "missing-issued":
				claims.IssuedAt = nil
			case "long-lifetime":
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(25 * time.Hour))
			case "future-issued":
				claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
			case "future-not-before":
				claims.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
			case "empty-id":
				claims.ID = ""
			case "missing-key":
				h.JWTKey = ""
			case "wrong-method":
				method = jwt.SigningMethodHS256
			}
			encoded, err := jwt.NewWithClaims(method, claims).SignedString([]byte(h.JWTKey))
			require.NoError(t, err)
			if name == "oversized" {
				encoded += strings.Repeat("x", 8192)
			}
			if name == "malformed" {
				encoded = "owned-private-invalid-confirmation"
			}
			recorder := httptest.NewRecorder()
			c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/auth/confirm/owned", nil).WithContext(ctx), recorder)
			c.SetParamNames("token")
			c.SetParamValues(encoded)
			if name != "missing-csrf" {
				c.Set("csrf", "owned-csrf")
			}
			var result error
			require.NotPanics(t, func() { result = h.ConfirmEmail(c) })
			after, err := client.User.Get(ctx, before.ID)
			require.NoError(t, err)
			if name == "valid" {
				require.NoError(t, result)
				require.True(t, after.EmailVerified)
				require.Equal(t, openuem.REGISTER_SEND_CERTIFICATE, after.Register)
				require.Error(t, h.ConfirmEmail(c), "a second confirmation must fail")
			} else {
				var failure *echo.HTTPError
				require.True(t, errors.As(result, &failure), "invalid proof or state was accepted")
				status := http.StatusBadRequest
				if name == "missing-csrf" {
					status = http.StatusForbidden
				}
				if name == "missing-settings" {
					status = http.StatusInternalServerError
				}
				require.Equal(t, status, failure.Code)
				if status == http.StatusBadRequest {
					require.Equal(t, "This confirmation link is invalid or expired. Ask your administrator for a new confirmation email.", failure.Message)
				}
				require.Equal(t, before.EmailVerified, after.EmailVerified, "rejected confirmation changed verification")
				require.Equal(t, before.Register, after.Register, "rejected confirmation changed account status")
			}
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			require.Equal(t, "no-referrer", recorder.Header().Get("Referrer-Policy"))
			require.NotContains(t, recorder.Body.String(), encoded)
		})
	}
}
